// Package redis implements the Redis infrastructure boundary.
package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	redisclient "github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"

	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

const (
	connectionMaxIdleTime       = 5 * time.Minute
	connectionMaxLifetime       = 30 * time.Minute
	connectionMaxLifetimeJitter = 5 * time.Minute
)

var (
	// ErrInvalidOptions indicates missing or unsafe Redis settings.
	ErrInvalidOptions = errors.New("invalid redis options")
	// ErrOpen indicates that Redis client construction failed.
	ErrOpen = errors.New("open redis client")
)

// Options contains one validated Redis client configuration.
type Options struct {
	Address        string
	Username       string
	PasswordFile   config.SecretFile
	CAFile         config.TrustFile
	PoolSize       int
	RequestTimeout time.Duration
}

// Client is the concrete Redis dependency owned by the composition root.
type Client struct {
	ping               func(context.Context) error
	publish            func(context.Context, string, []byte) error
	subscribe          func(context.Context, string) (messageSubscription, error)
	acquirePresence    presenceAcquireFunc
	renewPresence      presenceRenewFunc
	releasePresence    presenceReleaseFunc
	gatewayScript      gatewayScriptFunc
	observeEndpoints   observeEndpointsFunc
	flushEndpoints     flushEndpointsFunc
	loadEndpoints      loadEndpointsFunc
	loadConnectivity   loadConnectivityFunc
	applyRateLimit     rateLimitFunc
	recordDelivery     recordDeliveryFunc
	recordEnforcement  recordEnforcementFunc
	recordPaths        func(ctx context.Context, key string, generation int64, encoded string, ttl time.Duration) (int64, error)
	recordConnectivity func(ctx context.Context, key string, generation int64, encoded string, ttl time.Duration) (int64, error)
	recordRouteHealth  func(ctx context.Context, key string, generation int64, encoded string, reportedAt int64,
		ttl time.Duration, failed bool, exit string) (int64, error)
	recordDNSHealth func(ctx context.Context, key, nodeID string, generation int64, encoded string,
		reportedAt int64, ttl time.Duration) (int64, error)
	// loadDNSZone and loadDNSApply read the DNS index (dns_index.go);
	// countDNSHealth counts one resolver's states; pruneDNSIndex deletes
	// stale fields of an index hash.
	loadDNSZone    func(ctx context.Context, key string, cursor uint64, count int) ([]string, uint64, error)
	loadDNSApply   func(ctx context.Context, key string, fields []string) ([]any, error)
	countDNSHealth func(ctx context.Context, keys []string, since int64) ([]int64, error)
	pruneDNSIndex  func(ctx context.Context, zoneKey, applyKey string, entries []dnsIndexEntry) error
	loadSession    loadSessionFunc
	// recordRouteSelection runs recordRouteSelectionScript; loadSiteSelection
	// reads a Site's selection hash; pruneSiteSelection deletes its fields.
	recordRouteSelection func(ctx context.Context, key string, generation int64, encoded string, reportedAt int64,
		nodeID string) (int64, error)
	loadSiteSelection  func(ctx context.Context, key string, limit int) (map[string]string, error)
	pruneSiteSelection func(ctx context.Context, key string, fields []string) error
	touchDelivery      touchDeliveryFunc
	loadDeliveries     loadDeliveriesFunc
	replicaLoad        replicaLoadFunc
	kubernetesCAMarks  kubernetesCAMarksFunc
	// withdrawReplicaLoad removes one control replica's load field.
	withdrawReplicaLoad func(ctx context.Context, key, replicaID string) error
	metrics             *redisMetrics
	close               func() error
	closeOnce           sync.Once
	closeErr            error
}

// Open constructs a lazy, bounded TLS-only Redis client. Connectivity is
// checked synchronously by the application monitor before listeners start.
func Open(ctx context.Context, options Options) (*Client, error) {
	if ctx == nil {
		return nil, ErrInvalidOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return nil, errors.Join(ErrOpen, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return nil, errors.Join(ErrOpen, err)
	}
	clientOptions, err := buildClientOptions(options, password, caPEM)
	if err != nil {
		return nil, err
	}

	client := redisclient.NewClient(clientOptions)
	return &Client{
		ping: func(checkCtx context.Context) error {
			return client.Ping(checkCtx).Err()
		},
		publish: func(publishCtx context.Context, channel string, payload []byte) error {
			return client.Publish(publishCtx, channel, payload).Err()
		},
		replicaLoad:       runReplicaLoadScript(client),
		kubernetesCAMarks: runKubernetesCAMarksScript(client),
		gatewayScript:     runGatewayScript(client),
		withdrawReplicaLoad: func(withdrawCtx context.Context, key, replicaID string) error {
			return client.HDel(withdrawCtx, key, replicaID).Err()
		},
		subscribe: func(subscribeCtx context.Context, channel string) (messageSubscription, error) {
			subscription := client.Subscribe(subscribeCtx, channel)
			if _, err := subscription.Receive(subscribeCtx); err != nil {
				return nil, errors.Join(err, subscription.Close())
			}
			return subscription, nil
		},
		acquirePresence: func(
			acquireCtx context.Context,
			presenceKey string,
			endpointKey string,
			generation int64,
			replicaID string,
			ttl time.Duration,
			channel string,
			wakeup []byte,
		) (int64, int64, error) {
			return runStatusScript(acquireCtx, acquirePresenceScript, client,
				[]string{presenceKey, endpointKey},
				generation, replicaID, ttl.Milliseconds(), channel, wakeup,
				presenceTransferLimit, presenceTransferWindow.Milliseconds())
		},
		renewPresence: func(
			renewCtx context.Context,
			presenceKey string,
			endpointKey string,
			generation int64,
			replicaID string,
			ttl time.Duration,
		) (int64, error) {
			return renewPresenceScript.Run(
				renewCtx,
				client,
				[]string{presenceKey, endpointKey},
				generation,
				replicaID,
				ttl.Milliseconds(),
			).Int64()
		},
		releasePresence: func(
			releaseCtx context.Context,
			presenceKey string,
			endpointKey string,
			generation int64,
			replicaID string,
			channel string,
			wakeup []byte,
		) (int64, error) {
			return releasePresenceScript.Run(
				releaseCtx,
				client,
				[]string{presenceKey, endpointKey},
				generation,
				replicaID,
				channel,
				wakeup,
			).Int64()
		},
		observeEndpoints: func(observeCtx context.Context, observation endpointObservation) (int64, int64, error) {
			return runStatusScript(observeCtx, observeEndpointsScript, client,
				[]string{observation.endpointKey, observation.presenceKey},
				observation.generation,
				observation.payload,
				observation.preferredRelayPresent,
				observation.preferredRelay,
				observation.ttl.Milliseconds(),
				observation.channel,
				observation.wakeup,
				observation.interval.Milliseconds(),
				observation.discoveryKey,
				observation.discoSpacing.Milliseconds(),
			)
		},
		flushEndpoints: func(flushCtx context.Context, endpointKey string, generation int64, channel string,
			wakeup []byte, interval time.Duration) (int64, int64, error) {
			return runStatusScript(flushCtx, flushEndpointsScript, client, []string{endpointKey},
				generation, channel, wakeup, interval.Milliseconds())
		},
		loadEndpoints: func(
			loadCtx context.Context,
			endpointKey string,
			generation int64,
		) ([]byte, error) {
			payload, err := loadEndpointsScript.Run(
				loadCtx,
				client,
				[]string{endpointKey},
				generation,
			).Text()
			if errors.Is(err, redisclient.Nil) {
				return nil, nil
			}
			return []byte(payload), err
		},
		loadConnectivity: func(
			loadCtx context.Context,
			keys []string,
			generations []int64,
		) ([]any, error) {
			arguments := make([]any, len(generations))
			for index, generation := range generations {
				arguments[index] = generation
			}
			return loadConnectivityScript.Run(loadCtx, client, keys, arguments...).Slice()
		},
		applyRateLimit: func(
			rateLimitCtx context.Context,
			key string,
			capacity int64,
			refillInterval time.Duration,
		) ([]int64, error) {
			return runRateLimitScript(rateLimitCtx, client, key, capacity, refillInterval)
		},
		recordDelivery: func(
			recordCtx context.Context,
			deliveryKey string,
			sessionKey string,
			record deliveryRecord,
			ttl time.Duration,
		) (int64, error) {
			return recordDeliveryScript.Run(recordCtx, client, []string{deliveryKey, sessionKey},
				record.generation, record.networkRevision, record.policyRevision, record.deliveredAt,
				ttl.Milliseconds(), record.filterDigest, record.filterGrants, record.nodeID, record.machine,
				record.peerLimit, record.routeDigest, record.routeEntries, record.dnsDigest, record.dnsRoutes,
				record.dnsNetwork, record.dnsZones, dnsIndexPrefix, dnsIndexTTL.Milliseconds()).Int64()
		},
		loadSession: func(loadCtx context.Context, key string) ([]any, error) {
			return client.HMGet(loadCtx, key, "node_id", "generation", "machine").Result()
		},
		recordEnforcement: func(
			recordCtx context.Context,
			key string,
			record enforcementRecord,
			ttl time.Duration,
		) (int64, error) {
			return recordEnforcementScript.Run(recordCtx, client, []string{key}, record.generation,
				record.digest, record.grants, record.appliedAt, record.reportedAt, ttl.Milliseconds(),
				record.routeDigest, record.routeEntries, record.dnsDigest, record.dnsRoutes, record.dnsReason,
				record.nodeID, dnsIndexPrefix, dnsIndexTTL.Milliseconds()).Int64()
		},
		recordRouteSelection: func(recordCtx context.Context, key string, generation int64, encoded string,
			reportedAt int64, nodeID string) (int64, error) {
			return recordRouteSelectionScript.Run(recordCtx, client, []string{key}, generation, encoded, reportedAt,
				deliveryTTL.Milliseconds(), nodeID, siteSelectionPrefix, siteSelectionTTL.Milliseconds()).Int64()
		},
		loadSiteSelection: func(loadCtx context.Context, key string, limit int) (map[string]string, error) {
			entries, err := client.HGetAll(loadCtx, key).Result()
			if err != nil {
				return nil, err
			}
			if len(entries) > limit {
				return nil, errors.New("site selection is too large to count")
			}
			return entries, nil
		},
		pruneSiteSelection: func(pruneCtx context.Context, key string, fields []string) error {
			return client.HDel(pruneCtx, key, fields...).Err()
		},
		recordRouteHealth: func(recordCtx context.Context, key string, generation int64, encoded string,
			reportedAt int64, ttl time.Duration, failed bool, exit string) (int64, error) {
			flag := "0"
			if failed {
				flag = "1"
			}
			return recordRouteHealthScript.Run(recordCtx, client, []string{key}, generation, encoded, reportedAt,
				ttl.Milliseconds(), flag, siteHealthFailedChannel, siteHealthFailedPayload, exit).Int64()
		},
		recordDNSHealth: func(recordCtx context.Context, key, nodeID string, generation int64, encoded string,
			reportedAt int64, ttl time.Duration) (int64, error) {
			return recordDNSHealthScript.Run(recordCtx, client, []string{key}, generation, encoded, reportedAt,
				ttl.Milliseconds(), nodeID, dnsIndexPrefix, dnsIndexTTL.Milliseconds(),
				reportedAt-dnsHealthPruneAfter.Milliseconds()).Int64()
		},
		loadDNSZone: func(loadCtx context.Context, key string, cursor uint64, count int) ([]string, uint64, error) {
			pairs, next, err := client.HScan(loadCtx, key, cursor, "", int64(count)).Result()
			if err != nil {
				return nil, 0, err
			}
			nodes := make([]string, 0, len(pairs)/2)
			for index := 0; index+1 < len(pairs); index += 2 {
				nodes = append(nodes, pairs[index])
			}
			return nodes, next, nil
		},
		loadDNSApply: func(loadCtx context.Context, key string, fields []string) ([]any, error) {
			return client.HMGet(loadCtx, key, fields...).Result()
		},
		countDNSHealth: func(countCtx context.Context, keys []string, since int64) ([]int64, error) {
			pipe := client.Pipeline()
			counts := make([]*redisclient.IntCmd, len(keys))
			minimum := strconv.FormatInt(since, 10)
			for index, key := range keys {
				counts[index] = pipe.ZCount(countCtx, key, minimum, "+inf")
			}
			if _, err := pipe.Exec(countCtx); err != nil {
				return nil, err
			}
			values := make([]int64, len(keys))
			for index, count := range counts {
				values[index] = count.Val()
			}
			return values, nil
		},
		pruneDNSIndex: func(pruneCtx context.Context, zoneKey, applyKey string, entries []dnsIndexEntry) error {
			args := make([]any, 0, len(entries)*2)
			for _, entry := range entries {
				args = append(args, entry.node, entry.apply)
			}
			return pruneDNSIndexScript.Run(pruneCtx, client, []string{zoneKey, applyKey}, args...).Err()
		},
		recordPaths: func(recordCtx context.Context, key string, generation int64, encoded string,
			ttl time.Duration) (int64, error) {
			return recordPathsScript.Run(recordCtx, client, []string{key}, generation, encoded,
				ttl.Milliseconds()).Int64()
		},
		recordConnectivity: func(recordCtx context.Context, key string, generation int64, encoded string,
			ttl time.Duration) (int64, error) {
			return recordConnectivityScript.Run(recordCtx, client, []string{key}, generation, encoded,
				ttl.Milliseconds()).Int64()
		},
		touchDelivery: func(
			touchCtx context.Context,
			key string,
			nodeID string,
			generation int64,
			seenAt int64,
			ttl time.Duration,
		) (int64, error) {
			return touchDeliveryScript.Run(touchCtx, client, []string{key}, generation, seenAt,
				ttl.Milliseconds(), nodeID, dnsIndexPrefix, dnsIndexTTL.Milliseconds()).Int64()
		},
		loadDeliveries: func(loadCtx context.Context, keys []string) ([]any, error) {
			return loadDeliveriesScript.Run(loadCtx, client, keys).Slice()
		},
		metrics: newRedisMetrics(options.PoolSize, client.PoolStats),
		close:   client.Close,
	}, nil
}

// Component identifies this dependency to the application monitor.
func (*Client) Component() app.Component { return app.ComponentRedis }

// Check verifies a Redis round trip within the caller's context.
func (client *Client) Check(ctx context.Context) error {
	if ctx == nil || client == nil || client.ping == nil {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	err := client.ping(ctx)
	client.metrics.observeCommand(redisCommandPing, startedAt, err)
	if err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	return nil
}

// MetricsCollector returns the process-local Redis collector. The composition
// root owns registration with the operator metrics registry.
func (client *Client) MetricsCollector() prometheus.Collector {
	if client == nil || client.metrics == nil {
		return nil
	}
	return client.metrics
}

// Close releases the client once and returns the stable first close result.
func (client *Client) Close() error {
	if client == nil || client.close == nil {
		return ErrInvalidOptions
	}
	client.closeOnce.Do(func() {
		client.closeErr = client.close()
	})
	return client.closeErr
}

// Shutdown closes the client within the application shutdown contract. It
// never starts cleanup after the caller's budget has been exhausted.
func (client *Client) Shutdown(ctx context.Context) error {
	if ctx == nil || client == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return client.Close()
}

func buildClientOptions(options Options, password string, caPEM []byte) (*redisclient.Options, error) {
	host, portValue, err := net.SplitHostPort(options.Address)
	if err != nil || host == "" || options.Username == "" || password == "" ||
		options.PoolSize <= 0 || options.RequestTimeout <= 0 {
		return nil, ErrInvalidOptions
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return nil, ErrInvalidOptions
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, ErrInvalidOptions
	}
	maxConcurrentDials := min(options.PoolSize, 2)
	return &redisclient.Options{
		Addr:                  net.JoinHostPort(host, strconv.FormatUint(port, 10)),
		Username:              options.Username,
		Password:              password,
		DB:                    0,
		Protocol:              3,
		MaxRetries:            -1,
		DialTimeout:           options.RequestTimeout,
		DialerRetries:         1,
		ReadTimeout:           options.RequestTimeout,
		WriteTimeout:          options.RequestTimeout,
		ContextTimeoutEnabled: true,
		DisableIdentity:       true,
		PoolSize:              options.PoolSize,
		MaxConcurrentDials:    maxConcurrentDials,
		PoolTimeout:           options.RequestTimeout,
		MinIdleConns:          0,
		MaxActiveConns:        options.PoolSize,
		ConnMaxIdleTime:       connectionMaxIdleTime,
		ConnMaxLifetime:       connectionMaxLifetime,
		ConnMaxLifetimeJitter: connectionMaxLifetimeJitter,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
			ServerName: host,
		},
		MaintNotificationsConfig: &maintnotifications.Config{Mode: maintnotifications.ModeDisabled},
	}, nil
}
