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

	"github.com/meshtransit/meshtransit/core/internal/platform/app"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
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
	ping             func(context.Context) error
	publish          func(context.Context, string, []byte) error
	subscribe        func(context.Context, string) (messageSubscription, error)
	acquirePresence  presenceAcquireFunc
	renewPresence    presenceRenewFunc
	releasePresence  presenceReleaseFunc
	observeEndpoints observeEndpointsFunc
	loadEndpoints    loadEndpointsFunc
	loadConnectivity loadConnectivityFunc
	applyRateLimit   rateLimitFunc
	recordDelivery   recordDeliveryFunc
	touchDelivery    touchDeliveryFunc
	loadDeliveries   loadDeliveriesFunc
	metrics          *redisMetrics
	close            func() error
	closeOnce        sync.Once
	closeErr         error
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
		) (int64, error) {
			return acquirePresenceScript.Run(
				acquireCtx,
				client,
				[]string{presenceKey, endpointKey},
				generation,
				replicaID,
				ttl.Milliseconds(),
				channel,
				wakeup,
			).Int64()
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
		observeEndpoints: func(
			observeCtx context.Context,
			endpointKey string,
			presenceKey string,
			generation int64,
			payload []byte,
			preferredRelayPresent int64,
			preferredRelay int,
			ttl time.Duration,
			channel string,
			wakeup []byte,
		) (int64, error) {
			return observeEndpointsScript.Run(
				observeCtx,
				client,
				[]string{endpointKey, presenceKey},
				generation,
				payload,
				preferredRelayPresent,
				preferredRelay,
				ttl.Milliseconds(),
				channel,
				wakeup,
			).Int64()
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
			key string,
			generation int64,
			networkRevision int64,
			policyRevision int64,
			deliveredAt int64,
			ttl time.Duration,
		) (int64, error) {
			return recordDeliveryScript.Run(recordCtx, client, []string{key}, generation, networkRevision,
				policyRevision, deliveredAt, ttl.Milliseconds()).Int64()
		},
		touchDelivery: func(
			touchCtx context.Context,
			key string,
			generation int64,
			seenAt int64,
			ttl time.Duration,
		) (int64, error) {
			return touchDeliveryScript.Run(touchCtx, client, []string{key}, generation, seenAt,
				ttl.Milliseconds()).Int64()
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
