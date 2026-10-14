package redis

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	redisclient "github.com/redis/go-redis/v9"
)

type redisCommand string

const (
	redisCommandPing               redisCommand = "ping"
	redisCommandPublish            redisCommand = "publish"
	redisCommandSubscribe          redisCommand = "subscribe"
	redisCommandReceive            redisCommand = "receive"
	redisCommandAcquire            redisCommand = "presence_acquire"
	redisCommandRenew              redisCommand = "presence_renew"
	redisCommandRelease            redisCommand = "presence_release"
	redisCommandObserveEndpoints   redisCommand = "endpoints_observe"
	redisCommandFlushEndpoints     redisCommand = "endpoints_flush"
	redisCommandLoadEndpoints      redisCommand = "endpoints_load"
	redisCommandLoadConnectivity   redisCommand = "connectivity_load"
	redisCommandRateLimit          redisCommand = "rate_limit"
	redisCommandRecordDelivery     redisCommand = "delivery_record"
	redisCommandTouchDelivery      redisCommand = "delivery_touch"
	redisCommandLoadDeliveries     redisCommand = "delivery_load"
	redisCommandRecordEnforcement  redisCommand = "enforcement_record"
	redisCommandRecordPaths        redisCommand = "paths_record"
	redisCommandRecordConnectivity redisCommand = "connectivity_record"
	redisCommandReplicaLoad        redisCommand = "replica_load"
)

var redisCommands = [...]redisCommand{
	redisCommandPing,
	redisCommandPublish,
	redisCommandSubscribe,
	redisCommandReceive,
	redisCommandAcquire,
	redisCommandRenew,
	redisCommandRelease,
	redisCommandObserveEndpoints,
	redisCommandFlushEndpoints,
	redisCommandLoadEndpoints,
	redisCommandLoadConnectivity,
	redisCommandRateLimit,
	redisCommandRecordDelivery,
	redisCommandTouchDelivery,
	redisCommandLoadDeliveries,
	redisCommandRecordEnforcement,
	redisCommandRecordPaths,
	redisCommandRecordConnectivity,
	redisCommandReplicaLoad,
}

// endpointAnnouncementOutcomes is the closed set of what an endpoint
// observation or flush did for the Device's peers.
var endpointAnnouncementOutcomes = [...]string{"announced", "deferred", "unchanged", "flushed"}

type redisMetrics struct {
	commandTotal        *prometheus.CounterVec
	announcements       *prometheus.CounterVec
	commandDuration     *prometheus.HistogramVec
	poolStats           func() *redisclient.PoolStats
	poolConnectionsDesc *prometheus.Desc
	poolLimitDesc       *prometheus.Desc
	poolPendingDesc     *prometheus.Desc
	poolTimeoutsDesc    *prometheus.Desc
	subscriptionsDesc   *prometheus.Desc
	poolLimit           int
	activeSubscriptions atomic.Int64
}

func newRedisMetrics(poolLimit int, poolStats func() *redisclient.PoolStats) *redisMetrics {
	// Dashboard: sum by (operation, result) (rate(meshtransit_redis_commands_total[5m]))
	// Alert: sum(rate(meshtransit_redis_commands_total{result="error"}[5m])) > 0
	commandTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_redis_commands_total",
		Help: "Total Redis commands by bounded operation and result.",
	}, []string{"operation", "result"})
	// Dashboard: histogram_quantile(0.99, sum(rate(meshtransit_redis_command_duration_seconds_bucket[5m])) by (le, operation))
	// Alert: histogram_quantile(0.99, sum(rate(meshtransit_redis_command_duration_seconds_bucket[5m])) by (le, operation)) > 0.5
	commandDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_redis_command_duration_seconds",
		Help:    "Redis command duration in seconds by bounded operation and result.",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
	}, []string{"operation", "result"})
	for _, command := range redisCommands {
		for _, result := range [...]string{"success", "error"} {
			commandTotal.WithLabelValues(string(command), result)
			commandDuration.WithLabelValues(string(command), result)
		}
	}

	// Dashboard: sum by (outcome) (rate(meshtransit_endpoint_announcements_total[5m]))
	// A high deferred rate means Devices whose endpoints change faster than
	// the announce interval (mtcp-v1 §8.1).
	announcements := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_endpoint_announcements_total",
		Help: "Endpoint observations and flushes by what they did for the Device's peers.",
	}, []string{"outcome"})
	for _, outcome := range endpointAnnouncementOutcomes {
		announcements.WithLabelValues(outcome)
	}

	return &redisMetrics{
		commandTotal:    commandTotal,
		announcements:   announcements,
		commandDuration: commandDuration,
		poolStats:       poolStats,
		poolLimit:       poolLimit,
		// Dashboard: meshtransit_redis_pool_connections
		// Alert: meshtransit_redis_pool_connections{state="active"} / meshtransit_redis_pool_connections_max > 0.9
		poolConnectionsDesc: prometheus.NewDesc(
			"meshtransit_redis_pool_connections",
			"Current Redis command-pool connections by bounded state.",
			[]string{"state"},
			nil,
		),
		// Dashboard: meshtransit_redis_pool_connections_max
		poolLimitDesc: prometheus.NewDesc(
			"meshtransit_redis_pool_connections_max",
			"Configured maximum Redis command-pool connections.",
			nil,
			nil,
		),
		// Dashboard: meshtransit_redis_pool_pending_requests
		// Alert: meshtransit_redis_pool_pending_requests > 0
		poolPendingDesc: prometheus.NewDesc(
			"meshtransit_redis_pool_pending_requests",
			"Current requests waiting for a Redis command-pool connection.",
			nil,
			nil,
		),
		// Dashboard: rate(meshtransit_redis_pool_timeouts_total[5m])
		// Alert: rate(meshtransit_redis_pool_timeouts_total[5m]) > 0
		poolTimeoutsDesc: prometheus.NewDesc(
			"meshtransit_redis_pool_timeouts_total",
			"Total Redis command-pool wait timeouts.",
			nil,
			nil,
		),
		// Dashboard: meshtransit_redis_subscriptions_active
		subscriptionsDesc: prometheus.NewDesc(
			"meshtransit_redis_subscriptions_active",
			"Current caller-owned Redis subscriptions.",
			nil,
			nil,
		),
	}
}

func (metrics *redisMetrics) Describe(descriptions chan<- *prometheus.Desc) {
	metrics.commandTotal.Describe(descriptions)
	metrics.announcements.Describe(descriptions)
	metrics.commandDuration.Describe(descriptions)
	descriptions <- metrics.poolConnectionsDesc
	descriptions <- metrics.poolLimitDesc
	descriptions <- metrics.poolPendingDesc
	descriptions <- metrics.poolTimeoutsDesc
	descriptions <- metrics.subscriptionsDesc
}

func (metrics *redisMetrics) Collect(output chan<- prometheus.Metric) {
	metrics.commandTotal.Collect(output)
	metrics.announcements.Collect(output)
	metrics.commandDuration.Collect(output)

	stats := &redisclient.PoolStats{}
	if metrics.poolStats != nil {
		if current := metrics.poolStats(); current != nil {
			stats = current
		}
	}
	idleConnections := min(stats.IdleConns, stats.TotalConns)
	activeConnections := stats.TotalConns - idleConnections
	output <- prometheus.MustNewConstMetric(
		metrics.poolConnectionsDesc,
		prometheus.GaugeValue,
		float64(activeConnections),
		"active",
	)
	output <- prometheus.MustNewConstMetric(
		metrics.poolConnectionsDesc,
		prometheus.GaugeValue,
		float64(idleConnections),
		"idle",
	)
	output <- prometheus.MustNewConstMetric(
		metrics.poolLimitDesc,
		prometheus.GaugeValue,
		float64(metrics.poolLimit),
	)
	output <- prometheus.MustNewConstMetric(
		metrics.poolPendingDesc,
		prometheus.GaugeValue,
		float64(stats.PendingRequests),
	)
	output <- prometheus.MustNewConstMetric(
		metrics.poolTimeoutsDesc,
		prometheus.CounterValue,
		float64(stats.Timeouts),
	)
	output <- prometheus.MustNewConstMetric(
		metrics.subscriptionsDesc,
		prometheus.GaugeValue,
		float64(metrics.activeSubscriptions.Load()),
	)
}

func (metrics *redisMetrics) observeCommand(command redisCommand, startedAt time.Time, err error) {
	if metrics == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	metrics.commandTotal.WithLabelValues(string(command), result).Inc()
	metrics.commandDuration.WithLabelValues(string(command), result).Observe(time.Since(startedAt).Seconds())
}

func (metrics *redisMetrics) endpointAnnouncement(outcome string) {
	if metrics != nil {
		metrics.announcements.WithLabelValues(outcome).Inc()
	}
}

func (metrics *redisMetrics) subscriptionOpened() {
	if metrics != nil {
		metrics.activeSubscriptions.Add(1)
	}
}

func (metrics *redisMetrics) subscriptionClosed() {
	if metrics == nil {
		return
	}
	for {
		current := metrics.activeSubscriptions.Load()
		if current == 0 || metrics.activeSubscriptions.CompareAndSwap(current, current-1) {
			return
		}
	}
}
