package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/audit/partitions"
	"meshtransit.net/core/internal/domain/kubeaudit"
)

var errInvalidKubeAuditComposition = errors.New("invalid Kubernetes operation composition")

// Writer bounds (K1b0 §5): the queue's starting size is what the writer
// drains in about 200 ms, to be measured on the POC (b0d).
var (
	kubeAuditWriterOptions = kubeaudit.WriterOptions{Window: 5 * time.Millisecond, Rows: kubeaudit.MaximumRows,
		Queue: 400, Timeout: 2 * time.Second, RetryAfter: time.Second}
	kubeAuditReportOptions = kubeaudit.ReportOptions{Window: time.Second, Rows: 20000, Timeout: 5 * time.Second}
)

// kubeAudit is what records Kubernetes gateways' operations (gateway.audit1,
// mtcp-v1 §6.10): the intents' writer, the reports' writer and the limits,
// with their metrics. As a service it closes the writers, writing what
// they hold; it is started before the control listener, so it is shut down
// after the listener drained the sessions that submit to it.
type kubeAudit struct {
	intents *kubeaudit.Writer
	reports *kubeaudit.ReportWriter
	limits  mtcpadapter.KubeAuditLimiter
	metrics []prometheus.Collector
	// closed is closed once Shutdown wrote what the writers held.
	closed   chan error
	shutdown sync.Once
}

// kubeAuditFallbackReplicas is how many control replicas the shared limits
// are divided among while Redis cannot be reached: this replica then keeps
// its share locally (K1b0 §6).
const kubeAuditFallbackReplicas = 3

// composeKubeAudit builds the writers over schema 245 once the runtime role
// may record (probed once: the capability list is fixed for the process);
// nil when it may not. With Redis the Workspace's and gateways' limits are
// shared among replicas; without, each replica keeps them alone.
func composeKubeAudit(ctx context.Context, runtimePool *postgresadapter.Pool, client *redisadapter.Client) (
	*kubeAudit, error,
) {
	store, err := postgresadapter.NewKubernetesOperationStore(runtimePool)
	if err != nil {
		return nil, errors.Join(errInvalidKubeAuditComposition, err)
	}
	granted, err := store.Granted(ctx)
	if err != nil || !granted {
		return nil, err
	}
	isolated := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_kubernetes_operation_writer_isolated_total",
		Help: "Kubernetes operation batches written submission by submission after a row's data failed one.",
	})
	cooled := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_kubernetes_operation_writer_cooled_off_total",
		Help: "Kubernetes operation batches answered unavailable while the writer cooled off after a failure.",
	})
	lost := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_kubernetes_operation_reports_lost_total",
		Help: "Kubernetes operation outcomes and denials the store did not write.",
	})
	intentOptions, reportOptions := kubeAuditWriterOptions, kubeAuditReportOptions
	intentOptions.Isolated, intentOptions.CooledOff = isolated.Inc, cooled.Inc
	reportOptions.Lost = func(rows int) { lost.Add(float64(rows)) }
	intents, err := kubeaudit.NewWriter(store, intentOptions)
	if err != nil {
		return nil, errors.Join(errInvalidKubeAuditComposition, err)
	}
	reports, err := kubeaudit.NewReportWriter(store, reportOptions)
	if err != nil {
		intents.Close()
		return nil, errors.Join(errInvalidKubeAuditComposition, err)
	}
	fellBack := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_kubernetes_operation_limits_fallback_total",
		Help: "Kubernetes operation limit takes answered locally because Redis could not be reached.",
	})
	var limits mtcpadapter.KubeAuditLimiter
	if client != nil {
		limits, err = kubeaudit.NewSharedLimiter(client, kubeaudit.DefaultLimits, kubeAuditFallbackReplicas, time.Now,
			fellBack.Inc)
	} else {
		limits, err = kubeaudit.NewLocalLimiter(kubeaudit.DefaultLimits, 1, time.Now)
	}
	if err != nil {
		intents.Close()
		reports.Close()
		return nil, errors.Join(errInvalidKubeAuditComposition, err)
	}
	queue := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "meshtransit_kubernetes_operation_writer_queue",
		Help: "Kubernetes operation rows waiting for their writer, by kind.",
	}, []string{"kind"})
	return &kubeAudit{intents: intents, reports: reports, limits: limits, metrics: []prometheus.Collector{
		isolated, cooled, lost, fellBack, kubeAuditQueue{queue: queue, intents: intents, reports: reports},
	}, closed: make(chan error)}, nil
}

// Start implements app.Service: the writers run from composition.
func (audit *kubeAudit) Start(context.Context) error { return nil }

// Done is closed once the writers were closed: they never stop alone.
func (audit *kubeAudit) Done() <-chan error { return audit.closed }

// Shutdown writes what the writers hold, or gives up waiting at ctx's end.
func (audit *kubeAudit) Shutdown(ctx context.Context) error {
	audit.shutdown.Do(func() {
		go func() {
			audit.intents.Close()
			audit.reports.Close()
			close(audit.closed)
		}()
	})
	select {
	case <-audit.closed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// kubeAuditQueue reports the writers' queues when scraped.
type kubeAuditQueue struct {
	queue   *prometheus.GaugeVec
	intents *kubeaudit.Writer
	reports *kubeaudit.ReportWriter
}

func (collector kubeAuditQueue) Describe(descriptions chan<- *prometheus.Desc) {
	collector.queue.Describe(descriptions)
}

func (collector kubeAuditQueue) Collect(metrics chan<- prometheus.Metric) {
	collector.queue.WithLabelValues("intent").Set(float64(collector.intents.Queued()))
	collector.queue.WithLabelValues("outcome").Set(float64(collector.reports.Queued()))
	collector.queue.Collect(metrics)
}

// kubeOperationPartitionOptions keep three months ahead and check hourly:
// a failed pass (a lock not taken in time) is retried within the hour, and
// the gauge alerts long before a month runs out (K1b0 §4, §8).
var kubeOperationPartitionOptions = partitions.Options{MonthsAhead: 3, Interval: time.Hour,
	OperationTimeout: 30 * time.Second}

// composeKubeOperationPartitions keeps the monthly partitions of Kubernetes
// operations on the worker, with its gauge and counter.
func composeKubeOperationPartitions(pool *postgresadapter.Pool, logger *slog.Logger) (
	*partitions.Maintainer, []prometheus.Collector, error,
) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidKubeAuditComposition
	}
	logger = logger.With("partitions", "kubernetes_operation")
	store, err := postgresadapter.NewKubernetesOperationPartitionStore(pool, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidKubeAuditComposition, err)
	}
	maintainer, err := partitions.New(kubeOperationPartitionOptions, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidKubeAuditComposition, err)
	}
	// Watch (review b0c H1, M1): ahead under 2, or -1 (this month's is
	// missing: type A operations are refused); a last whole pass over 3
	// hours old (passes keep failing, ahead is stale; before a whole pass it
	// is the worker's start); both absent while no worker runs. Ahead reads
	// NaN before the first whole pass, never an alert.
	ahead := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "meshtransit_kubernetes_operation_partitions_ahead",
		Help: "Months ahead of this one every Kubernetes operation table held at the last whole pass; " +
			"-1: this month's is missing; NaN: no pass yet.",
	}, store.Ahead)
	checked := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "meshtransit_kubernetes_operation_partitions_checked_timestamp_seconds",
		Help: "Unix time of the last whole Kubernetes operation partition pass, or of the worker's start before one.",
	}, store.CheckedAt)
	failed := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "meshtransit_kubernetes_operation_partitions_passes_failed_total",
		Help: "Kubernetes operation partition passes that failed, retried at the next one.",
	}, func() float64 { return float64(maintainer.Snapshot().Failed) })
	dropped := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "meshtransit_kubernetes_operation_partitions_dropped_total",
		Help: "Kubernetes operation partitions dropped past their retention.",
	}, func() float64 { return float64(store.Dropped()) })
	return maintainer, []prometheus.Collector{ahead, checked, failed, dropped}, nil
}
