package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/retention"
	"meshtransit.net/core/internal/platform/app"
)

var errInvalidRetentionComposition = errors.New("invalid retention composition")

// composeRetention removes, on the worker, what the retention policy no
// longer keeps (schema 274), with counters of what went and the time of the
// last whole pass. Watch: that time over three hours old means passes keep
// failing (most often a lock on the Activity table not taken in 200 ms).
func composeRetention(pool *postgresadapter.Pool, logger *slog.Logger) (
	*retention.Maintainer, []prometheus.Collector, error,
) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidRetentionComposition
	}
	store, err := postgresadapter.NewRetentionStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidRetentionComposition, err)
	}
	maintainer, err := retention.New(retention.DefaultOptions(), store, logger.With("job", "retention"))
	if err != nil {
		return nil, nil, errors.Join(errInvalidRetentionComposition, err)
	}
	removed := func(name, help string, read func(retention.Measurements) uint64) prometheus.Collector {
		return prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help},
			func() float64 { return float64(read(maintainer.Snapshot())) })
	}
	collectors := []prometheus.Collector{
		removed("meshtransit_retention_idempotency_records_removed_total",
			"Expired idempotency records removed.",
			func(m retention.Measurements) uint64 { return m.IdempotencyRecords }),
		removed("meshtransit_retention_outbox_events_removed_total",
			"Finished outbox events removed with their attempts.",
			func(m retention.Measurements) uint64 { return m.OutboxEvents }),
		removed("meshtransit_retention_outbox_attempts_removed_total",
			"Outbox delivery attempts removed with their events.",
			func(m retention.Measurements) uint64 { return m.OutboxAttempts }),
		removed("meshtransit_retention_audit_partitions_removed_total",
			"Monthly Activity partitions dropped past retention.",
			func(m retention.Measurements) uint64 { return m.AuditPartitions }),
		removed("meshtransit_retention_audit_rows_removed_total",
			"Activity identities, authority mutations and stray events removed past retention.",
			func(m retention.Measurements) uint64 { return m.AuditRows + m.AuditEvents }),
		removed("meshtransit_retention_network_summary_marks_folded_total",
			"Network summary change marks folded into their queue.",
			func(m retention.Measurements) uint64 { return m.SummaryMarks }),
		removed("meshtransit_retention_passes_failed_total",
			"Retention passes that failed, retried at the next one.",
			func(m retention.Measurements) uint64 { return m.Failed }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "meshtransit_retention_last_whole_pass_timestamp_seconds",
			Help: "Unix time of the last retention pass that finished every kind; 0 before one.",
		}, func() float64 {
			last := maintainer.Snapshot().LastWholePass
			if last.IsZero() {
				return 0
			}
			return float64(last.Unix())
		}),
	}
	return maintainer, collectors, nil
}

var _ app.Service = (*retention.Maintainer)(nil)
