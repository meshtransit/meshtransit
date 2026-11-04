package main

import (
	"errors"
	"log/slog"
	"math"

	"github.com/prometheus/client_golang/prometheus"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/auditvolume"
)

var errInvalidAuditVolumeComposition = errors.New("invalid audit volume composition")

// composeAuditVolume samples, on the worker, the events every Deployment
// audit stream holds (TD-CORE-134). Watch rate() of the counter: that stream
// is one row every Workspace's sign-ins and sessions queue on, measured at
// roughly 500–1 000 events/s; alert well before, at about 100/s. Every
// worker replica reports the same total: alert on max, never sum, of
// rate() over the counter, and only while the last sample is fresh (a
// failed read keeps the last value, which reads as 0/s).
func composeAuditVolume(pool *postgresadapter.Pool, logger *slog.Logger) (
	*auditvolume.Sampler, []prometheus.Collector, error,
) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidAuditVolumeComposition
	}
	store, err := postgresadapter.NewAuditVolumeStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidAuditVolumeComposition, err)
	}
	sampler, err := auditvolume.New(auditvolume.DefaultOptions(), store, logger.With("job", "audit-volume"))
	if err != nil {
		return nil, nil, errors.Join(errInvalidAuditVolumeComposition, err)
	}
	collectors := []prometheus.Collector{
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "meshtransit_audit_deployment_events_total",
			Help: "Audit events every Deployment stream holds at the last sample; rate() is their write rate. " +
				"Every worker replica reports the same total: use max, not sum. " +
				"NaN before the first sample, so a start is not read as a burst.",
		}, func() float64 {
			snapshot := sampler.Snapshot()
			if !snapshot.Sampled {
				return math.NaN()
			}
			return float64(snapshot.Events)
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "meshtransit_audit_deployment_events_sampled_timestamp_seconds",
			Help: "Unix time of the last good sample of the Deployment audit streams; 0 before one.",
		}, func() float64 {
			snapshot := sampler.Snapshot()
			if !snapshot.Sampled {
				return 0
			}
			return float64(snapshot.At.Unix())
		}),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "meshtransit_audit_deployment_samples_failed_total",
			Help: "Samples of the Deployment audit streams that failed.",
		}, func() float64 { return float64(sampler.Snapshot().Failed) }),
	}
	return sampler, collectors, nil
}
