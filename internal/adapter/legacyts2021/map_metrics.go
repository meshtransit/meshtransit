package legacyts2021

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type mapResult uint8

const (
	mapResultUnknown mapResult = iota
	mapAuthorized
	mapStreamClosed
	mapAuthorityChanged
	mapCoordinationLost
	mapInvalidRequest
	mapAuthenticationFailed
	mapCanceled
	mapUnavailable
)

type mapMetrics struct {
	active   prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	streams  prometheus.Gauge
}

func newMapMetrics() mapMetrics {
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_map_requests_active",
		Help: "Number of authenticated map requests currently being processed.",
	})
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_control_map_requests_total",
		Help: "Total authenticated map requests by bounded terminal result.",
	}, []string{"result"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_control_map_request_duration_seconds",
		Help:    "Authenticated map request duration by bounded terminal result.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"result"})
	streams := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_map_streams_active",
		Help: "Number of active authenticated map streams owned by this replica.",
	})
	for _, result := range allMapResults() {
		label := result.label()
		requests.WithLabelValues(label)
		duration.WithLabelValues(label)
	}
	return mapMetrics{active: active, requests: requests, duration: duration, streams: streams}
}

func (metrics mapMetrics) collectors() [4]prometheus.Collector {
	return [4]prometheus.Collector{metrics.active, metrics.requests, metrics.duration, metrics.streams}
}

func (metrics mapMetrics) start() time.Time {
	metrics.active.Inc()
	return time.Now()
}

func (metrics mapMetrics) finish(startedAt time.Time, result mapResult) {
	metrics.active.Dec()
	label := result.label()
	metrics.requests.WithLabelValues(label).Inc()
	metrics.duration.WithLabelValues(label).Observe(time.Since(startedAt).Seconds())
}

func (metrics mapMetrics) streamOpened() { metrics.streams.Inc() }

func (metrics mapMetrics) streamClosed() { metrics.streams.Dec() }

func allMapResults() [8]mapResult {
	return [8]mapResult{
		mapAuthorized,
		mapStreamClosed,
		mapAuthorityChanged,
		mapCoordinationLost,
		mapInvalidRequest,
		mapAuthenticationFailed,
		mapCanceled,
		mapUnavailable,
	}
}

func (result mapResult) label() string {
	switch result {
	case mapAuthorized:
		return "authorized"
	case mapStreamClosed:
		return "stream_closed"
	case mapAuthorityChanged:
		return "authority_changed"
	case mapCoordinationLost:
		return "coordination_lost"
	case mapInvalidRequest:
		return "invalid_request"
	case mapAuthenticationFailed:
		return "authentication_failed"
	case mapCanceled:
		return "canceled"
	case mapUnavailable:
		return "unavailable"
	default:
		return "internal_failure"
	}
}
