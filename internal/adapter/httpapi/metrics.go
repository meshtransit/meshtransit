package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxBuildLabelBytes = 128

var (
	// ErrInvalidMetrics indicates unsafe build metadata or runtime state.
	ErrInvalidMetrics = errors.New("invalid operator metrics")
)

// BuildInfo is bounded, non-secret release metadata exposed to operators.
type BuildInfo struct {
	Version             string
	Revision            string
	GoVersion           string
	ConfigSchemaVersion int
}

type operatorMetrics struct {
	handler         http.Handler
	requestTotal    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

func newOperatorMetrics(
	state healthState,
	build BuildInfo,
	workerTelemetry revisionWorkerTelemetry,
	additionalCollectors ...prometheus.Collector,
) (*operatorMetrics, error) {
	if state == nil || !validBuildInfo(build) {
		return nil, ErrInvalidMetrics
	}
	snapshot := state.Snapshot()
	if len(snapshot.Roles) == 0 {
		return nil, ErrInvalidMetrics
	}

	registry := prometheus.NewRegistry()
	requestTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_operator_http_requests_total",
		Help: "Total operator HTTP requests by bounded route and status class.",
	}, []string{"route", "status"})
	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_operator_http_request_duration_seconds",
		Help:    "Operator HTTP request duration by bounded route.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	}, []string{"route"})
	buildMetric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_build_info",
		Help: "Static build and configuration schema metadata.",
		ConstLabels: prometheus.Labels{
			"config_schema_version": strconv.Itoa(build.ConfigSchemaVersion),
			"go_version":            build.GoVersion,
			"revision":              build.Revision,
			"version":               build.Version,
		},
	})
	buildMetric.Set(1)
	collectorSet := []prometheus.Collector{
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		requestTotal,
		requestDuration,
		buildMetric,
	}

	for _, role := range snapshot.Roles {
		if !validRoleLabel(role) {
			return nil, ErrInvalidMetrics
		}
	}

	components := make([]string, 0, len(snapshot.Components))
	for component := range snapshot.Components {
		if !validComponentLabel(component) {
			return nil, ErrInvalidMetrics
		}
		components = append(components, component)
	}
	sort.Strings(components)
	collectorSet = append(collectorSet, newRuntimeMetricsCollector(state, snapshot.Roles, components))
	if workerTelemetry != nil {
		collectorSet = append(collectorSet, newRevisionWorkerMetricsCollector(workerTelemetry))
	}
	for _, collector := range additionalCollectors {
		if collector == nil {
			return nil, ErrInvalidMetrics
		}
		collectorSet = append(collectorSet, collector)
	}

	for _, collector := range collectorSet {
		if err := registry.Register(collector); err != nil {
			return nil, fmt.Errorf("%w: register collector: %w", ErrInvalidMetrics, err)
		}
	}

	return &operatorMetrics{
		handler: promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			ErrorHandling:     promhttp.HTTPErrorOnError,
			ErrorLog:          log.New(io.Discard, "", 0),
			EnableOpenMetrics: true,
		}),
		requestTotal:    requestTotal,
		requestDuration: requestDuration,
	}, nil
}

type runtimeMetricsCollector struct {
	state          healthState
	roles          []string
	components     []string
	readyDesc      *prometheus.Desc
	roleDesc       *prometheus.Desc
	dependencyDesc *prometheus.Desc
}

func newRuntimeMetricsCollector(
	state healthState,
	roles []string,
	components []string,
) *runtimeMetricsCollector {
	return &runtimeMetricsCollector{
		state:      state,
		roles:      append([]string(nil), roles...),
		components: append([]string(nil), components...),
		readyDesc: prometheus.NewDesc(
			"meshtransit_runtime_ready",
			"Whether the runtime can safely admit its configured work.",
			nil,
			nil,
		),
		roleDesc: prometheus.NewDesc(
			"meshtransit_runtime_role",
			"Active concrete runtime roles.",
			[]string{"role"},
			nil,
		),
		dependencyDesc: prometheus.NewDesc(
			"meshtransit_dependency_ready",
			"Whether the last bounded dependency check succeeded.",
			[]string{"component"},
			nil,
		),
	}
}

func (collector *runtimeMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.readyDesc
	descriptions <- collector.roleDesc
	descriptions <- collector.dependencyDesc
}

func (collector *runtimeMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.state.Snapshot()
	metrics <- prometheus.MustNewConstMetric(
		collector.readyDesc,
		prometheus.GaugeValue,
		boolMetricValue(snapshot.Ready),
	)
	for _, role := range collector.roles {
		metrics <- prometheus.MustNewConstMetric(
			collector.roleDesc,
			prometheus.GaugeValue,
			1,
			role,
		)
	}
	for _, component := range collector.components {
		metrics <- prometheus.MustNewConstMetric(
			collector.dependencyDesc,
			prometheus.GaugeValue,
			boolMetricValue(snapshot.Components[component] == "ready"),
			component,
		)
	}
}

func boolMetricValue(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func (metrics *operatorMetrics) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		startedAt := time.Now()
		writer := &statusResponseWriter{ResponseWriter: response}
		next.ServeHTTP(writer, request)
		metrics.requestTotal.WithLabelValues(operatorRoute(request.URL.Path), statusClass(writer.StatusCode())).Inc()
		metrics.requestDuration.WithLabelValues(operatorRoute(request.URL.Path)).Observe(time.Since(startedAt).Seconds())
	})
}

func validBuildInfo(build BuildInfo) bool {
	return validBuildLabel(build.Version) &&
		validBuildLabel(build.Revision) &&
		validBuildLabel(build.GoVersion) &&
		build.ConfigSchemaVersion > 0
}

func validBuildLabel(value string) bool {
	if value == "" || len(value) > maxBuildLabelBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < '!' || character > '~' {
			return false
		}
	}
	return true
}

func validRoleLabel(role string) bool {
	switch role {
	case "api", "control", "worker", "relay":
		return true
	default:
		return false
	}
}

func validComponentLabel(component string) bool {
	return component == "postgresql" || component == "redis"
}

func operatorRoute(path string) string {
	switch path {
	case "/live":
		return "live"
	case "/ready":
		return "ready"
	case "/health":
		return "health"
	case "/metrics":
		return "metrics"
	default:
		return "not_found"
	}
}

func statusClass(statusCode int) string {
	switch statusCode / 100 {
	case 1:
		return "1xx"
	case 2:
		return "2xx"
	case 3:
		return "3xx"
	case 4:
		return "4xx"
	case 5:
		return "5xx"
	default:
		return "unknown"
	}
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (writer *statusResponseWriter) WriteHeader(statusCode int) {
	if writer.statusCode != 0 {
		return
	}
	writer.statusCode = statusCode
	writer.ResponseWriter.WriteHeader(statusCode)
}

func (writer *statusResponseWriter) Write(body []byte) (int, error) {
	if writer.statusCode == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *statusResponseWriter) StatusCode() int {
	if writer.statusCode == 0 {
		return http.StatusOK
	}
	return writer.statusCode
}

func (writer *statusResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}
