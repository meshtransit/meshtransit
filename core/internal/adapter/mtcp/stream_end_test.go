package mtcp

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/control/mapsession"
)

func TestStreamEndReasons(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want string
	}{
		{mapsession.ErrSuspended, "suspended"},
		{errors.Join(mapsession.ErrUnauthorized, errors.New("x")), "unauthorized"},
		{mapsession.ErrAuthorizationExpired, "unauthorized"},
		{mapsession.ErrPresenceConflict, "presence_conflict"},
		{errors.Join(mapsession.ErrStreamUnavailable, errors.New("db timeout")), "unavailable"},
		{errors.Join(mapsession.ErrStreamWrite, errors.New("reset")), "write_failed"},
		{mapsession.ErrStreamDiscontinuity, "discontinuity"},
		{errors.New("anything else"), "other"},
	}
	for _, test := range tests {
		if got := streamEndReason(test.err); got != test.want {
			t.Errorf("streamEndReason(%v) = %q, want %q", test.err, got, test.want)
		}
	}
	metrics := NewMetrics()
	metrics.streamEnded("unavailable")
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() != "meshtransit_mtcp_map_stream_ends_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metric.GetLabel()[0].GetValue() == "unavailable" && metric.GetCounter().GetValue() == 1 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("stream end counter not exported with reason unavailable = 1")
	}
	var none *Metrics
	none.streamEnded("other") // an Application without metrics must not panic
}
