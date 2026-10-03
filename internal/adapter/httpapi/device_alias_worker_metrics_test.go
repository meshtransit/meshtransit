package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/sharing/devicealias"
)

type deviceAliasMetricsStore struct{}

func (deviceAliasMetricsStore) List(context.Context, deployment.ID, devicealias.Cursor, int) (devicealias.Page, error) {
	return devicealias.Page{Done: true}, nil
}
func (deviceAliasMetricsStore) Change(context.Context, devicealias.ChangeIntent) (bool, error) {
	return false, nil
}

func TestDeviceAliasWorkerMetricsAreIdentifierFree(t *testing.T) {
	t.Parallel()
	installation, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := devicealias.New(devicealias.Options{DeploymentID: installation, BatchSize: 8, PollInterval: time.Second, OperationTimeout: time.Second}, deviceAliasMetricsStore{}, deviceAliasMetricsStore{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewDeviceAliasWorkerMetricsCollector(worker)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := newOperatorMetrics(newRuntimeState(t, app.RoleWorker), testBuildInfo(), nil, collector)
	if err != nil {
		t.Fatal(err)
	}
	body := request(t, metrics.handler, "/metrics").Body.String()
	for _, name := range []string{"running", "passes_total", "discovery_errors_total", "changes_total", "deferred_total"} {
		if !strings.Contains(body, "meshtransit_device_alias_worker_"+name+" 0") || strings.Contains(body, "meshtransit_device_alias_worker_"+name+"{") {
			t.Fatal("missing or labelled worker metric", name)
		}
	}
	if strings.Contains(body, installation.String()) {
		t.Fatal("metrics expose installation")
	}
	collector, err = NewDeviceAliasWorkerMetricsCollector(nil)
	if collector != nil || !errors.Is(err, ErrInvalidDeviceAliasWorkerMetrics) {
		t.Fatal("nil worker accepted", err)
	}
}
