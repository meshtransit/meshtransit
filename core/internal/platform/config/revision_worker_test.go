package config

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadRevisionWorkerRejectsUnsafeBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "zero batch", key: envRevisionWorkerBatchSize, value: "0"},
		{name: "oversized batch", key: envRevisionWorkerBatchSize, value: "257"},
		{name: "short lease", key: envRevisionWorkerLease, value: "999ms"},
		{name: "long lease", key: envRevisionWorkerLease, value: "5m1s"},
		{name: "short poll", key: envRevisionWorkerPollInterval, value: "99ms"},
		{name: "long poll", key: envRevisionWorkerPollInterval, value: "1m1s"},
		{name: "short retry", key: envRevisionWorkerRetryDelay, value: "99ms"},
		{name: "long retry", key: envRevisionWorkerRetryDelay, value: "24h1s"},
		{name: "short operation", key: envRevisionWorkerOperationTimeout, value: "99ms"},
		{name: "long operation", key: envRevisionWorkerOperationTimeout, value: "31s"},
		{name: "lease cannot cover batch", key: envRevisionWorkerLease, value: "24s"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validProcessValues(map[string]string{test.key: test.value})
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %q, want setting name %s", err, test.key)
			}
		})
	}
}

func TestLoadNonWorkerRoleIgnoresRevisionWorkerSettings(t *testing.T) {
	t.Parallel()

	values := validProcessValues(map[string]string{
		envRole:                    "api",
		envRevisionWorkerBatchSize: "not-an-integer",
	})
	got, err := Load(mapLookup(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.RevisionWorker != nil {
		t.Fatalf("RevisionWorker = %+v, want nil", got.RevisionWorker)
	}
}
