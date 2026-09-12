package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerEmitsJSONAndRedactsSensitiveAttributes(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger, err := NewLogger(&output, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}

	logger.With("authorization", "Bearer secret-one").Info(
		"runtime ready",
		"role", "api",
		"error_code", "startup_failed",
		"error", errors.New("secret-four"),
		"api_key", "secret-two",
		slog.Group("request", "password", "secret-three", "result", "accepted"),
	)

	encoded := output.String()
	for _, secret := range []string{"secret-one", "secret-two", "secret-three", "secret-four"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("log output contains sensitive value %q: %s", secret, encoded)
		}
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if record["role"] != "api" {
		t.Fatalf("role = %v, want api", record["role"])
	}
	if record["error_code"] != "startup_failed" {
		t.Fatalf("error_code = %v, want startup_failed", record["error_code"])
	}
	if record["error"] != redactedValue {
		t.Fatalf("error = %v, want redacted", record["error"])
	}
	if record["authorization"] != redactedValue {
		t.Fatalf("authorization = %v, want redacted", record["authorization"])
	}
	request, ok := record["request"].(map[string]any)
	if !ok {
		t.Fatalf("request = %T, want object", record["request"])
	}
	if request["password"] != redactedValue {
		t.Fatalf("password = %v, want redacted", request["password"])
	}
}

func TestNewLoggerHonorsLevel(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger, err := NewLogger(&output, slog.LevelWarn)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}

	logger.Info("not emitted")
	logger.Warn("emitted")

	if strings.Contains(output.String(), "not emitted") {
		t.Fatalf("info log was emitted at warn level: %s", output.String())
	}
	if !strings.Contains(output.String(), "emitted") {
		t.Fatalf("warn log was not emitted: %s", output.String())
	}
}

func TestNewLoggerRejectsNilOutput(t *testing.T) {
	t.Parallel()

	logger, err := NewLogger(nil, slog.LevelInfo)
	if !errors.Is(err, ErrInvalidLogger) {
		t.Fatalf("NewLogger() error = %v, want ErrInvalidLogger", err)
	}
	if logger != nil {
		t.Fatalf("NewLogger() = %v, want nil", logger)
	}
}
