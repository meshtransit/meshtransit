package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
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

func TestNewLoggerRedactsCallbackCustodyAliases(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"code", "authorization_code", "state", "nonce", "code_verifier", "pkce_verifier",
		"code_challenge", "proof", "csrf", "csrf_proof", "claims", "id_token_claims",
		"email", "email_address", "request_uri", "http_request_uri", "request_target",
		"http.target", "raw_query", "query", "query_string", "query_params", "query_parameters",
		"referer", "referrer", "RaW-QuErY", "AUTHORIZATION.CODE", "CsRf.PrOoF",
	} {
		t.Run(strings.ToLower(key), func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			logger, err := NewLogger(&output, slog.LevelInfo)
			if err != nil {
				t.Fatal("construct process logger")
			}
			logger.InfoContext(
				t.Context(),
				"callback unavailable",
				slog.String(key, "synthetic-private-custody"),
			)
			record := privateLogRecord(t, &output)
			if record[key] != redactedValue {
				t.Fatal("callback custody alias was not redacted")
			}
		})
	}
}

func TestNewLoggerRedactsSensitiveGroupAncestors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path []string
		emit func(*slog.Logger)
	}{
		{
			name: "record group",
			path: []string{"raw_query", "payload"},
			emit: func(logger *slog.Logger) {
				logger.Info("callback unavailable",
					slog.Group("raw_query", "payload", "synthetic-private-custody"),
					slog.String("operation", "complete"))
			},
		},
		{
			name: "prebound group and sibling",
			path: []string{"authorization", "value"},
			emit: func(logger *slog.Logger) {
				logger.With(slog.Group("authorization", "value", "synthetic-private-custody")).Info("callback unavailable")
			},
		},
		{
			name: "with group and prebound leaf",
			path: []string{"request", "Raw-Query", "payload"},
			emit: func(logger *slog.Logger) {
				logger.WithGroup("request").WithGroup("Raw-Query").
					With("payload", "synthetic-private-custody").Info("callback unavailable")
			},
		},
		{
			name: "distant sensitive ancestor",
			path: []string{"request", "EMAIL", "details", "value"},
			emit: func(logger *slog.Logger) {
				logger.WithGroup("request").WithGroup("EMAIL").WithGroup("details").
					Info("callback unavailable", "value", "synthetic-private-custody")
			},
		},
		{
			name: "nested inline groups",
			path: []string{"outer", "csrf_proof", "nested", "value"},
			emit: func(logger *slog.Logger) {
				logger.Info("callback unavailable", slog.Group("outer",
					slog.Group("csrf_proof", slog.Group("nested", "value", "synthetic-private-custody"))))
			},
		},
		{
			name: "resolved log valuer group",
			path: []string{"packet", "raw_query", "value"},
			emit: func(logger *slog.Logger) {
				logger.Info("callback unavailable", "packet", privateLogCustodyGroup{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			logger, err := NewLogger(&output, slog.LevelInfo)
			if err != nil {
				t.Fatal("construct process logger")
			}
			logger = logger.With(
				slog.String("error_code", "callback_unavailable"),
				slog.Int("status_code", 503),
				slog.String("result", "denied"),
			)
			test.emit(logger)
			record := privateLogRecord(t, &output)
			codesChanged := record["error_code"] != "callback_unavailable" || record["status_code"] != float64(503)
			outcomeChanged := record["result"] != "denied" || record["msg"] != "callback unavailable"
			if codesChanged || outcomeChanged {
				t.Fatal("closed sibling fields or fixed message changed")
			}
			if test.name == "record group" && record["operation"] != "complete" {
				t.Fatal("following sibling inherited sensitive group redaction")
			}
			var value any = record
			for _, key := range test.path {
				group, ok := value.(map[string]any)
				if !ok {
					t.Fatal("group structure changed")
				}
				value = group[key]
			}
			if value != redactedValue {
				t.Fatal("sensitive group leaf was not redacted")
			}
		})
	}
}

func TestNewLoggerPreservesClosedDiagnosticAttributes(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger, err := NewLogger(&output, slog.LevelInfo)
	if err != nil {
		t.Fatal("construct process logger")
	}
	logger.WithGroup("request").InfoContext(
		t.Context(),
		"callback unavailable",
		slog.Int("status_code", 503),
		slog.String("error_code", "callback_unavailable"),
		slog.Int("state_version", 2),
		slog.String("operation", "complete"),
		slog.String("result", "denied"),
	)
	record := privateLogRecord(t, &output)
	request, ok := record["request"].(map[string]any)
	if !ok {
		t.Fatal("diagnostic group absent")
	}
	for key, expected := range map[string]any{
		"status_code": float64(503), "error_code": "callback_unavailable", "state_version": float64(2),
		"operation": "complete", "result": "denied",
	} {
		if request[key] != expected {
			t.Fatal("closed diagnostic attribute changed")
		}
	}
}

type privateLogCustodyGroup struct{}

func (privateLogCustodyGroup) LogValue() slog.Value {
	return slog.GroupValue(slog.Group("raw_query", "value", "synthetic-private-custody"))
}

func privateLogRecord(t *testing.T, output *bytes.Buffer) map[string]any {
	t.Helper()
	if strings.Contains(output.String(), "synthetic-private-custody") {
		t.Fatal("private custody reached process log output")
	}
	record := make(map[string]any)
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal("decode process log record")
	}
	return record
}

func FuzzRedactAttributeSensitiveAncestor(f *testing.F) {
	f.Add("request", "details", uint8(0))
	f.Add("", "", uint8(1))
	f.Add("innocent", "nested", uint8(2))
	f.Fuzz(func(t *testing.T, prefix, suffix string, selector uint8) {
		if len(prefix) > 512 {
			prefix = prefix[:512]
		}
		if len(suffix) > 512 {
			suffix = suffix[:512]
		}
		anchors := []string{"Raw_Query", "authorization", "code", "CsRf-PrOoF", "EMAIL.ADDRESS"}
		groups := []string{prefix, anchors[int(selector)%len(anchors)], suffix}
		original := slices.Clone(groups)
		attribute := slog.String("payload", "synthetic-private-custody")
		got := redactAttribute(groups, attribute)
		isMarker := got.Value.Kind() == slog.KindString && got.Value.String() == redactedValue
		if got.Key != attribute.Key || !isMarker {
			t.Fatal("sensitive ancestor failed closed redaction")
		}
		if !slices.Equal(groups, original) {
			t.Fatal("redaction mutated borrowed group path")
		}
	})
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
