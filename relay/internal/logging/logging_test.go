package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggerRedactsSensitiveAttributes(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	logger := New(&buffer, slog.LevelInfo)
	logger.Info("relay session refused", "error", errors.New("bad ticket for node nodekey:abcd"),
		"node_key", "nodekey:abcd", "relay_key_file", "/etc/meshrelay/key", "ticket", "t0k",
		"reason", "ticket_expired", "sessions", 3, slog.Group("credentials", "user", "x"),
		"public_key", "mtrelay:pub", "trusted_signing_keys", "mtsign:pub")
	out := buffer.String()
	for _, leaked := range []string{"nodekey:abcd", "/etc/meshrelay/key", "t0k", "\"x\""} {
		if strings.Contains(out, leaked) {
			t.Errorf("log leaks %q: %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"error":"[REDACTED]"`) {
		t.Errorf("error not replaced by [REDACTED]: %s", out)
	}
	for _, kept := range []string{"ticket_expired", "\"sessions\":3", "relay session refused", "mtrelay:pub", "mtsign:pub"} {
		if !strings.Contains(out, kept) {
			t.Errorf("log lost %q: %s", kept, out)
		}
	}
}
