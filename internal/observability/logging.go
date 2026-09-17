// Package observability constructs safe process observability primitives.
package observability

import (
	"errors"
	"io"
	"log/slog"
	"strings"
)

const redactedValue = "[REDACTED]"

// ErrInvalidLogger indicates that a logger dependency is missing.
var ErrInvalidLogger = errors.New("invalid logger configuration")

// NewLogger constructs a JSON slog logger that redacts values attached to
// sensitive attribute names and every leaf beneath a sensitive group name.
// Callers must still use fixed messages and trusted static names; this does not
// inspect arbitrary value contents or sanitize other logging/tracing sinks.
func NewLogger(output io.Writer, level slog.Level) (*slog.Logger, error) {
	if output == nil {
		return nil, ErrInvalidLogger
	}

	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redactAttribute,
	})
	return slog.New(handler), nil
}

func redactAttribute(groups []string, attribute slog.Attr) slog.Attr {
	if sensitiveKey(attribute.Key) {
		return slog.String(attribute.Key, redactedValue)
	}
	// ReplaceAttr visits non-group leaves only, including resolved LogValuers.
	// Inspect every ancestor without retaining or mutating the borrowed path.
	for _, group := range groups {
		if sensitiveKey(group) {
			return slog.String(attribute.Key, redactedValue)
		}
	}
	return attribute
}

func sensitiveKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	// Exact aliases keep closed status_code/error_code/state_version observable.
	switch normalized {
	case "error", "code", "authorizationcode", "state", "nonce",
		"codeverifier", "pkceverifier", "codechallenge", "proof", "csrf", "csrfproof",
		"claims", "idtokenclaims", "email", "emailaddress",
		"requesturi", "httprequesturi", "requesttarget", "httptarget",
		"rawquery", "query", "querystring", "queryparams", "queryparameters", "referer", "referrer":
		return true
	}
	for _, fragment := range []string{
		"authorization",
		"cookie",
		"credential",
		"dsn",
		"key",
		"password",
		"secret",
		"token",
		"url",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
