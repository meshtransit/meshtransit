// Package logging builds the relay's JSON logger. It redacts values under
// sensitive attribute names, as Core's logger does (TD-SEC-28): an error or a
// key never reaches the log as text. Messages and attribute names stay fixed
// by the caller; values are not inspected.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

const redacted = "[REDACTED]"

// New returns a JSON logger at level that redacts sensitive attributes.
func New(output io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level, ReplaceAttr: redact}))
}

func redact(groups []string, attribute slog.Attr) slog.Attr {
	if sensitive(attribute.Key) {
		return slog.String(attribute.Key, redacted)
	}
	for _, group := range groups {
		if sensitive(group) {
			return slog.String(attribute.Key, redacted)
		}
	}
	return attribute
}

func sensitive(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	switch normalized {
	// The relay's public key an operator copies into the relay map, and the
	// count of trusted signing keys: kept, by exact name.
	case "publickey", "trustedsigningkeys":
		return false
	case "error", "err", "ticket", "proof", "query", "rawquery", "requesturi", "referer", "referrer":
		return true
	}
	for _, fragment := range []string{
		"authorization", "cookie", "credential", "dsn", "key", "password", "secret", "token", "url",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
