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
// sensitive attribute names at every slog group depth.
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

func redactAttribute(_ []string, attribute slog.Attr) slog.Attr {
	if !sensitiveKey(attribute.Key) {
		return attribute
	}
	return slog.String(attribute.Key, redactedValue)
}

func sensitiveKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	if normalized == "error" {
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
