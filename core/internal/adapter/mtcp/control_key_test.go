package mtcp

import (
	"errors"
	"strings"
	"testing"
)

func TestParseControlKey(t *testing.T) {
	t.Parallel()
	valid := "privkey:" + strings.Repeat("1f", 32)
	if private, err := ParseControlKey(valid); err != nil || private.IsZero() {
		t.Fatalf("valid key: %v", err)
	}
	for name, text := range map[string]string{
		"empty":      "",
		"no prefix":  strings.Repeat("1f", 32),
		"public":     "mkey:" + strings.Repeat("1f", 32),
		"short":      "privkey:" + strings.Repeat("1f", 31),
		"long":       valid + "00",
		"uppercase":  "privkey:" + strings.Repeat("1F", 32),
		"not hex":    "privkey:" + strings.Repeat("zz", 32),
		"zero":       "privkey:" + strings.Repeat("00", 32),
		"whitespace": valid + " ",
	} {
		if _, err := ParseControlKey(text); !errors.Is(err, ErrInvalidControlKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
