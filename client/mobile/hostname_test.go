package mobile

import (
	"runtime"
	"strings"
	"testing"
)

func TestHostnameForMakesADNSLabel(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"POCO F4":                    "poco-f4",
		"Điện thoại của Mạnh":        "dien-thoai-cua-manh",
		"  Pixel 9 Pro (work)  ":     "pixel-9-pro-work",
		"iPhone_15--Max":             "iphone-15-max",
		"café":                       "cafe",
		"手机":                         runtime.GOOS,
		"---":                        runtime.GOOS,
		strings.Repeat("a", 70):      strings.Repeat("a", 63),
		strings.Repeat("ab ", 30):    strings.TrimSuffix(strings.Repeat("ab-", 21), "-"),
		"Galaxy S24 Ultra của Hạnh!": "galaxy-s24-ultra-cua-hanh",
	} {
		got := hostnameFor(name)
		if got != want {
			t.Errorf("hostnameFor(%q) = %q, want %q", name, got, want)
		}
		if !validLabel(got) {
			t.Errorf("hostnameFor(%q) = %q is not a DNS label Core accepts", name, got)
		}
	}
}

// validLabel is Core's rule for a hostname label (core/internal/domain/node).
func validLabel(label string) bool {
	if len(label) == 0 || len(label) > maxHostnameLabel || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		letter := character >= 'a' && character <= 'z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && character != '-' {
			return false
		}
	}
	return true
}
