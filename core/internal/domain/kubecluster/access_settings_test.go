package kubecluster_test

import (
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

// A contact is what a gateway shows a refused user: bounded clean text, or
// none (K2 §29.1).
func TestValidAccessContact(t *testing.T) {
	t.Parallel()
	for contact, valid := range map[string]bool{
		"":                             true,
		"#k8s-access on Slack":         true,
		"platform@example.com, ext 42": true,
		"Nhóm nền tảng":                true,
		strings.Repeat("a", 256):       true,
		strings.Repeat("a", 257):       false,
		" leading space":               false,
		"line\nbreak":                  false,
		"bell\x07":                     false,
		"right-to-left\u202eoverride":  false,
		string([]byte{0xff, 0xfe}):     false,
	} {
		if got := kubecluster.ValidAccessContact(contact); got != valid {
			t.Errorf("ValidAccessContact(%q) = %t", contact, got)
		}
	}
}
