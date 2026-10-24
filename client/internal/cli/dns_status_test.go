package cli

import "testing"

func TestFormatDNSStatusShowsTheHostRefusal(t *testing.T) {
	t.Parallel()
	if got := formatDNSStatus("configured", ""); got != "configured" {
		t.Fatalf("configured = %q", got)
	}
	if got := formatDNSStatus("failed", "resolved refused the link"); got != "failed (resolved refused the link)" {
		t.Fatalf("failed = %q", got)
	}
}
