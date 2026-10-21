package captivewindow

import (
	"strings"
	"testing"
	"time"
)

func TestWindowValidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	good := Window{ID: strings.Repeat("0f", 16), OpenedAt: now.Add(-3 * time.Minute), ClosedAt: now.Add(-time.Minute),
		End: EndExpired}
	if err := good.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Window){
		"id":          func(window *Window) { window.ID = strings.Repeat("0F", 16) },
		"end":         func(window *Window) { window.End = "portal" },
		"no opening":  func(window *Window) { window.OpenedAt = time.Time{} },
		"backwards":   func(window *Window) { window.ClosedAt = window.OpenedAt.Add(-time.Second) },
		"too long":    func(window *Window) { window.OpenedAt = window.ClosedAt.Add(-MaximumLength - time.Second) },
		"in a minute": func(window *Window) { window.ClosedAt = now.Add(2 * time.Minute) },
		"too old": func(window *Window) {
			window.OpenedAt, window.ClosedAt = now.Add(-MaximumAge-time.Hour), now.Add(-MaximumAge-time.Hour+time.Minute)
		},
	} {
		window := good
		change(&window)
		if window.Validate(now) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !ValidID(good.ID) || ValidID("ab") {
		t.Fatal("ValidID")
	}
}
