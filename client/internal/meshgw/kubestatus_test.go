package meshgw

import (
	"testing"
	"time"
)

// A group never checked makes the oldest check 0, first or last (review
// b6a M5).
func TestOldestCheck(t *testing.T) {
	t.Parallel()
	checked := time.Unix(1_800_000_000, 0)
	for name, groups := range map[string][]groupStatus{
		"unchecked first": {{Name: "a"}, {Name: "b", CheckedAt: checked}},
		"unchecked last":  {{Name: "b", CheckedAt: checked}, {Name: "a"}},
		"none":            {},
	} {
		if got := oldestCheck(groups); got != 0 {
			t.Errorf("%s: %d", name, got)
		}
	}
	if got := oldestCheck([]groupStatus{{CheckedAt: checked.Add(time.Hour)}, {CheckedAt: checked}}); got != checked.Unix() {
		t.Fatalf("oldest %d", got)
	}
	if got := labelValue("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Fatalf("escaped %q", got)
	}
}
