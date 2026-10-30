package postgres

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
)

// Denial counts answer profile reasons as today's readers know them: a
// profile's refusal as not_granted, a reporting grant's pass not at all
// (review d4a H1).
func TestFoldProfileDenials(t *testing.T) {
	t.Parallel()
	at := func(minutes int) time.Time { return time.Date(2026, 10, 30, 12, minutes, 0, 0, time.UTC) }
	folded := foldProfileDenials([]kubecluster.DenialCount{
		{Reason: "forbidden", Count: 1, FirstAt: at(1), LastAt: at(2)},
		{Reason: "not_granted", Count: 2, FirstAt: at(3), LastAt: at(4)},
		{Reason: "profile_denied", Count: 5, FirstAt: at(0), LastAt: at(9)},
		{Reason: "profile_would_deny", Count: 7, FirstAt: at(0), LastAt: at(9)},
	})
	if len(folded) != 2 || folded[1].Reason != "not_granted" || folded[1].Count != 7 ||
		!folded[1].FirstAt.Equal(at(0)) || !folded[1].LastAt.Equal(at(9)) {
		t.Fatalf("folded = %+v", folded)
	}
	alone := foldProfileDenials([]kubecluster.DenialCount{{Reason: "profile_denied", Count: 1, FirstAt: at(1),
		LastAt: at(1)}})
	if len(alone) != 1 || alone[0].Reason != "not_granted" {
		t.Fatalf("alone = %+v", alone)
	}
}
