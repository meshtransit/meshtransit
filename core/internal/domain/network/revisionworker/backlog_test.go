package revisionworker

import (
	"errors"
	"testing"
	"time"
)

func TestNewBacklogValidatesReadyWorkObservation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		events    int64
		oldestAge time.Duration
		wantError bool
	}{
		{name: "empty", events: 0, oldestAge: 0},
		{name: "ready events", events: 4, oldestAge: 3 * time.Second},
		{name: "negative events", events: -1, wantError: true},
		{name: "negative age", events: 1, oldestAge: -time.Second, wantError: true},
		{name: "empty with age", oldestAge: time.Second, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			backlog, err := NewBacklog(test.events, test.oldestAge)
			if test.wantError {
				if !errors.Is(err, ErrInvalidBacklog) {
					t.Fatalf("NewBacklog() error = %v, want ErrInvalidBacklog", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewBacklog() error = %v", err)
			}
			if backlog.Events() != test.events || backlog.OldestAge() != test.oldestAge {
				t.Fatalf(
					"NewBacklog() = (%d, %s), want (%d, %s)",
					backlog.Events(),
					backlog.OldestAge(),
					test.events,
					test.oldestAge,
				)
			}
		})
	}
}
