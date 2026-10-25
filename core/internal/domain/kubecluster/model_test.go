package kubecluster_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func TestParseNameAcceptsDNSLabels(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"prod", "a", "eks-prod-1", "0", strings.Repeat("a", 60)} {
		name, err := kubecluster.ParseName(value)
		if err != nil || name.String() != value {
			t.Errorf("ParseName(%q) = %q, %v", value, name, err)
		}
	}
}

func TestParseNameRefusesOtherText(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"", "Prod", "-prod", "prod-", "pr_od", "pr.od", " prod", "prod ", strings.Repeat("a", 61), "prød",
	} {
		if _, err := kubecluster.ParseName(value); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("ParseName(%q) error = %v, want ErrInvalid", value, err)
		}
	}
}

func TestValidDescription(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"":                        true,
		"EKS in Singapore":        true,
		strings.Repeat("é", 128):  true,
		strings.Repeat("a", 129):  false,
		" leading":                false,
		"trailing ":               false,
		"line\nbreak":             false,
		"delete\x7f":              false,
		string([]byte{0xff, 'a'}): false,
	}
	for description, want := range cases {
		if got := kubecluster.ValidDescription(description); got != want {
			t.Errorf("ValidDescription(%q) = %v, want %v", description, got, want)
		}
	}
}

func TestJoinKeyRequestBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		lifetime time.Duration
		uses     int
		valid    bool
	}{
		{"shortest", kubecluster.MinimumJoinKeyLifetime, 1, true},
		{"longest", kubecluster.MaximumJoinKeyLifetime, kubecluster.MaximumJoinKeyUses, true},
		{"default lifetime", 0, 2, true},
		{"over an hour", time.Hour + time.Second, 1, false},
		{"under five minutes", 4 * time.Minute, 1, false},
		{"fraction of a second", 10*time.Minute + time.Millisecond, 1, false},
		{"no use", time.Hour, 0, false},
		{"too many uses", time.Hour, kubecluster.MaximumJoinKeyUses + 1, false},
	}
	for _, tc := range cases {
		got := kubecluster.ValidJoinKey(tc.lifetime, tc.uses)
		if got != tc.valid {
			t.Errorf("%s: ValidJoinKey(%v, %d) = %v, want %v", tc.name, tc.lifetime, tc.uses, got, tc.valid)
		}
	}
	if kubecluster.MaximumPendingRequests(3) != 6 {
		t.Fatalf("MaximumPendingRequests(3) = %d, want 6", kubecluster.MaximumPendingRequests(3))
	}
}

func pendingRequest(t *testing.T, created, expires time.Time) kubecluster.Request {
	t.Helper()
	request, err := kubecluster.NewRequest(kubecluster.RequestParams{
		State: kubecluster.RequestPending, CreatedAt: created, ExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return request
}

// An approval before the deadline moves a pending request on; anything else
// is refused without a change.
func TestRequestApprove(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	expires := created.Add(time.Hour)
	request := pendingRequest(t, created, expires)

	approved, err := request.Approve(created.Add(time.Minute))
	if err != nil || approved.State() != kubecluster.RequestApproved {
		t.Fatalf("Approve() = %v, %v", approved.State(), err)
	}
	if _, err := approved.Approve(created.Add(2 * time.Minute)); !errors.Is(err, kubecluster.ErrTransition) {
		t.Fatalf("approving twice error = %v, want ErrTransition", err)
	}
	if _, err := request.Approve(expires); !errors.Is(err, kubecluster.ErrExpired) {
		t.Fatalf("approving at the deadline error = %v, want ErrExpired", err)
	}
	if request.State() != kubecluster.RequestPending {
		t.Fatal("a refused approval changed the request")
	}
}

// Each wrong code counts; the fifth cancels the request.
func TestRequestWrongCodes(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	request := pendingRequest(t, created, created.Add(time.Hour))
	for attempt := 1; attempt <= kubecluster.MaximumCodeAttempts; attempt++ {
		next, err := request.WrongCode(created.Add(time.Minute))
		if err != nil {
			t.Fatalf("WrongCode() attempt %d error = %v", attempt, err)
		}
		if next.FailedAttempts() != attempt {
			t.Fatalf("attempt %d: FailedAttempts() = %d", attempt, next.FailedAttempts())
		}
		wantCancelled := attempt == kubecluster.MaximumCodeAttempts
		if (next.State() == kubecluster.RequestCancelled) != wantCancelled {
			t.Fatalf("attempt %d: state = %v", attempt, next.State())
		}
		request = next
	}
	if _, err := request.WrongCode(created.Add(time.Minute)); !errors.Is(err, kubecluster.ErrTransition) {
		t.Fatalf("a wrong code on a cancelled request error = %v", err)
	}
}

func TestRequestTerminalStates(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	request := pendingRequest(t, created, created.Add(time.Hour))
	rejected, err := request.Reject()
	if err != nil || rejected.State() != kubecluster.RequestRejected {
		t.Fatalf("Reject() = %v, %v", rejected.State(), err)
	}
	if _, err := rejected.Approve(created); !errors.Is(err, kubecluster.ErrTransition) {
		t.Fatalf("approving a rejected request error = %v", err)
	}
	if _, err := request.Complete(); !errors.Is(err, kubecluster.ErrTransition) {
		t.Fatalf("completing a pending request error = %v", err)
	}
	approved, err := request.Approve(created)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := approved.Complete()
	if err != nil || completed.State() != kubecluster.RequestCompleted {
		t.Fatalf("Complete() = %v, %v", completed.State(), err)
	}
	if _, err := completed.Reject(); !errors.Is(err, kubecluster.ErrTransition) {
		t.Fatalf("rejecting a completed request error = %v", err)
	}
}

func TestNewRequestRefusesInconsistentState(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	for name, params := range map[string]kubecluster.RequestParams{
		"unknown state":      {CreatedAt: created, ExpiresAt: created.Add(time.Hour)},
		"no creation time":   {State: kubecluster.RequestPending, ExpiresAt: created},
		"deadline not after": {State: kubecluster.RequestPending, CreatedAt: created, ExpiresAt: created},
		"negative attempts":  {State: kubecluster.RequestPending, CreatedAt: created, ExpiresAt: created.Add(time.Hour), FailedAttempts: -1},
		"too many attempts":  {State: kubecluster.RequestPending, CreatedAt: created, ExpiresAt: created.Add(time.Hour), FailedAttempts: kubecluster.MaximumCodeAttempts},
		"over the ceiling":   {State: kubecluster.RequestCancelled, CreatedAt: created, ExpiresAt: created.Add(time.Hour), FailedAttempts: kubecluster.MaximumCodeAttempts + 1},
	} {
		if _, err := kubecluster.NewRequest(params); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: NewRequest() error = %v, want ErrInvalid", name, err)
		}
	}
}
