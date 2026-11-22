package kubecluster_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
)

type recordingTrusts struct {
	confirms, chooses []kubecluster.TrustDecision
	resets            []kubecluster.TrustReset
}

func (store *recordingTrusts) ConfirmTrust(_ context.Context,
	decision kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error) {
	store.confirms = append(store.confirms, decision)
	return kubecluster.TrustDecisionResult{Changed: true}, nil
}

func (store *recordingTrusts) ChooseTrust(_ context.Context,
	decision kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error) {
	store.chooses = append(store.chooses, decision)
	return kubecluster.TrustDecisionResult{Changed: true}, nil
}

func (store *recordingTrusts) ResetTrust(_ context.Context,
	reset kubecluster.TrustReset) (kubecluster.TrustDecisionResult, error) {
	store.resets = append(store.resets, reset)
	return kubecluster.TrustDecisionResult{Changed: true}, nil
}

func TestPodTokenIsValidAt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	valid := kubecluster.PodToken{PodUID: "0d4b5c2e-9a7f-4b1e-8c3d-2f6a1b9e7c40", JTI: "8f2c-41",
		ExpiresAt: now.Add(time.Hour)}
	if !valid.IsValidAt(now) {
		t.Fatal("a valid pod token was refused")
	}
	for name, change := range map[string]func(*kubecluster.PodToken){
		"upper-case UID":  func(token *kubecluster.PodToken) { token.PodUID = strings.ToUpper(token.PodUID) },
		"short UID":       func(token *kubecluster.PodToken) { token.PodUID = token.PodUID[1:] },
		"no jti":          func(token *kubecluster.PodToken) { token.JTI = "" },
		"space in jti":    func(token *kubecluster.PodToken) { token.JTI = "a b" },
		"long jti":        func(token *kubecluster.PodToken) { token.JTI = strings.Repeat("a", 129) },
		"expired":         func(token *kubecluster.PodToken) { token.ExpiresAt = now },
		"beyond an hour":  func(token *kubecluster.PodToken) { token.ExpiresAt = now.Add(2 * time.Hour) },
		"no expiry given": func(token *kubecluster.PodToken) { token.ExpiresAt = time.Time{} },
	} {
		token := valid
		change(&token)
		if token.IsValidAt(now) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKnownRefusal(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{kubecluster.RefusedTokenReplayed, kubecluster.RefusedPodHeld,
		kubecluster.RefusedApprover, kubecluster.RefusedDiffersFromTrust} {
		if !kubecluster.KnownRefusal(reason) {
			t.Errorf("%s is not known", reason)
		}
	}
	if kubecluster.KnownRefusal("approved") || kubecluster.KnownRefusal("") {
		t.Fatal("an unknown reason is known")
	}
}

func TestTrusts(t *testing.T) {
	t.Parallel()
	_, _, session, scope, now := serviceFixture(t)
	store := &recordingTrusts{}
	trusts, err := kubecluster.NewTrusts(store, fixedClock(now))
	if err != nil {
		t.Fatal(err)
	}
	cluster := kubecluster.ID(mustID(t, "000000000301"))
	decision := kubecluster.TrustDecision{Session: session, Scope: scope, ClusterID: cluster, Digest: [32]byte{7},
		Version: 4, CorrelationID: mustID(t, "000000000921")}
	if _, err := trusts.Confirm(context.Background(), decision); err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if _, err := trusts.Choose(context.Background(), decision); err != nil {
		t.Fatalf("Choose() error = %v", err)
	}
	reset := kubecluster.TrustReset{Session: session, Scope: scope, ClusterID: cluster, Reason: "rebuilt",
		Version: 4, CorrelationID: mustID(t, "000000000922")}
	if _, err := trusts.Reset(context.Background(), reset); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	for name, change := range map[string]func(*kubecluster.TrustDecision){
		"no digest":      func(decision *kubecluster.TrustDecision) { decision.Digest = [32]byte{} },
		"no version":     func(decision *kubecluster.TrustDecision) { decision.Version = 0 },
		"no cluster":     func(decision *kubecluster.TrustDecision) { decision.ClusterID = kubecluster.ID{} },
		"no correlation": func(decision *kubecluster.TrustDecision) { decision.CorrelationID = [16]byte{} },
	} {
		bad := decision
		change(&bad)
		if _, err := trusts.Confirm(context.Background(), bad); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: Confirm() error = %v", name, err)
		}
		if _, err := trusts.Choose(context.Background(), bad); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: Choose() error = %v", name, err)
		}
	}
	for _, reason := range []string{"", " padded", "padded ", "line\nbreak", strings.Repeat("x", 257)} {
		bad := reset
		bad.Reason = reason
		if _, err := trusts.Reset(context.Background(), bad); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("reason %q: Reset() error = %v", reason, err)
		}
	}
	if len(store.confirms) != 1 || len(store.chooses) != 1 || len(store.resets) != 1 {
		t.Fatalf("invalid actions reached the store: %d %d %d", len(store.confirms), len(store.chooses),
			len(store.resets))
	}
	ended := decision
	ended.Session = activeSession(t, now.Add(-48*time.Hour))
	if _, err := trusts.Confirm(context.Background(), ended); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("ended session: Confirm() error = %v", err)
	}
	if _, err := kubecluster.NewTrusts(nil, fixedClock(now)); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("NewTrusts(nil) error = %v", err)
	}
}
