package kubecluster_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
)

type recordingInstallTokens struct {
	changes []kubecluster.TrustModeChange
	issues  []kubecluster.InstallTokenIssue
}

func (store *recordingInstallTokens) SetTrustMode(_ context.Context,
	change kubecluster.TrustModeChange) (kubecluster.TrustModeResult, error) {
	store.changes = append(store.changes, change)
	return kubecluster.TrustModeResult{Mode: change.Mode, Changed: true}, nil
}

func (store *recordingInstallTokens) IssueInstallToken(_ context.Context,
	issue kubecluster.InstallTokenIssue) (kubecluster.JoinKey, error) {
	store.issues = append(store.issues, issue)
	return kubecluster.JoinKey{}, nil
}

func TestInstallTokensIssue(t *testing.T) {
	t.Parallel()
	_, _, session, scope, now := serviceFixture(t)
	store := &recordingInstallTokens{}
	tokens, err := kubecluster.NewInstallTokens(store, fixedClock(now), &sequentialSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	cluster := kubecluster.ID(mustID(t, "000000000301"))
	issued, err := tokens.Issue(context.Background(), kubecluster.InstallTokenRequest{
		Session: session, Scope: scope, ClusterID: cluster, Replicas: 3, CorrelationID: mustID(t, "000000000901"),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if len(store.issues) != 1 || store.issues[0].Lifetime != time.Hour || store.issues[0].Replicas != 3 ||
		!store.issues[0].PreapprovalID.IsValid() || issued.Replicas != 3 ||
		!strings.HasPrefix(issued.Presentation.Reveal(), "mtk1.") || issued.Presentation.Token() != store.issues[0].Token {
		t.Fatalf("issued %+v after %d store calls", issued, len(store.issues))
	}
	// A day is the longest an install token lives.
	if _, err := tokens.Issue(context.Background(), kubecluster.InstallTokenRequest{
		Session: session, Scope: scope, ClusterID: cluster, Lifetime: 24 * time.Hour, Replicas: 5,
		CorrelationID: mustID(t, "000000000902"),
	}); err != nil {
		t.Fatalf("a day, five replicas: Issue() error = %v", err)
	}
	for name, request := range map[string]kubecluster.InstallTokenRequest{
		"over a day":      {Session: session, Scope: scope, ClusterID: cluster, Lifetime: 25 * time.Hour, Replicas: 1, CorrelationID: mustID(t, "000000000903")},
		"under 5 minutes": {Session: session, Scope: scope, ClusterID: cluster, Lifetime: time.Minute, Replicas: 1, CorrelationID: mustID(t, "000000000904")},
		"part second":     {Session: session, Scope: scope, ClusterID: cluster, Lifetime: time.Hour + time.Millisecond, Replicas: 1, CorrelationID: mustID(t, "000000000905")},
		"no replica":      {Session: session, Scope: scope, ClusterID: cluster, CorrelationID: mustID(t, "000000000906")},
		"six replicas":    {Session: session, Scope: scope, ClusterID: cluster, Replicas: 6, CorrelationID: mustID(t, "000000000907")},
		"no cluster":      {Session: session, Scope: scope, Replicas: 1, CorrelationID: mustID(t, "000000000908")},
		"no correlation":  {Session: session, Scope: scope, ClusterID: cluster, Replicas: 1},
		"no scope":        {Session: session, ClusterID: cluster, Replicas: 1, CorrelationID: mustID(t, "000000000909")},
	} {
		if _, err := tokens.Issue(context.Background(), request); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: Issue() error = %v, want ErrInvalid", name, err)
		}
	}
	if len(store.issues) != 2 {
		t.Fatalf("invalid requests reached the store: %d calls", len(store.issues))
	}
	// A session ended on this host's clock is refused before the store.
	if _, err := tokens.Issue(context.Background(), kubecluster.InstallTokenRequest{
		Session: activeSession(t, now.Add(-48*time.Hour)), Scope: scope, ClusterID: cluster, Replicas: 1,
		CorrelationID: mustID(t, "000000000910"),
	}); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("ended session: Issue() error = %v, want ErrForbidden", err)
	}
}

func TestInstallTokensSetTrustMode(t *testing.T) {
	t.Parallel()
	_, _, session, scope, now := serviceFixture(t)
	store := &recordingInstallTokens{}
	tokens, err := kubecluster.NewInstallTokens(store, fixedClock(now), &sequentialSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	cluster := kubecluster.ID(mustID(t, "000000000301"))
	result, err := tokens.SetTrustMode(context.Background(), kubecluster.TrustModeChange{
		Session: session, Scope: scope, ClusterID: cluster, Mode: kubecluster.TrustModePrivateTOFU, Version: 3,
		CorrelationID: mustID(t, "000000000911"),
	})
	if err != nil || !result.Changed || len(store.changes) != 1 || store.changes[0].Version != 3 {
		t.Fatalf("SetTrustMode() = %+v, %v after %d calls", result, err, len(store.changes))
	}
	for name, change := range map[string]kubecluster.TrustModeChange{
		"issuer later": {Session: session, Scope: scope, ClusterID: cluster, Mode: "issuer", Version: 3, CorrelationID: mustID(t, "000000000912")},
		"no version":   {Session: session, Scope: scope, ClusterID: cluster, Mode: kubecluster.TrustModeCode, CorrelationID: mustID(t, "000000000913")},
		"no cluster":   {Session: session, Scope: scope, Mode: kubecluster.TrustModeCode, Version: 3, CorrelationID: mustID(t, "000000000914")},
	} {
		if _, err := tokens.SetTrustMode(context.Background(), change); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: SetTrustMode() error = %v, want ErrInvalid", name, err)
		}
	}
	if len(store.changes) != 1 {
		t.Fatalf("invalid changes reached the store: %d calls", len(store.changes))
	}
	if _, err := kubecluster.NewInstallTokens(nil, fixedClock(now), &sequentialSecrets{}); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("NewInstallTokens(nil store) error = %v", err)
	}
}
