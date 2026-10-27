package meshgw

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
)

// fakeJoiner plays the gateway daemon: JoinCluster answers from answers in
// turn; PrepareGatewayKeys fails with prepareErrs in turn.
type fakeJoiner struct {
	fakeController
	answers     []joinAnswer
	joins       []string // join keys used
	reported    map[string]string
	prepareErrs []error
	prepared    int
	pods        []daemon.PodIdentity // pod identities sent
}

type joinAnswer struct {
	result daemon.ClusterJoin
	err    error
}

func (f *fakeJoiner) JoinCluster(_ context.Context, joinKey string, reported map[string]string, _ time.Duration,
	pod daemon.PodIdentity,
) (daemon.ClusterJoin, error) {
	f.joins = append(f.joins, joinKey)
	f.pods = append(f.pods, pod)
	f.reported = reported
	if len(f.answers) == 0 {
		return daemon.ClusterJoin{}, errors.New("unexpected join")
	}
	answer := f.answers[0]
	f.answers = f.answers[1:]
	if answer.err == nil && answer.result.State == daemon.ClusterJoinJoined {
		f.registration = string(daemon.RegistrationRegistered)
	}
	return answer.result, answer.err
}

func (f *fakeJoiner) PrepareGatewayKeys(context.Context) error {
	f.prepared++
	if len(f.prepareErrs) == 0 {
		return nil
	}
	err := f.prepareErrs[0]
	f.prepareErrs = f.prepareErrs[1:]
	return err
}

func joinConfig(t *testing.T) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key-0")
	if err := os.WriteFile(path, []byte("mtk1.secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		ControlURL: "https://control.example.com", ControlFingerprint: "sha256:" + strings.Repeat("a", 64),
		Hostname: "meshgw-prod-0", JoinKeyFile: path, PodName: "meshgw-0", Namespace: "mt-kube",
	}
}

func waitingFor(code string) joinAnswer {
	return joinAnswer{result: daemon.ClusterJoin{
		State: daemon.ClusterJoinWaiting, Code: code, RequestID: "request-1",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}}
}

// The replica prints its code while it waits, and goes on once joined; the
// join key never reaches the log.
func TestJoinPrintsTheCodeUntilJoined(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	service := &fakeJoiner{answers: []joinAnswer{
		waitingFor("ABCDE-FGHIJ"), waitingFor("ABCDE-FGHIJ"),
		{result: daemon.ClusterJoin{State: daemon.ClusterJoinJoined}},
	}}
	if err := joinUntilDone(t.Context(), service, joinConfig(t), testPod, time.Millisecond, logger); err != nil {
		t.Fatalf("joinUntilDone() = %v", err)
	}
	if len(service.joins) != 3 || service.joins[0] != "mtk1.secret" {
		t.Fatalf("joins %v", service.joins)
	}
	if service.reported["pod"] != "meshgw-0" || service.reported["namespace"] != "mt-kube" {
		t.Fatalf("reported %v", service.reported)
	}
	if strings.Count(logs.String(), "enroll code: ABCDE-FGHIJ") != 2 || strings.Contains(logs.String(), "mtk1") {
		t.Fatalf("log:\n%s", logs.String())
	}
}

func TestJoinStopsOnRefusals(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		answers []joinAnswer
		want    string
	}{
		{
			name: "wrong key", answers: []joinAnswer{{err: &controlplane.RejectedError{Code: "credential_invalid"}}},
			want: "join key",
		},
		{
			name: "used up", answers: []joinAnswer{{err: &controlplane.RejectedError{Code: "credential_exhausted"}}},
			want: "join key",
		},
		{
			name: "rejected", answers: []joinAnswer{{err: &controlplane.RejectedError{Code: "not_permitted"}}},
			want: "state Secret",
		},
		{name: "expired twice", answers: []joinAnswer{
			{err: &controlplane.RejectedError{Code: "expired"}},
			{err: &controlplane.RejectedError{Code: "expired"}},
		}, want: "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &fakeJoiner{answers: test.answers}
			err := joinUntilDone(t.Context(), service, joinConfig(t), testPod, time.Millisecond, slog.New(slog.DiscardHandler))
			if err == nil || !strings.Contains(err.Error(), test.want) || !permanent(err) {
				t.Fatalf("joinUntilDone() = %v", err)
			}
		})
	}
}

// Core failing to answer is retried; a joined replica needs no join key.
func TestJoinRetriesTemporaryFailures(t *testing.T) {
	t.Parallel()
	service := &fakeJoiner{answers: []joinAnswer{
		{err: controlplane.ErrRegistrationTemporary},
		{err: controlplane.ErrGatewayContested},
		{result: daemon.ClusterJoin{State: daemon.ClusterJoinJoined}},
	}}
	if err := joinUntilDone(t.Context(), service, joinConfig(t), testPod, time.Millisecond,
		slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("joinUntilDone() = %v", err)
	}
	joined := &fakeJoiner{}
	joined.registration = string(daemon.RegistrationRegistered)
	joined.pinned = true
	cfg := joinConfig(t)
	cfg.JoinKeyFile = "/nonexistent/key-0"
	if err := joinUntilDone(t.Context(), joined, cfg, testPod, time.Millisecond, slog.New(slog.DiscardHandler)); err != nil ||
		len(joined.joins) != 0 {
		t.Fatalf("a joined replica: %v, joins %v", err, joined.joins)
	}
}

func TestPrepareKeysUntilDone(t *testing.T) {
	t.Parallel()
	service := &fakeJoiner{prepareErrs: []error{controlplane.ErrGatewayContested, controlplane.ErrRegistrationTemporary}}
	if err := prepareKeysUntilDone(t.Context(), service, time.Millisecond, slog.New(slog.DiscardHandler)); err != nil ||
		service.prepared != 3 {
		t.Fatalf("prepareKeysUntilDone() = %v after %d", err, service.prepared)
	}
	lost := &fakeJoiner{prepareErrs: []error{daemon.ErrGatewayKeysLost}}
	if err := prepareKeysUntilDone(t.Context(), lost, time.Millisecond,
		slog.New(slog.DiscardHandler)); !errors.Is(err, daemon.ErrGatewayKeysLost) || !permanent(err) {
		t.Fatalf("lost keys: %v", err)
	}
}

// testPod is the pod identity the join tests read.
func testPod(context.Context, Config) (daemon.PodIdentity, error) {
	return daemon.PodIdentity{
		Token: "pod-token-secret", Issuer: "https://kubernetes.default.svc.cluster.local",
		JWKS: []byte(`{"keys":[]}`),
	}, nil
}

// Each join carries the pod's identity, read for it; the token never
// reaches the log (K1.1).
func TestJoinSendsThePodIdentity(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	service := &fakeJoiner{answers: []joinAnswer{
		waitingFor("ABCDE-FGHIJ"),
		{result: daemon.ClusterJoin{State: daemon.ClusterJoinJoined}},
	}}
	if err := joinUntilDone(t.Context(), service, joinConfig(t), testPod, time.Millisecond,
		slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("joinUntilDone() = %v", err)
	}
	if len(service.pods) != 2 || service.pods[0].Token != "pod-token-secret" || len(service.pods[1].JWKS) == 0 {
		t.Fatalf("pods %v", service.pods)
	}
	if strings.Contains(logs.String(), "pod-token-secret") {
		t.Fatalf("the token reached the log:\n%s", logs.String())
	}
}

// A pod identity that cannot be read is retried, saying why.
func TestJoinRetriesAnUnreadablePodIdentity(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	failed := false
	source := func(ctx context.Context, cfg Config) (daemon.PodIdentity, error) {
		if !failed {
			failed = true
			return daemon.PodIdentity{}, errors.New("reading the pod token: no such file")
		}
		return testPod(ctx, cfg)
	}
	service := &fakeJoiner{answers: []joinAnswer{{result: daemon.ClusterJoin{State: daemon.ClusterJoinJoined}}}}
	if err := joinUntilDone(t.Context(), service, joinConfig(t), source, time.Millisecond,
		slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("joinUntilDone() = %v", err)
	}
	if !strings.Contains(logs.String(), "pod token") || len(service.joins) != 1 {
		t.Fatalf("joins %v, log:\n%s", service.joins, logs.String())
	}
}

// Keys that hold a request with other signing material: the replica prints
// its own code and the request to reject, and asks again (design §6.3).
func TestJoinConflictPrintsTheCodeAndAsksAgain(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	service := &fakeJoiner{answers: []joinAnswer{
		{result: daemon.ClusterJoin{State: daemon.ClusterJoinConflict, Code: "KLMNO-PQRST", RequestID: "request-9"}},
		{result: daemon.ClusterJoin{State: daemon.ClusterJoinJoined}},
	}}
	if err := joinUntilDone(t.Context(), service, joinConfig(t), testPod, time.Millisecond,
		slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("joinUntilDone() = %v", err)
	}
	if !strings.Contains(logs.String(), "KLMNO-PQRST") || !strings.Contains(logs.String(), "request-9") ||
		len(service.joins) != 2 {
		t.Fatalf("joins %v, log:\n%s", service.joins, logs.String())
	}
}

// Core's invalid refusals say what to fix; the state Secret is no answer.
func TestJoinRefusalForInvalidNamesNoSecret(t *testing.T) {
	t.Parallel()
	err := joinRefusal(&controlplane.RejectedError{
		Code:    "invalid",
		Message: "a Kubernetes gateway joins with its pod's ServiceAccount token: upgrade meshgw",
	})
	if !errors.Is(err, ErrJoinRefused) || strings.Contains(err.Error(), "Secret") ||
		!strings.Contains(err.Error(), "upgrade meshgw") {
		t.Fatalf("joinRefusal() = %v", err)
	}
}
