package kubecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// fakeCore answers requests with scripted results; an issued answer is
// signed for the request's CSR.
type fakeCore struct {
	t        *testing.T
	ca       testCA
	now      *time.Time
	answers  []func(request controlplane.KubeCertRequest) (controlplane.KubeCertResult, error)
	requests []controlplane.KubeCertRequest
	token    string
	revision uint64
}

func (core *fakeCore) request(_ context.Context, request controlplane.KubeCertRequest) (controlplane.KubeCertResult,
	error,
) {
	core.requests = append(core.requests, request)
	if len(core.answers) == 0 {
		core.t.Fatal("an unexpected request")
	}
	answer := core.answers[0]
	core.answers = core.answers[1:]
	return answer(request)
}

// issue answers with a certificate for the request's key.
func (core *fakeCore) issue(request controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
	csr, err := x509.ParseCertificateRequest(request.CSR)
	if err != nil {
		core.t.Fatal(err)
	}
	public, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		core.t.Fatal("not an ECDSA key")
	}
	return core.ca.issueFor(core.t, public, *core.now, core.revision), nil
}

func refuse(reason string) func(controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
	return func(controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
		return controlplane.KubeCertResult{Outcome: controlplane.KubeCertRefused, Reason: reason}, nil
	}
}

func testManager(t *testing.T, core *fakeCore) *Manager {
	t.Helper()
	manager, err := New(Options{
		Request: core.request, Token: func() (string, error) { return core.token, nil },
		Now: func() time.Time { return *core.now }, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.mapSeen = true // as after the first map
	return manager
}

func newFakeCore(t *testing.T) *fakeCore {
	t.Helper()
	now := testNow
	return &fakeCore{t: t, ca: newTestCA(t), now: &now, token: "pod-token-1", revision: 5}
}

// A pod's first certificate comes with its token; the next renews with the
// current key at Core's renew_at, signed for the session that sends it.
func TestManagerAsksThenRenews(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	core.answers = append(core.answers, core.issue)
	manager := testManager(t, core)
	manager.step(t.Context(), *core.now)
	first, ok := manager.Current()
	if !ok || len(core.requests) != 1 || core.requests[0].Token != "pod-token-1" || core.requests[0].Renewal() ||
		!manager.nextAt.Equal(first.RenewAt) {
		t.Fatalf("current %v, requests %d, next %v", ok, len(core.requests), manager.nextAt)
	}
	*core.now = first.RenewAt
	var signed bool
	core.answers = append(core.answers, func(request controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
		proof, err := sharedmtcp.SignKubeCertRenewal(request.RenewalKey, [32]byte{7}, request.RequestID,
			request.RenewalSerial, request.CSR)
		csr, _ := x509.ParseCertificateRequest(request.CSR)
		spki, _ := x509.MarshalPKIXPublicKey(first.Key.Public())
		signed = err == nil && request.Token == "" && request.RenewalSerial == first.Serial && csr != nil &&
			sharedmtcp.VerifyKubeCertRenewal(spki, [32]byte{7}, request.RequestID, first.Serial, request.CSR, proof)
		return core.issue(request)
	})
	manager.step(t.Context(), *core.now)
	second, _ := manager.Current()
	if !signed || second.Serial == first.Serial || second.Key == first.Key {
		t.Fatalf("renewal signed %v, serials %x %x", signed, first.Serial, second.Serial)
	}
	if snapshot := manager.Snapshot(); !snapshot.HasCertificate || snapshot.Requests[[2]string{"issued", ""}] != 2 {
		t.Fatalf("snapshot %+v", snapshot)
	}
}

// A retry sends the same request again; a refused renewal falls back to the
// token; a used token waits for the kubelet's next one (§10 H2).
func TestManagerFollowsTheReasons(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	manager := testManager(t, core)
	retry := func(controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
		return controlplane.KubeCertResult{
			Outcome: controlplane.KubeCertRetry, Reason: "timeout",
			RetryAfter: 2 * time.Second,
		}, nil
	}
	core.answers = append(core.answers, retry, core.issue)
	manager.step(t.Context(), *core.now)
	if manager.pending == nil || manager.nextAt.Before(core.now.Add(2*time.Second)) {
		t.Fatalf("a retry: pending %v, next %v", manager.pending != nil, manager.nextAt)
	}
	*core.now = manager.nextAt
	manager.step(t.Context(), *core.now)
	if core.requests[0].RequestID != core.requests[1].RequestID {
		t.Fatal("a retry made a new request")
	}
	current, _ := manager.Current()
	// The renewal is refused: the next request carries the token.
	*core.now = current.RenewAt
	core.answers = append(core.answers, refuse("renewal_unknown"))
	manager.step(t.Context(), *core.now)
	*core.now = manager.nextAt
	core.answers = append(core.answers, refuse("token_used"))
	manager.step(t.Context(), *core.now)
	last := core.requests[len(core.requests)-1]
	if last.Renewal() || last.Token != "pod-token-1" || manager.waitToken == nil {
		t.Fatalf("after a refused renewal: %v, waiting for a token %v", last, manager.waitToken != nil)
	}
	// The same token: no request; a new one: a new request.
	*core.now = manager.nextAt
	manager.step(t.Context(), *core.now)
	asked := len(core.requests)
	core.token = "pod-token-2"
	*core.now = manager.nextAt
	core.answers = append(core.answers, core.issue)
	manager.step(t.Context(), *core.now)
	if asked != len(core.requests)-1 || core.requests[len(core.requests)-1].Token != "pod-token-2" {
		t.Fatalf("requests %d after waiting, then %d", asked, len(core.requests))
	}
}

// A certificate that does not check is never taken; the gateway keeps its
// own and asks with a new key after a growing wait (§10 H1).
func TestManagerRefusesABadCertificate(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	manager := testManager(t, core)
	core.answers = append(core.answers, core.issue)
	manager.step(t.Context(), *core.now)
	current, _ := manager.Current()
	*core.now = current.RenewAt
	other := newTestCA(t)
	core.answers = append(core.answers, func(request controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
		result, err := core.issue(request)
		return withIssuer(result, other), err
	})
	manager.step(t.Context(), *core.now)
	kept, _ := manager.Current()
	if kept.Serial != current.Serial || manager.pending != nil || manager.failures != 1 ||
		manager.nextAt.Before(core.now.Add(30*time.Second)) ||
		manager.Snapshot().Requests[[2]string{"verify_failed", ""}] != 1 {
		t.Fatalf("after a bad certificate: failures %d, next %v", manager.failures, manager.nextAt.Sub(*core.now))
	}
}

// A map that names a new signing CA renews early, once, within the hour;
// an older map or one without a signing CA does not (§3.3, R-M6).
func TestManagerRenewsEarlyOnTheMap(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	manager := testManager(t, core)
	core.answers = append(core.answers, core.issue)
	manager.step(t.Context(), *core.now)
	current, _ := manager.Current()
	*core.now = core.now.Add(time.Hour)
	manager.mapCA = &networkmap.KubernetesCA{Root: current.Root[:], Signing: make([]byte, 32), MapRevision: 4}
	manager.planEarly(*core.now)
	if manager.early != nil {
		t.Fatal("an older map planned a renewal")
	}
	manager.mapCA = &networkmap.KubernetesCA{Root: current.Root[:], Signing: make([]byte, 32), MapRevision: 6}
	manager.planEarly(*core.now)
	plan := manager.early
	if plan == nil || plan.root || plan.at.After(core.now.Add(time.Hour)) || !manager.Snapshot().MapMismatch {
		t.Fatalf("early plan %+v", plan)
	}
	// The same pair again plans nothing more; a matching map cancels it.
	manager.early = nil
	manager.planEarly(*core.now)
	if manager.early != nil {
		t.Fatal("the same pair planned twice")
	}
	manager.mapCA = &networkmap.KubernetesCA{Root: current.Root[:], Signing: current.Issuer[:], MapRevision: 7}
	manager.planEarly(*core.now)
	if manager.early != nil || manager.Snapshot().MapMismatch {
		t.Fatal("a matching map left a plan")
	}
}

// No answer: the same request goes again; Core without certificates waits
// longer each time (§10 M4).
func TestManagerWithoutAnAnswer(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	manager := testManager(t, core)
	lost := func(controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
		return controlplane.KubeCertResult{}, controlplane.ErrKubeCertSessionLost
	}
	unsupported := func(controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
		return controlplane.KubeCertResult{}, controlplane.ErrKubeCertUnsupported
	}
	core.answers = append(core.answers, lost, unsupported, unsupported)
	manager.step(t.Context(), *core.now)
	*core.now = manager.nextAt
	manager.step(t.Context(), *core.now)
	firstWait := manager.nextAt.Sub(*core.now)
	*core.now = manager.nextAt
	manager.step(t.Context(), *core.now)
	if core.requests[0].RequestID != core.requests[2].RequestID || firstWait < 30*time.Second ||
		manager.nextAt.Sub(*core.now) < firstWait/2 {
		t.Fatalf("waits %v then %v", firstWait, manager.nextAt.Sub(*core.now))
	}
	if !errors.Is(controlplane.ErrKubeCertUnsupported, controlplane.ErrKubeCertUnsupported) {
		t.Fatal("unreachable")
	}
}

// issueFor signs a replica certificate for a public key.
func (ca testCA) issueFor(t *testing.T, public *ecdsa.PublicKey, now time.Time, revision uint64) controlplane.KubeCertResult {
	t.Helper()
	return ca.issue(t, &ecdsa.PrivateKey{PublicKey: *public}, now, true, revision)
}

// Refusals that make a new request wait longer each time until a
// certificate is issued; a map wait lasts until the map names another
// signing CA (a4b1 review H-A, H-B); a stop waits minutes.
func TestManagerBacksOffRefusals(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	manager := testManager(t, core)
	var waits []time.Duration
	for range 4 {
		core.answers = append(core.answers, refuse("attempts"))
		manager.step(t.Context(), *core.now)
		waits = append(waits, manager.nextAt.Sub(*core.now))
		*core.now = manager.nextAt
	}
	if waits[0] < 30*time.Second || waits[3] < 4*time.Minute || manager.refusals != 4 {
		t.Fatalf("waits %v, refusals %d", waits, manager.refusals)
	}
	// no_ca while the map names the old signing CA: no request until the
	// map names another.
	old := &networkmap.KubernetesCA{Root: make([]byte, 32), Signing: make([]byte, 32), MapRevision: 9}
	manager.mapCA = old
	core.answers = append(core.answers, refuse("no_ca"))
	manager.step(t.Context(), *core.now)
	asked := len(core.requests)
	for range 3 {
		*core.now = core.now.Add(time.Minute)
		manager.step(t.Context(), *core.now)
	}
	if len(core.requests) != asked || manager.waitMapTill.IsZero() {
		t.Fatalf("asked %d → %d while the map named the old CA", asked, len(core.requests))
	}
	manager.mapCA = &networkmap.KubernetesCA{
		Root: core.ca.rootPrint[:], Signing: core.ca.intermediatePrint[:],
		MapRevision: 10,
	}
	core.answers = append(core.answers, core.issue)
	*core.now = core.now.Add(time.Minute)
	manager.step(t.Context(), *core.now)
	if len(core.requests) != asked+1 {
		t.Fatalf("no request once the map named a new CA (%d)", len(core.requests))
	}
	if _, ok := manager.Current(); !ok || manager.refusals != 0 || manager.pending != nil {
		t.Fatalf("after the issue: refusals %d, pending %v", manager.refusals, manager.pending != nil)
	}
	// A stop waits minutes, whatever the refusal count.
	stopped := testManager(t, core)
	core.answers = append(core.answers, refuse("revoked"))
	stopped.step(t.Context(), *core.now)
	if wait := stopped.nextAt.Sub(*core.now); wait < 5*time.Minute {
		t.Fatalf("a stop waits %v", wait)
	}
}

// Current never returns an expired certificate; Run takes maps and stops
// with its context (a4b1 review M3, M8).
func TestManagerRunAndCurrent(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	manager := testManager(t, core)
	core.answers = append(core.answers, core.issue)
	manager.step(t.Context(), *core.now)
	current, ok := manager.Current()
	if !ok {
		t.Fatal("no certificate")
	}
	*core.now = current.NotAfter
	if _, ok := manager.Current(); ok {
		t.Fatal("an expired certificate was returned")
	}
	*core.now = testNow
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	manager.MapChanged(&networkmap.KubernetesCA{Root: current.Root[:], Signing: current.Issuer[:], MapRevision: 9})
	manager.MapChanged(nil)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v", err)
	}
}

// Nothing is asked before the first map; the first map starts at once,
// whatever happened before (a4b2 review M2).
func TestManagerWaitsForTheFirstMap(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	manager := testManager(t, core)
	manager.mapSeen, manager.attempts = false, 5
	manager.step(t.Context(), *core.now)
	if len(core.requests) != 0 || !manager.nextAt.Equal(core.now.Add(recheck)) {
		t.Fatalf("asked %d before a map, next at %v", len(core.requests), manager.nextAt)
	}
	core.answers = append(core.answers, core.issue)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	manager.MapChanged(nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := manager.Current(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no request after the first map")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// RenewAfter, for demos, renews sooner than Core asks, never under 15
// minutes (a4 design §10 L4).
func TestManagerRenewAfter(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	options := Options{
		Request: core.request, Token: func() (string, error) { return core.token, nil },
		Now: func() time.Time { return *core.now }, Logger: slog.New(slog.DiscardHandler), RenewAfter: 14 * time.Minute,
	}
	if _, err := New(options); !errors.Is(err, ErrInvalid) {
		t.Fatalf("New() with RenewAfter 14m = %v", err)
	}
	options.RenewAfter = 15 * time.Minute
	manager, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	manager.mapSeen = true
	core.answers = append(core.answers, core.issue)
	manager.step(t.Context(), *core.now)
	if want := core.now.Add(15 * time.Minute); !manager.nextAt.Equal(want) {
		t.Fatalf("renews at %v, want %v", manager.nextAt, want)
	}
}
