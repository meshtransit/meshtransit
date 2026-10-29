package kubecert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"log/slog"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

// recheck bounds every wait: the token file and the map are looked at
// again at least this often.
const recheck = 30 * time.Second

// ErrInvalid reports unsafe options.
var ErrInvalid = errors.New("kubecert: invalid options")

// Options bind a manager to its gateway.
type Options struct {
	// Request sends one request on the map stream's session and returns
	// Core's answer (the stream's KubeCerts channel).
	Request func(ctx context.Context, request controlplane.KubeCertRequest) (controlplane.KubeCertResult, error)
	// Token reads the pod's current ServiceAccount token.
	Token func() (string, error)
	// Now is Core's clock as the gateway estimates it.
	Now    func() time.Time
	Logger *slog.Logger
	// RenewAfter, tests and demos only, renews a certificate this long
	// after its issue when that is sooner than Core asks; zero: never. At
	// least MinimumRenewAfter, so a fleet cannot hit Core's 12 an hour.
	RenewAfter time.Duration
	// StoreDir, when set, keeps the certificate and its key in a file there
	// (an emptyDir in memory), so a restarted container takes it back
	// rather than asking Core (K1b design §3, Q52).
	StoreDir string
}

// MinimumRenewAfter is the shortest Options.RenewAfter: the reissue floor,
// so there is one floor (review a4d L3).
const MinimumRenewAfter = minimumReissue

// Manager keeps the gateway's certificate; it owns one goroutine (Run).
type Manager struct {
	options Options
	maps    chan *networkmap.KubernetesCA

	// Owned by Run.
	pending     *pendingRequest
	mapCA       *networkmap.KubernetesCA
	nextAt      time.Time
	attempts    int // retries of the current request
	failures    int // new keys in a row (verify failed, wrong form)
	unsupported int // answers that Core issues no certificates
	// refusals counts refusals since the last issue: each new request after
	// one waits longer (a4b1 review H-A, H-B). newPending never resets it.
	refusals  int
	waitToken *tokenWait
	// waitMapTill ends a wait for a map whose signing CA is not
	// waitMapSigning (a4b1 review H-A).
	waitMapTill    time.Time
	waitMapSigning []byte
	forceToken     bool
	// mapSeen: a map was applied. Nothing is asked before (§10 L3; a4b2
	// review M2): a replica waiting for approval builds up no backoff.
	mapSeen bool
	early   *earlyPlan
	planned map[[64]byte]earlyPlan // CA pairs an early renewal was planned for, and when
	// restored: the certificate came from the store, not yet checked
	// against a map; renewSoon: it was, of other CAs, and its early renewal
	// comes within recheck, until a certificate is issued (Q71).
	restored, renewSoon bool

	mu       sync.Mutex
	current  *Certificate
	counts   map[outcomeKey]uint64
	mismatch bool
	since    time.Time // when the waiting request was first sent; zero: none
}

type pendingRequest struct {
	id      [16]byte
	key     *ecdsa.PrivateKey
	csr     []byte
	renews  *Certificate // the certificate a renewal proves with; nil: token
	firstAt time.Time
}

// String redacts the request, which holds a private key.
func (pendingRequest) String() string { return "kubecert.pendingRequest([REDACTED])" }

// GoString redacts detailed formatting.
func (pendingRequest) GoString() string { return "kubecert.pendingRequest([REDACTED])" }

// tokenWait waits for a token other than digest (none read: any token).
type tokenWait struct {
	digest [32]byte
	read   bool
	until  time.Time
}

type earlyPlan struct {
	at   time.Time
	root bool
}

type outcomeKey struct{ outcome, reason string }

// New builds a manager without I/O.
func New(options Options) (*Manager, error) {
	if options.Request == nil || options.Token == nil || options.Now == nil || options.Logger == nil ||
		options.RenewAfter != 0 && options.RenewAfter < MinimumRenewAfter {
		return nil, ErrInvalid
	}
	return &Manager{
		options: options, maps: make(chan *networkmap.KubernetesCA, 1), planned: map[[64]byte]earlyPlan{},
		counts: map[outcomeKey]uint64{},
	}, nil
}

// MapChanged hands the manager the latest map's CAs (nil: absent); it never
// blocks, and only the latest counts.
func (manager *Manager) MapChanged(ca *networkmap.KubernetesCA) {
	for {
		select {
		case manager.maps <- ca:
			return
		default:
		}
		select {
		case <-manager.maps:
		default:
		}
	}
}

// Current returns the current certificate, if any still valid now: the
// manager drops an expired one only when it next acts (a4b1 review M3).
func (manager *Manager) Current() (Certificate, bool) {
	now := manager.options.Now()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.current == nil || !manager.current.NotAfter.After(now) {
		return Certificate{}, false
	}
	return *manager.current, true
}

// Run keeps the certificate until ctx ends. The first request waits for the
// first map (the stream sends nothing before it, §10 L3).
func (manager *Manager) Run(ctx context.Context) error {
	manager.restore(ctx)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ca := <-manager.maps:
			manager.mapArrived(ca, manager.options.Now())
		case <-timer.C:
			if now := manager.options.Now(); !now.Before(manager.nextAt) {
				manager.step(ctx, now)
			}
		}
		wait := min(recheck, max(0, manager.nextAt.Sub(manager.options.Now())))
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
	}
}

// mapArrived takes a new map's CAs. The first map starts at once; one that
// ends a wait for another signing CA (no_ca) brings the next request within
// recheck, jittered so a cluster's replicas do not ask together, whatever
// the refusal backoff (docs review a4 M2).
func (manager *Manager) mapArrived(ca *networkmap.KubernetesCA, now time.Time) {
	manager.mapCA = ca
	if manager.restoredMap(ca) {
		manager.renewSoon = true
	}
	if !manager.mapSeen {
		manager.mapSeen, manager.attempts, manager.nextAt = true, 0, time.Time{}
	}
	if !manager.waitMapTill.IsZero() && ca != nil && len(ca.Signing) == 32 &&
		!bytes.Equal(ca.Signing, manager.waitMapSigning) {
		if soon := now.Add(jitter(recheck)); soon.Before(manager.nextAt) {
			manager.nextAt = soon
		}
	}
	manager.planEarly(now)
}

// step acts when due: waits for a token or map out, then asks.
func (manager *Manager) step(ctx context.Context, now time.Time) {
	if !manager.mapSeen || !manager.waitedOut(now) {
		manager.nextAt = now.Add(recheck)
		return
	}
	current, valid := manager.validCurrent(now)
	if valid && manager.pending == nil {
		due := manager.dueAt(current, now)
		if now.Before(due) {
			manager.nextAt = due
			return
		}
	}
	if manager.pending == nil {
		if err := manager.newPending(current, valid, now); err != nil {
			manager.options.Logger.ErrorContext(ctx, "kubernetes gateway certificate key failed",
				"error_code", "kubernetes_certificate_key_failed")
			manager.failures++
			manager.nextAt = now.Add(failureBackoff(manager.failures))
			return
		}
	}
	manager.ask(ctx, now)
}

// waitedOut reports whether a wait for a new token or a map ended.
func (manager *Manager) waitedOut(now time.Time) bool {
	if wait := manager.waitToken; wait != nil && now.Before(wait.until) {
		token, err := manager.options.Token()
		if err != nil || wait.read && sha256.Sum256([]byte(token)) == wait.digest {
			return false
		}
	}
	manager.waitToken = nil
	if !manager.waitMapTill.IsZero() && now.Before(manager.waitMapTill) {
		// Over once the map names a signing CA other than the one it named
		// at the refusal (a4b1 review H-A).
		ca := manager.mapCA
		if ca == nil || len(ca.Signing) != 32 || bytes.Equal(ca.Signing, manager.waitMapSigning) {
			return false
		}
	}
	manager.waitMapTill, manager.waitMapSigning = time.Time{}, nil
	return true
}

func (manager *Manager) validCurrent(now time.Time) (*Certificate, bool) {
	manager.mu.Lock()
	expired := manager.current != nil && !manager.current.NotAfter.After(now)
	if expired {
		// Expired: dropped, with its file; the gateway asks with its token.
		manager.current = nil
	}
	current := manager.current
	manager.mu.Unlock()
	if expired {
		manager.forget()
	}
	return current, current != nil
}

// dueAt is when the current certificate renews: Core's time, or an early
// renewal the map asked for.
func (manager *Manager) dueAt(current *Certificate, now time.Time) time.Time {
	plan := manager.early
	due := renewalTime(*current, plan != nil && plan.root)
	if after := manager.options.RenewAfter; after > 0 && current.IssuedAt.Add(after).Before(due) {
		due = current.IssuedAt.Add(after)
	}
	if plan != nil && plan.at.Before(due) {
		earliest := current.IssuedAt.Add(minimumReissue)
		if plan.root {
			// Never sooner than a minute after the issue (a4b1 review M5).
			earliest = current.IssuedAt.Add(renewFloor)
		}
		if plan.at.Before(earliest) {
			return earliest
		}
		return plan.at
	}
	return due
}

// newPending makes a new request: a renewal while the certificate holds,
// else with the token; always a new key and request ID.
func (manager *Manager) newPending(current *Certificate, valid bool, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	pending := &pendingRequest{key: key, csr: csr, firstAt: now}
	if _, err := rand.Read(pending.id[:]); err != nil {
		return err
	}
	if valid && !manager.forceToken && current.NotAfter.After(now.Add(renewFloor)) {
		renews := *current
		pending.renews = &renews
	}
	manager.pending, manager.attempts = pending, 0
	return nil
}

// request is the protocol request for the waiting one: the token read now,
// or a renewal signed for the session that sends it.
func (manager *Manager) request() (controlplane.KubeCertRequest, error) {
	pending := manager.pending
	request := controlplane.KubeCertRequest{RequestID: pending.id, CSR: pending.csr}
	if renews := pending.renews; renews != nil {
		// The stream signs it for the session that sends it (§6.9).
		request.RenewalSerial, request.RenewalKey = renews.Serial, renews.Key
		return request, nil
	}
	token, err := manager.options.Token()
	if err != nil {
		return controlplane.KubeCertRequest{}, err
	}
	request.Token = token
	return request, nil
}
