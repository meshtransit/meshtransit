package relayauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// Publishing schedule (mtrp-v1 §9). Core signs once per RefreshInterval
// window aligned to Unix time and derives every timestamp from the window
// start, so replicas publish byte-identical documents (Ed25519 signatures
// are deterministic) and a relay polling through a load balancer sees one
// ETag.
const (
	RefreshInterval = 10 * time.Second
	StateLifetime   = 10 * time.Minute
	// windowSlack delays each refresh past the window boundary so a timer
	// that fires marginally early still lands in the new window.
	windowSlack = 50 * time.Millisecond
	// keyTrustWindow is the not_after given to published signing keys. It is
	// renewed every refresh, so a key stays trusted while Core runs and lapses
	// a week after Core stops listing it.
	keyTrustWindow = 7 * 24 * time.Hour
	// RevocationCheckInterval is how often Core looks for new revocations
	// between windows. A change is signed at once, so relays holding a long
	// poll stop honouring a revoked node within seconds (production
	// criterion: 5 s p99). Replicas may sign such a state a second apart;
	// relays keep the highest sequence.
	RevocationCheckInterval = time.Second
)

// RevocationWindow is how far back revocations are published: the longest
// ticket lifetime plus the skew relays tolerate. Anything that ended earlier
// can no longer appear in a valid ticket.
const RevocationWindow = mtrp.MaxTicketLifetime + mtrp.MaxIssueSkew

// Revoked lists what relays must stop honouring: node keys, and Trust
// Contracts whose zones are withdrawn.
type Revoked struct {
	NodeKeys       [][32]byte
	TrustContracts [][16]byte
}

// RevocationSource lists what ended at or after since.
type RevocationSource interface {
	RelayRevocations(ctx context.Context, since time.Time) (Revoked, error)
}

// Options configures a Publisher.
type Options struct {
	Signer      key.SigningPrivate
	Next        *key.SigningPrivate // published ahead of a rotation; never signs
	Map         *mtrp.RelayMap      // nil: no relay map is served
	Drain       []key.RelayPublic
	Revocations RevocationSource // nil: no revocations yet
	// Private reads the Private Interchange relays; nil: none.
	Private PrivateInterchangeSource
	Now     func() time.Time
	Logger  *slog.Logger
	Metrics *Metrics
}

// document is one signed artefact with its HTTP validator.
type document struct {
	body []byte
	etag string
}

// Publisher keeps a signed relay state and relay map fresh. It implements
// the process service contract (Start, Shutdown, Done).
type Publisher struct {
	opts     Options
	state    atomic.Pointer[document]
	relayMap atomic.Pointer[document]

	// window is the last signed window. Only the refresh goroutine (and
	// Start before it) writes it, under cacheMu, because request goroutines
	// read it under cacheMu to sign Network maps and grants.
	window time.Time
	// stateIssued and revocationKey describe the current state: when it was
	// issued (a window start, or a revocation check) and what it revokes.
	// Owned by the refresh goroutine.
	stateIssued   time.Time
	revocationKey string

	// changed is closed and replaced whenever a new state is stored, waking
	// relays that hold a long poll.
	notifyMu sync.Mutex
	changed  chan struct{}

	private atomic.Pointer[interchange.Directory]
	// Per-window caches of Network maps (by content key) and relay grants.
	cacheMu     sync.Mutex
	cacheWindow time.Time
	maps        map[string]*document
	grants      map[key.RelayPublic]*document

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan error
}

// NewPublisher validates its options.
func NewPublisher(opts Options) (*Publisher, error) {
	if opts.Signer.IsZero() {
		return nil, errors.New("relayauthority: signing key is required")
	}
	if opts.Next != nil && opts.Next.Public() == opts.Signer.Public() {
		return nil, errors.New("relayauthority: next signing key equals the current one")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Metrics == nil {
		opts.Metrics = NewMetrics()
	}
	return &Publisher{opts: opts, changed: make(chan struct{})}, nil
}

// Start signs the first documents (failing if it cannot) and starts the
// refresh loop.
func (p *Publisher) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done != nil {
		return errors.New("relayauthority: publisher already started")
	}
	if err := p.refresh(ctx); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p.cancel = cancel
	p.done = make(chan error, 1)
	go p.run(runCtx, p.done)
	return nil
}

// Shutdown stops the refresh loop and waits for it.
func (p *Publisher) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done reports when the refresh loop has ended.
func (p *Publisher) Done() <-chan error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

func (p *Publisher) run(ctx context.Context, done chan<- error) {
	defer close(done)
	t := time.NewTimer(untilNextWindow(time.Now()))
	defer t.Stop()
	var checks <-chan time.Time
	if p.opts.Revocations != nil {
		ticker := time.NewTicker(RevocationCheckInterval)
		defer ticker.Stop()
		checks = ticker.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(untilNextWindow(time.Now()))
			// A failed refresh keeps the previous documents, which stay
			// valid for StateLifetime; it is retried on the next tick.
			if err := p.refresh(ctx); err != nil && ctx.Err() == nil {
				p.opts.Logger.Warn("relay authority refresh failed", "error", err)
			}
		case <-checks:
			if err := p.checkRevocations(ctx); err != nil && ctx.Err() == nil {
				p.opts.Logger.Warn("relay revocation check failed", "error", err)
			}
		}
	}
}

// untilNextWindow is the delay to just after the next window boundary.
func untilNextWindow(now time.Time) time.Duration {
	return RefreshInterval - time.Duration(now.UnixNano()%int64(RefreshInterval)) + windowSlack
}

// windowStart truncates t to its RefreshInterval window.
func windowStart(t time.Time) time.Time {
	ms := RefreshInterval.Milliseconds()
	return time.UnixMilli(t.UnixMilli() / ms * ms)
}

// refresh signs a new relay state and, when configured, relay map, once per
// window. A window that is not after the last signed one (a repeated tick or
// a clock step back) keeps the current documents, so the sequence, which is
// the window start in milliseconds, strictly increases.
func (p *Publisher) refresh(ctx context.Context) error {
	now := windowStart(p.opts.Now())
	if p.state.Load() != nil && !now.After(p.window) {
		return nil
	}
	state, revocationKey, err := p.buildState(ctx, now, now)
	if err != nil {
		return err
	}
	p.refreshPrivate(ctx)
	stateDoc, err := p.sign(mtrp.DocumentRelayState, state.Payload)
	if err != nil {
		p.opts.Metrics.refreshes.WithLabelValues("sign_failed").Inc()
		return err
	}
	var mapDoc *document
	if p.opts.Map != nil {
		// The map of a Network without a Private Interchange.
		m := NetworkMap(*p.opts.Map, nil, p.privateDirectory().Revision)
		m.ExpiresAt = now.Add(MapLifetime)
		mapDoc, err = p.sign(mtrp.DocumentRelayMap, func() ([]byte, error) { return m.Payload(now) })
		if err != nil {
			p.opts.Metrics.refreshes.WithLabelValues("sign_failed").Inc()
			return err
		}
	}
	p.cacheMu.Lock()
	p.window = now
	p.cacheMu.Unlock()
	p.storeState(stateDoc, now, revocationKey)
	if mapDoc != nil {
		p.relayMap.Store(mapDoc)
	}
	p.opts.Metrics.refreshes.WithLabelValues("ok").Inc()
	p.opts.Metrics.revocations.Set(float64(len(state.Tickets) + len(state.Nodes) + len(state.Discos) + len(state.Zones)))
	p.opts.Metrics.lastSuccess.Set(float64(now.Unix()))
	return nil
}

// buildState assembles the relay state issued at issued, revoking what ended
// since window minus RevocationWindow. It returns a key of the revocations
// for change detection.
func (p *Publisher) buildState(ctx context.Context, issued, window time.Time) (mtrp.RelayState, string, error) {
	state := mtrp.RelayState{
		Sequence:    issued.UnixMilli(),
		IssuedAt:    issued,
		ExpiresAt:   issued.Add(StateLifetime),
		Drain:       p.opts.Drain,
		SigningKeys: p.trustedKeys(window),
	}
	if p.opts.Revocations != nil {
		revoked, err := p.opts.Revocations.RelayRevocations(ctx, window.Add(-RevocationWindow))
		if err != nil {
			p.opts.Metrics.refreshes.WithLabelValues("revocations_failed").Inc()
			return mtrp.RelayState{}, "", err
		}
		state.Nodes = make([]mtrp.RevocationID, len(revoked.NodeKeys))
		for i, node := range revoked.NodeKeys {
			state.Nodes[i] = mtrp.RevocationHash(mtrp.RevokeNode, node[:])
		}
		for _, contract := range revoked.TrustContracts {
			state.Zones = append(state.Zones, mtrp.ZoneRevocationHash(mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: contract}))
		}
	}
	return state, revocationKeyOf(state), nil
}

// revocationKeyOf identifies the set of revocations a state carries.
func revocationKeyOf(state mtrp.RelayState) string {
	ids := make([]string, 0, len(state.Nodes)+len(state.Zones))
	for _, id := range state.Nodes {
		ids = append(ids, "n"+hex.EncodeToString(id[:]))
	}
	for _, id := range state.Zones {
		ids = append(ids, "z"+hex.EncodeToString(id[:]))
	}
	slices.Sort(ids)
	return strings.Join(ids, ",")
}

// checkRevocations signs a new state at once when the revocations changed
// since the current state, without waiting for the next window. Only the
// state is re-signed; relay maps and grants keep their window.
func (p *Publisher) checkRevocations(ctx context.Context) error {
	if p.opts.Revocations == nil || p.state.Load() == nil {
		return nil
	}
	issued := p.opts.Now().Truncate(RevocationCheckInterval)
	if !issued.After(p.stateIssued) {
		return nil
	}
	state, revocationKey, err := p.buildState(ctx, issued, p.window)
	if err != nil || revocationKey == p.revocationKey {
		return err
	}
	stateDoc, err := p.sign(mtrp.DocumentRelayState, state.Payload)
	if err != nil {
		p.opts.Metrics.refreshes.WithLabelValues("sign_failed").Inc()
		return err
	}
	p.storeState(stateDoc, issued, revocationKey)
	p.opts.Metrics.refreshes.WithLabelValues("revocation").Inc()
	p.opts.Metrics.revocations.Set(float64(len(state.Tickets) + len(state.Nodes) + len(state.Discos) + len(state.Zones)))
	return nil
}

// storeState makes doc the current state and wakes waiting relays.
func (p *Publisher) storeState(doc *document, issued time.Time, revocationKey string) {
	p.stateIssued, p.revocationKey = issued, revocationKey
	p.state.Store(doc)
	p.notifyMu.Lock()
	close(p.changed)
	p.changed = make(chan struct{})
	p.notifyMu.Unlock()
}

// stateChanged returns a channel closed when the next state is stored.
func (p *Publisher) stateChanged() <-chan struct{} {
	p.notifyMu.Lock()
	defer p.notifyMu.Unlock()
	return p.changed
}

func (p *Publisher) sign(kind mtrp.DocumentKind, payload func() ([]byte, error)) (*document, error) {
	body, err := payload()
	if err != nil {
		return nil, err
	}
	signed, err := mtrp.SignDocument(kind, body, p.opts.Signer)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(signed)
	return &document{body: signed, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}, nil
}

// trustedKeys lists the current and next signing keys, trusted for
// keyTrustWindow from now.
func (p *Publisher) trustedKeys(now time.Time) []mtrp.TrustedKey {
	keys := []mtrp.TrustedKey{{Key: p.opts.Signer.Public(), NotAfter: now.Add(keyTrustWindow)}}
	if p.opts.Next != nil {
		keys = append(keys, mtrp.TrustedKey{Key: p.opts.Next.Public(), NotAfter: now.Add(keyTrustWindow)})
	}
	return keys
}

// Metrics returns the publisher's and its handler's collectors.
func (p *Publisher) Metrics() *Metrics { return p.opts.Metrics }
