package relayauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// Publishing schedule (mtrp-v1 §9).
const (
	RefreshInterval = 10 * time.Second
	StateLifetime   = 10 * time.Minute
	// keyTrustWindow is the not_after given to published signing keys. It is
	// renewed every refresh, so a key stays trusted while Core runs and lapses
	// a week after Core stops listing it.
	keyTrustWindow = 7 * 24 * time.Hour
)

// RevocationSource lists the revocation entries relays must enforce now.
type RevocationSource interface {
	RelayRevocations(ctx context.Context, now time.Time) (tickets, nodes, discos []mtrp.RevocationID, err error)
}

// Options configures a Publisher.
type Options struct {
	Signer      key.SigningPrivate
	Next        *key.SigningPrivate // published ahead of a rotation; never signs
	Map         *mtrp.RelayMap      // nil: no relay map is served
	Drain       []key.RelayPublic
	Revocations RevocationSource // nil: no revocations yet
	Now         func() time.Time
	Logger      *slog.Logger
	Metrics     *Metrics
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

	sequence int64 // owned by the refresh goroutine (and Start before it)

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
	return &Publisher{opts: opts}, nil
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
	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// A failed refresh keeps the previous documents, which stay
			// valid for StateLifetime; it is retried on the next tick.
			if err := p.refresh(ctx); err != nil && ctx.Err() == nil {
				p.opts.Logger.Warn("relay authority refresh failed", "error", err)
			}
		}
	}
}

// refresh signs a new relay state and, when configured, relay map.
func (p *Publisher) refresh(ctx context.Context) error {
	now := p.opts.Now()
	state := mtrp.RelayState{
		Sequence:  max(now.UnixMilli(), p.sequence+1),
		IssuedAt:  now,
		ExpiresAt: now.Add(StateLifetime),
		Drain:     p.opts.Drain,
		SigningKeys: []mtrp.TrustedKey{
			{Key: p.opts.Signer.Public(), NotAfter: now.Add(keyTrustWindow)},
		},
	}
	if p.opts.Next != nil {
		state.SigningKeys = append(state.SigningKeys, mtrp.TrustedKey{Key: p.opts.Next.Public(), NotAfter: now.Add(keyTrustWindow)})
	}
	if p.opts.Revocations != nil {
		var err error
		state.Tickets, state.Nodes, state.Discos, err = p.opts.Revocations.RelayRevocations(ctx, now)
		if err != nil {
			p.opts.Metrics.refreshes.WithLabelValues("revocations_failed").Inc()
			return err
		}
	}
	stateDoc, err := p.sign(mtrp.DocumentRelayState, state.Payload)
	if err != nil {
		p.opts.Metrics.refreshes.WithLabelValues("sign_failed").Inc()
		return err
	}
	var mapDoc *document
	if p.opts.Map != nil {
		m := *p.opts.Map
		m.ExpiresAt = now.Add(MapLifetime)
		mapDoc, err = p.sign(mtrp.DocumentRelayMap, func() ([]byte, error) { return m.Payload(now) })
		if err != nil {
			p.opts.Metrics.refreshes.WithLabelValues("sign_failed").Inc()
			return err
		}
	}
	p.sequence = state.Sequence
	p.state.Store(stateDoc)
	if mapDoc != nil {
		p.relayMap.Store(mapDoc)
	}
	p.opts.Metrics.refreshes.WithLabelValues("ok").Inc()
	p.opts.Metrics.revocations.Set(float64(len(state.Tickets) + len(state.Nodes) + len(state.Discos)))
	p.opts.Metrics.lastSuccess.Set(float64(now.Unix()))
	return nil
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

// Metrics returns the publisher's and its handler's collectors.
func (p *Publisher) Metrics() *Metrics { return p.opts.Metrics }
