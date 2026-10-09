// Package corelink keeps a relay's trust state in step with Core: it polls the
// signed relay state (docs/protocol/mtrp-v1.md §9) and exposes the trusted
// signing keys and revocations to the relay server.
package corelink

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// Defaults.
const (
	DefaultInterval = 10 * time.Second
	DefaultTimeout  = 10 * time.Second
	maxBackoff      = time.Minute
	statePath       = "/relay/v1/state"
)

var errNotNewer = errors.New("corelink: relay state is not newer than the current one")

// Config configures a Link.
type Config struct {
	CoreURL   string              // https://control.example.com
	Bootstrap []key.SigningPublic // trusted until the first verified state
	Self      key.RelayPublic     // this relay, for drain commands
	OnDrain   func()              // called once when Core asks this relay to drain
	Interval  time.Duration
	Timeout   time.Duration
	Client    *http.Client // tests; production builds one with Timeout and no redirects
	Now       func() time.Time
	Logger    *slog.Logger
	Metrics   func(result string)
}

// Link holds the latest verified relay state. Its read methods are safe for
// concurrent use and lock-free.
type Link struct {
	cfg      Config
	stateURL string

	keys       atomic.Pointer[mtrp.StaticKeys]
	revoked    atomic.Pointer[mtrp.RevocationSet]
	generation atomic.Uint64

	// Owned by the polling goroutine.
	sequence  int64
	etag      string
	expiresAt time.Time
	state     mtrp.RelayState
	drainOnce sync.Once
}

// New validates the configuration and installs the bootstrap keys.
func New(cfg Config) (*Link, error) {
	if len(cfg.Bootstrap) == 0 {
		return nil, errors.New("corelink: at least one bootstrap signing key is required")
	}
	u, err := url.Parse(cfg.CoreURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return nil, fmt.Errorf("corelink: Core URL must be https://host[:port] without credentials or query")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = func(string) {}
	}
	if cfg.OnDrain == nil {
		cfg.OnDrain = func() {}
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: cfg.Timeout,
				MaxIdleConns:        2,
			},
			// The state URL is fixed configuration; never follow a redirect.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	l := &Link{cfg: cfg, stateURL: u.JoinPath(statePath).String()}
	bootstrap := mtrp.NewStaticKeys(cfg.Bootstrap...)
	l.keys.Store(&bootstrap)
	l.revoked.Store(mtrp.NewRevocationSet(mtrp.RelayState{}))
	return l, nil
}

// SigningKey implements mtrp.KeySet with the currently trusted keys.
func (l *Link) SigningKey(id key.KeyID) (key.SigningPublic, bool) {
	return l.keys.Load().SigningKey(id)
}

// Revoked implements mtrp.Revocations.
func (l *Link) Revoked(t mtrp.Ticket) bool { return l.revoked.Load().Revoked(t) }

// Generation increases whenever the revocations change, so the relay only
// rescans its sessions when there is something new.
func (l *Link) Generation() uint64 { return l.generation.Load() }

// Run polls until ctx is done. Failures keep the last good state and back
// off; they never stop the relay.
func (l *Link) Run(ctx context.Context) error {
	delay := time.Duration(0)
	failures := 0
	for {
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
		}
		err := l.Poll(ctx)
		if stopping(ctx) {
			return nil // a poll cut short by shutdown is not a failure
		}
		l.refreshKeys() // keys can expire while Core is unreachable
		switch {
		case err != nil:
			failures++
			delay = min(l.cfg.Interval<<min(failures, 6), maxBackoff)
			l.cfg.Logger.Warn("relay state update failed", "error", err, "retry_in", delay.String(),
				"state_expired", !l.expiresAt.IsZero() && l.cfg.Now().After(l.expiresAt))
		default:
			failures = 0
			delay = l.cfg.Interval
		}
		// Jitter spreads a fleet's requests.
		delay += time.Duration(rand.Int64N(int64(delay/10) + 1)) //nolint:gosec // jitter, not security
	}
}

// Poll fetches and applies the relay state once.
func (l *Link) Poll(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.stateURL, nil)
	if err != nil {
		return err
	}
	if l.etag != "" {
		req.Header.Set("If-None-Match", l.etag)
	}
	resp, err := l.cfg.Client.Do(req)
	if err != nil {
		l.cfg.Metrics("fetch_failed")
		return fmt.Errorf("corelink: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		l.cfg.Metrics("not_modified")
		l.refreshKeys()
		return nil
	case http.StatusOK:
	default:
		l.cfg.Metrics("bad_status")
		return fmt.Errorf("corelink: fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, mtrp.MaxDocumentPayload+1024))
	if err != nil {
		l.cfg.Metrics("fetch_failed")
		return fmt.Errorf("corelink: read: %w", err)
	}
	if err := l.apply(body); err != nil {
		if errors.Is(err, errNotNewer) {
			// A Core replica one signing window behind the one that served
			// the held state: keep it, and keep its ETag.
			l.cfg.Metrics("not_newer")
			return nil
		}
		l.cfg.Metrics("rejected")
		return err
	}
	l.etag = resp.Header.Get("ETag")
	l.cfg.Metrics("applied")
	return nil
}

// apply verifies a signed state and makes it current.
func (l *Link) apply(doc []byte) error {
	payload, _, err := mtrp.OpenDocument(doc, mtrp.DocumentRelayState, *l.keys.Load())
	if err != nil {
		return fmt.Errorf("corelink: %w", err)
	}
	state, err := mtrp.ParseRelayState(payload)
	if err != nil {
		return fmt.Errorf("corelink: %w", err)
	}
	now := l.cfg.Now()
	if state.Sequence <= l.sequence {
		return errNotNewer
	}
	if !now.Before(state.ExpiresAt) {
		return fmt.Errorf("corelink: relay state expired at %s", state.ExpiresAt.UTC().Format(time.RFC3339))
	}
	keys, err := state.TrustedKeySet(now)
	if err != nil {
		return fmt.Errorf("corelink: relay state lists no valid signing key: %w", err)
	}
	l.keys.Store(&keys)
	l.revoked.Store(mtrp.NewRevocationSet(state))
	l.generation.Add(1)
	l.sequence, l.expiresAt, l.state = state.Sequence, state.ExpiresAt, state
	if slices.Contains(state.Drain, l.cfg.Self) {
		l.drainOnce.Do(func() {
			l.cfg.Logger.Warn("Core asked this relay to drain")
			l.cfg.OnDrain()
		})
	}
	return nil
}

// refreshKeys drops keys whose not_after passed while the state is unchanged.
func (l *Link) refreshKeys() {
	if l.sequence == 0 {
		return
	}
	if keys, err := l.state.TrustedKeySet(l.cfg.Now()); err == nil {
		l.keys.Store(&keys)
	} else {
		empty := mtrp.StaticKeys{}
		l.keys.Store(&empty) // every key expired: fail closed
	}
}

func stopping(ctx context.Context) bool { return ctx.Err() != nil }
