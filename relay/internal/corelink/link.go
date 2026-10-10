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
	"strconv"
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
	// DefaultLongPoll is how long Core may hold a state poll (wait=N,
	// mtrp-v1 §9) so revocations reach the relay as soon as Core signs them.
	DefaultLongPoll = 25 * time.Second
	// notNewerDelay paces polls answered by a Core replica still behind the
	// state the relay holds, until that replica catches up.
	notNewerDelay  = time.Second
	maxBackoff     = time.Minute
	statePath      = "/relay/v1/state"
	grantPath      = "/relay/v1/grant"
	maxSealedGrant = 64 << 10
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
	LongPoll  time.Duration // whole seconds; 0 uses DefaultLongPoll
	Client    *http.Client  // tests; production builds one with Timeout and no redirects
	Now       func() time.Time
	Logger    *slog.Logger
	Metrics   func(result string)
	// Revocations, when set, receives the number of revocation entries in
	// force after each applied state.
	Revocations func(n int)
	// Private makes this relay a Private Interchange: it polls its grant
	// (mtrp-v1 §9.2), sealed to Key, and admits only the granted Networks.
	// Without a valid grant it admits nothing.
	Private bool
	Key     key.RelayPrivate
}

// Link holds the latest verified relay state. Its read methods are safe for
// concurrent use and lock-free.
type Link struct {
	cfg      Config
	stateURL string
	grantURL string

	keys       atomic.Pointer[mtrp.StaticKeys]
	revoked    atomic.Pointer[mtrp.RevocationSet]
	generation atomic.Uint64

	// Owned by the polling goroutine.
	sequence  int64
	etag      string
	expiresAt time.Time
	state     mtrp.RelayState
	drainOnce sync.Once

	grant         atomic.Pointer[mtrp.RelayGrant]
	grantSequence uint64 // owned by the polling goroutine
	grantExpired  bool   // owned by the polling goroutine
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
	if cfg.LongPoll <= 0 {
		cfg.LongPoll = DefaultLongPoll
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Revocations == nil {
		cfg.Revocations = func(int) {}
	}
	if cfg.Metrics == nil {
		cfg.Metrics = func(string) {}
	}
	if cfg.OnDrain == nil {
		cfg.OnDrain = func() {}
	}
	if cfg.Client == nil {
		// No client-wide timeout: each request carries its own, longer for a
		// held poll.
		cfg.Client = &http.Client{
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
	if cfg.Private && (cfg.Key.IsZero() || cfg.Key.Public() != cfg.Self) {
		return nil, errors.New("corelink: a Private Interchange needs its relay key")
	}
	l := &Link{cfg: cfg, stateURL: u.JoinPath(statePath).String()}
	if cfg.Private {
		grantURL := u.JoinPath(grantPath)
		grantURL.RawQuery = url.Values{"relay": {cfg.Self.String()}}.Encode()
		l.grantURL = grantURL.String()
	}
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

// ZoneRevoked implements mtrp.ZoneRevocations. A Private Interchange treats
// every zone outside its grant as withdrawn: tickets without a granted
// Network are refused, and routes open only within granted Networks.
func (l *Link) ZoneRevoked(z mtrp.Zone) bool {
	if l.revoked.Load().ZoneRevoked(z) {
		return true
	}
	if !l.cfg.Private {
		return false
	}
	grant := l.grant.Load()
	return grant == nil || z.Kind != mtrp.ZoneNetwork || !l.cfg.Now().Before(grant.ExpiresAt) || !grant.Serves(z.ID)
}

// Grant returns the Private Interchange grant in force, if any.
func (l *Link) Grant() (mtrp.RelayGrant, bool) {
	grant := l.grant.Load()
	if grant == nil {
		return mtrp.RelayGrant{}, false
	}
	return *grant, true
}

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
		outcome, err := l.poll(ctx)
		if err == nil && l.cfg.Private {
			err = l.PollGrant(ctx)
		}
		if stopping(ctx) {
			return nil // a poll cut short by shutdown is not a failure
		}
		l.refreshKeys() // keys can expire while Core is unreachable
		l.noteGrantExpiry()
		switch {
		case err != nil:
			failures++
			delay = min(l.cfg.Interval<<min(failures, 6), maxBackoff)
			l.cfg.Logger.Warn("relay state update failed", "error", err, "retry_in", delay.String(),
				"state_expired", !l.expiresAt.IsZero() && l.cfg.Now().After(l.expiresAt))
		case outcome == pollApplied || outcome == pollHeld:
			// Core holds the next poll until it signs a new state.
			failures, delay = 0, 0
			continue
		case outcome == pollNotNewer:
			failures, delay = 0, min(notNewerDelay, l.cfg.Interval)
		default:
			// Answered at once: this Core does not hold polls.
			failures, delay = 0, l.cfg.Interval
		}
		// Jitter spreads a fleet's requests.
		delay += time.Duration(rand.Int64N(int64(delay/10) + 1)) //nolint:gosec // jitter, not security
	}
}

// pollOutcome says how a state poll ended, which sets the next delay.
type pollOutcome int

const (
	pollApplied  pollOutcome = iota // a newer state was applied
	pollHeld                        // Core held the poll until its wait ended
	pollAnswered                    // not modified, answered at once
	pollNotNewer                    // a replica behind the held state answered
)

// Poll fetches and applies the relay state once.
func (l *Link) Poll(ctx context.Context) error {
	_, err := l.poll(ctx)
	return err
}

func (l *Link) poll(ctx context.Context) (pollOutcome, error) {
	target, timeout := l.stateURL, l.cfg.Timeout
	if l.etag != "" {
		target += "?wait=" + strconv.Itoa(int(l.cfg.LongPoll/time.Second))
		timeout += l.cfg.LongPoll
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return pollAnswered, err
	}
	if l.etag != "" {
		req.Header.Set("If-None-Match", l.etag)
	}
	started := time.Now()
	resp, err := l.cfg.Client.Do(req)
	if err != nil {
		l.cfg.Metrics("fetch_failed")
		return pollAnswered, fmt.Errorf("corelink: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		l.cfg.Metrics("not_modified")
		l.refreshKeys()
		if time.Since(started) >= l.cfg.LongPoll/2 {
			return pollHeld, nil
		}
		return pollAnswered, nil
	case http.StatusOK:
	default:
		l.cfg.Metrics("bad_status")
		return pollAnswered, fmt.Errorf("corelink: fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, mtrp.MaxDocumentPayload+1024))
	if err != nil {
		l.cfg.Metrics("fetch_failed")
		return pollAnswered, fmt.Errorf("corelink: read: %w", err)
	}
	if err := l.apply(body); err != nil {
		if errors.Is(err, errNotNewer) {
			// A Core replica behind the one that served the held state:
			// keep it, and keep its ETag.
			l.cfg.Metrics("not_newer")
			return pollNotNewer, nil
		}
		l.cfg.Metrics("rejected")
		return pollAnswered, err
	}
	l.etag = resp.Header.Get("ETag")
	l.cfg.Metrics("applied")
	return pollApplied, nil
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
	revoked := mtrp.NewRevocationSet(state)
	l.revoked.Store(revoked)
	l.cfg.Revocations(revoked.Len())
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

// PollGrant fetches, opens and applies this Private Interchange's grant.
func (l *Link) PollGrant(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, l.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.grantURL, nil)
	if err != nil {
		return err
	}
	resp, err := l.cfg.Client.Do(req)
	if err != nil {
		l.cfg.Metrics("grant_fetch_failed")
		return fmt.Errorf("corelink: grant fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		l.cfg.Metrics("grant_bad_status")
		return fmt.Errorf("corelink: grant fetch: status %d", resp.StatusCode)
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, maxSealedGrant+1))
	if err != nil || len(sealed) > maxSealedGrant {
		l.cfg.Metrics("grant_fetch_failed")
		return errors.New("corelink: grant read failed or too large")
	}
	if err := l.applyGrant(sealed); err != nil {
		if errors.Is(err, errNotNewer) {
			l.cfg.Metrics("grant_not_newer")
			return nil
		}
		l.cfg.Metrics("grant_rejected")
		return err
	}
	l.cfg.Metrics("grant_applied")
	return nil
}

// applyGrant opens a sealed grant, verifies it and makes it current.
func (l *Link) applyGrant(sealed []byte) error {
	document, err := mtrp.OpenRelayGrant(sealed, l.cfg.Key)
	if err != nil {
		return fmt.Errorf("corelink: %w", err)
	}
	payload, _, err := mtrp.OpenDocument(document, mtrp.DocumentRelayGrant, *l.keys.Load())
	if err != nil {
		return fmt.Errorf("corelink: %w", err)
	}
	grant, err := mtrp.ParseRelayGrant(payload, l.cfg.Self, l.cfg.Now())
	if err != nil {
		return fmt.Errorf("corelink: %w", err)
	}
	if grant.Sequence <= l.grantSequence {
		return errNotNewer
	}
	previous := l.grant.Load()
	l.grant.Store(&grant)
	l.grantSequence, l.grantExpired = grant.Sequence, false
	if previous == nil || !slices.Equal(previous.Networks, grant.Networks) {
		l.cfg.Logger.Info("Private Interchange grant updated", "networks", len(grant.Networks))
		l.generation.Add(1) // the relay rescans sessions and routes
	}
	return nil
}

// noteGrantExpiry rescans sessions once when the grant in force expires.
func (l *Link) noteGrantExpiry() {
	grant := l.grant.Load()
	if !l.cfg.Private || grant == nil || l.grantExpired || l.cfg.Now().Before(grant.ExpiresAt) {
		return
	}
	l.grantExpired = true
	l.cfg.Logger.Warn("Private Interchange grant expired: admitting no session until Core answers")
	l.generation.Add(1)
}
