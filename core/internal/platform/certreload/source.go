// Package certreload serves a TLS certificate that is read again from its
// files while the process runs, so a certificate cert-manager or an
// operator renews reaches every listener without a restart (V1-11, TD-OPS-32).
package certreload

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultInterval is how often the files are read again.
	DefaultInterval = time.Minute
	// expiryWarning: while the served certificate expires within this, a
	// warning repeats every expiryWarningEvery, so a renewal that never
	// arrives, or is refused, is not one log line weeks before the outage.
	expiryWarning      = 7 * 24 * time.Hour
	expiryWarningEvery = 24 * time.Hour
)

// ErrInvalid reports options a Source cannot serve.
var ErrInvalid = errors.New("certreload: invalid options")

// Options build a Source.
type Options struct {
	// Name labels the listener in logs ("control", "management", ...).
	Name string
	// Initial is the certificate the listener was built with.
	Initial tls.Certificate
	// Load reads the files again and checks the result as the listener's
	// constructor does; it must not keep the key's bytes.
	Load func() (tls.Certificate, error)
	// Interval defaults to DefaultInterval.
	Interval time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
	// Logger defaults to one that discards.
	Logger *slog.Logger
}

// Source hands each TLS handshake the newest good certificate. At most once
// per interval, one handshake reads the files again (the others keep the
// current certificate); a read that fails, or a certificate not valid at
// that moment, keeps the current one.
type Source struct {
	name     string
	load     func() (tls.Certificate, error)
	interval time.Duration
	now      func() time.Time
	logger   *slog.Logger

	current   atomic.Pointer[tls.Certificate]
	checkedAt atomic.Pointer[time.Time] // the last read attempt, with its monotonic reading
	mu        sync.Mutex                // one read at a time
	failing   bool                      // under mu
	warnedAt  time.Time                 // under mu: the last expiry warning
}

// New returns a Source serving options.Initial until a newer certificate
// reads well.
func New(options Options) (*Source, error) {
	if options.Name == "" || options.Load == nil || len(options.Initial.Certificate) == 0 ||
		options.Initial.PrivateKey == nil || options.Interval < 0 {
		return nil, ErrInvalid
	}
	source := &Source{
		name: options.Name, load: options.Load, interval: options.Interval,
		now: options.Now, logger: options.Logger,
	}
	if source.interval == 0 {
		source.interval = DefaultInterval
	}
	if source.now == nil {
		source.now = time.Now
	}
	if source.logger == nil {
		source.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	initial := options.Initial
	if initial.Leaf == nil {
		leaf, err := x509.ParseCertificate(initial.Certificate[0])
		if err != nil {
			return nil, ErrInvalid
		}
		initial.Leaf = leaf
	}
	source.current.Store(&initial)
	now := source.now()
	source.checkedAt.Store(&now)
	return source, nil
}

// GetCertificate is a tls.Config.GetCertificate. The listener's config must
// leave Certificates empty: Go calls GetCertificate only when a client sends
// SNI or Certificates is empty, and ingress controllers often send none.
func (source *Source) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	source.reloadIfDue()
	return source.current.Load(), nil
}

// Current returns the certificate a handshake would get now.
func (source *Source) Current() tls.Certificate {
	source.reloadIfDue()
	return *source.current.Load()
}

func (source *Source) reloadIfDue() {
	if !source.due() || !source.mu.TryLock() {
		return
	}
	defer source.mu.Unlock()
	if !source.due() {
		return
	}
	now := source.now()
	source.checkedAt.Store(&now)
	certificate, reason := source.read(now)
	if reason != "" {
		if !source.failing {
			source.failing = true
			source.logger.Warn("tls certificate could not be read again; serving the current one",
				"listener", source.name, "error_code", "tls_certificate_reload_failed", "reason", reason)
		}
		source.warnIfExpiring(now)
		return
	}
	if source.failing {
		source.failing = false
		source.logger.Info("tls certificate reads again", "listener", source.name)
	}
	if !bytes.Equal(certificate.Certificate[0], source.current.Load().Certificate[0]) {
		source.current.Store(&certificate)
		source.logger.Info("tls certificate reloaded", "listener", source.name,
			"not_after", certificate.Leaf.NotAfter.UTC())
	}
	source.warnIfExpiring(now)
}

// read loads the files and names why they cannot serve: "load_failed" (a
// read error or the listener's own checks), "rejected" (not a certificate),
// "not_valid_now" (outside its validity, or a chain member is).
func (source *Source) read(now time.Time) (tls.Certificate, string) {
	certificate, err := source.load()
	if err != nil {
		return tls.Certificate{}, "load_failed"
	}
	if err := validAt(&certificate, now); err != nil {
		if errors.Is(err, errNotValidNow) {
			return tls.Certificate{}, "not_valid_now"
		}
		return tls.Certificate{}, "rejected"
	}
	return certificate, ""
}

// warnIfExpiring repeats a warning while the served certificate is close
// to expiry. Called under mu.
func (source *Source) warnIfExpiring(now time.Time) {
	notAfter := source.current.Load().Leaf.NotAfter
	if notAfter.Sub(now) > expiryWarning ||
		(!source.warnedAt.IsZero() && now.Sub(source.warnedAt) < expiryWarningEvery) {
		return
	}
	source.warnedAt = now
	source.logger.Warn("tls certificate expires soon and no newer one serves", "listener", source.name,
		"error_code", "tls_certificate_expiring", "not_after", notAfter.UTC())
}

func (source *Source) due() bool {
	return source.now().Sub(*source.checkedAt.Load()) >= source.interval
}

var errNotValidNow = errors.New("certreload: certificate not valid now")

// validAt checks a freshly read certificate and every chain member parse and
// are valid now (as the login listener checks at start), and fills Leaf.
func validAt(certificate *tls.Certificate, now time.Time) error {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return ErrInvalid
	}
	for index, encoded := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(encoded)
		if err != nil {
			return ErrInvalid
		}
		if now.Before(parsed.NotBefore) || !now.Before(parsed.NotAfter) {
			return errNotValidNow
		}
		if index == 0 {
			certificate.Leaf = parsed
		}
	}
	return nil
}
