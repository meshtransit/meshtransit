package certreload

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var epoch = time.Date(2026, time.November, 20, 9, 0, 0, 0, time.UTC)

func certificate(t *testing.T, serial int64, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "core.example"},
		DNSNames: []string{"core.example"}, NotBefore: notBefore, NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type clock struct{ now atomic.Pointer[time.Time] }

func newClock() *clock {
	c := &clock{}
	c.set(epoch)
	return c
}
func (c *clock) set(at time.Time)         { c.now.Store(&at) }
func (c *clock) advance(by time.Duration) { c.set(c.now.Load().Add(by)) }
func (c *clock) Now() time.Time           { return *c.now.Load() }

type files struct {
	mu    sync.Mutex
	next  tls.Certificate
	err   error
	reads int
}

func (f *files) set(certificate tls.Certificate, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next, f.err = certificate, err
}

func (f *files) load() (tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.next, f.err
}

func (f *files) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

func newSource(t *testing.T, initial tls.Certificate, f *files, c *clock, logs *bytes.Buffer) *Source {
	t.Helper()
	source, err := New(Options{
		Name: "control", Initial: initial, Load: f.load, Now: c.Now,
		Logger: slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func served(t *testing.T, source *Source) []byte {
	t.Helper()
	got, err := source.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || got == nil {
		t.Fatalf("GetCertificate() = %v, %v", got, err)
	}
	return got.Certificate[0]
}

// A renewed certificate is served after the interval, without a restart,
// and the files are read at most once per interval.
func TestSourceServesTheRenewedCertificate(t *testing.T) {
	t.Parallel()
	c, f, logs := newClock(), &files{}, &bytes.Buffer{}
	first := certificate(t, 1, epoch.Add(-time.Hour), epoch.Add(24*time.Hour))
	renewed := certificate(t, 2, epoch.Add(-time.Minute), epoch.Add(90*24*time.Hour))
	f.set(renewed, nil)
	source := newSource(t, first, f, c, logs)

	if !bytes.Equal(served(t, source), first.Certificate[0]) || f.count() != 0 {
		t.Fatalf("before the interval: reads %d", f.count())
	}
	c.advance(DefaultInterval)
	if !bytes.Equal(served(t, source), renewed.Certificate[0]) || f.count() != 1 {
		t.Fatalf("after the interval: reads %d", f.count())
	}
	served(t, source)
	if f.count() != 1 {
		t.Fatalf("read again within the interval: %d", f.count())
	}
	if !strings.Contains(logs.String(), "tls certificate reloaded") || !strings.Contains(logs.String(), "listener=control") {
		t.Fatalf("logs: %s", logs.String())
	}
	if got := source.Current(); !bytes.Equal(got.Certificate[0], renewed.Certificate[0]) {
		t.Fatal("Current() is not the renewed certificate")
	}
}

// A read that fails, or a certificate not valid now, keeps the current one;
// the warning is logged once per failing streak.
func TestSourceKeepsTheCurrentCertificate(t *testing.T) {
	t.Parallel()
	c, f, logs := newClock(), &files{}, &bytes.Buffer{}
	first := certificate(t, 1, epoch.Add(-time.Hour), epoch.Add(24*time.Hour))
	source := newSource(t, first, f, c, logs)

	f.set(tls.Certificate{}, errors.New("half-written Secret"))
	for range 3 {
		c.advance(DefaultInterval)
		if !bytes.Equal(served(t, source), first.Certificate[0]) {
			t.Fatal("a failed read replaced the certificate")
		}
	}
	if n := strings.Count(logs.String(), "tls_certificate_reload_failed"); n != 1 {
		t.Fatalf("warnings = %d, want 1:\n%s", n, logs.String())
	}
	for _, unusable := range []tls.Certificate{
		certificate(t, 3, epoch.Add(-48*time.Hour), epoch.Add(-time.Hour)), // expired
		certificate(t, 4, epoch.Add(time.Hour), epoch.Add(48*time.Hour)),   // not yet valid
		{Certificate: [][]byte{[]byte("not DER")}, PrivateKey: first.PrivateKey},
	} {
		f.set(unusable, nil)
		c.advance(DefaultInterval)
		if !bytes.Equal(served(t, source), first.Certificate[0]) {
			t.Fatal("an unusable certificate replaced the current one")
		}
	}
	f.set(first, nil)
	c.advance(DefaultInterval)
	served(t, source)
	if !strings.Contains(logs.String(), "tls certificate reads again") ||
		strings.Contains(logs.String(), "tls certificate reloaded") {
		t.Fatalf("recovery to the same certificate: %s", logs.String())
	}
}

// Concurrent handshakes when a read is due read the files once.
func TestSourceReadsOncePerInterval(t *testing.T) {
	t.Parallel()
	c, f := newClock(), &files{}
	first := certificate(t, 1, epoch.Add(-time.Hour), epoch.Add(24*time.Hour))
	f.set(certificate(t, 2, epoch.Add(-time.Hour), epoch.Add(48*time.Hour)), nil)
	source := newSource(t, first, f, c, &bytes.Buffer{})
	c.advance(DefaultInterval)
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() { _, _ = source.GetCertificate(nil) })
	}
	group.Wait()
	if f.count() != 1 {
		t.Fatalf("reads = %d, want 1", f.count())
	}
}

func TestNewRefusesInvalidOptions(t *testing.T) {
	t.Parallel()
	valid := certificate(t, 1, epoch.Add(-time.Hour), epoch.Add(time.Hour))
	load := func() (tls.Certificate, error) { return valid, nil }
	for name, options := range map[string]Options{
		"no name":    {Initial: valid, Load: load},
		"no load":    {Name: "x", Initial: valid},
		"no initial": {Name: "x", Load: load},
		"no key":     {Name: "x", Initial: tls.Certificate{Certificate: valid.Certificate}, Load: load},
		"negative":   {Name: "x", Initial: valid, Load: load, Interval: -time.Second},
	} {
		if _, err := New(options); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: New() = %v", name, err)
		}
	}
}

// While the served certificate expires within a week and nothing newer
// serves, a warning repeats daily, not on every read.
func TestSourceWarnsDailyBeforeExpiry(t *testing.T) {
	t.Parallel()
	c, f, logs := newClock(), &files{}, &bytes.Buffer{}
	first := certificate(t, 1, epoch.Add(-time.Hour), epoch.Add(3*24*time.Hour))
	f.set(first, nil)
	source := newSource(t, first, f, c, logs)
	c.advance(DefaultInterval)
	served(t, source)
	c.advance(DefaultInterval)
	served(t, source)
	if n := strings.Count(logs.String(), "tls_certificate_expiring"); n != 1 {
		t.Fatalf("warnings after two reads = %d, want 1:\n%s", n, logs.String())
	}
	c.advance(expiryWarningEvery)
	served(t, source)
	if n := strings.Count(logs.String(), "tls_certificate_expiring"); n != 2 {
		t.Fatalf("warnings a day later = %d, want 2", n)
	}
	renewed := certificate(t, 2, c.Now().Add(-time.Minute), c.Now().Add(90*24*time.Hour))
	f.set(renewed, nil)
	c.advance(expiryWarningEvery)
	served(t, source)
	if n := strings.Count(logs.String(), "tls_certificate_expiring"); n != 2 {
		t.Fatalf("warned after the renewal served: %d", n)
	}
}

// The warning names why a read cannot serve.
func TestSourceNamesTheReason(t *testing.T) {
	t.Parallel()
	for reason, next := range map[string]func(t *testing.T) (tls.Certificate, error){
		"load_failed": func(*testing.T) (tls.Certificate, error) { return tls.Certificate{}, errors.New("read") },
		"not_valid_now": func(t *testing.T) (tls.Certificate, error) {
			return certificate(t, 9, epoch.Add(-48*time.Hour), epoch.Add(-time.Hour)), nil
		},
		"rejected": func(t *testing.T) (tls.Certificate, error) {
			valid := certificate(t, 9, epoch.Add(-time.Hour), epoch.Add(time.Hour))
			return tls.Certificate{Certificate: [][]byte{[]byte("not DER")}, PrivateKey: valid.PrivateKey}, nil
		},
	} {
		c, f, logs := newClock(), &files{}, &bytes.Buffer{}
		source := newSource(t, certificate(t, 1, epoch.Add(-time.Hour), epoch.Add(90*24*time.Hour)), f, c, logs)
		f.set(next(t))
		c.advance(DefaultInterval)
		served(t, source)
		if !strings.Contains(logs.String(), "reason="+reason) {
			t.Errorf("%s: %s", reason, logs.String())
		}
	}
}
