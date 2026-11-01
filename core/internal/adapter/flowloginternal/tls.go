// Package flowloginternal serves Core's internal API to the connection log
// receiver (meshflow, connection logs design §16c): a listener of its own,
// mutual TLS 1.3 with the receiver's own CA and identity, read-only.
package flowloginternal

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// reloadInterval is how often the certificate, key and CA files are
	// read again, so they rotate without a restart (C38a).
	reloadInterval = time.Minute
	// reloadGrace is how long the last good material serves while the
	// files do not read; after it every handshake fails (review s4c1a H1).
	reloadGrace = 5 * time.Minute
)

var (
	// ErrInvalidCredentials reports unreadable or invalid TLS files.
	ErrInvalidCredentials = errors.New("flowloginternal: invalid TLS credentials")
	// ErrNoReceiverCA reports a receiver CA file that is gone or holds no
	// certificate: no receiver is trusted until one is back.
	ErrNoReceiverCA = errors.New("flowloginternal: no receiver CA")
	// ErrWrongClient reports a client certificate that does not name the
	// receiver.
	ErrWrongClient = errors.New("flowloginternal: client certificate does not name the receiver")
	// ErrStaleCredentials reports material past reloadGrace.
	ErrStaleCredentials = errors.New("flowloginternal: TLS credentials could not be read again")
)

// credentials holds the server certificate and the receiver CA, read from
// files by a background reload. A receiver CA that is removed or emptied
// stops trusting anyone at the next reload; any other read failure keeps the
// last good material for reloadGrace, then fails every handshake.
type credentials struct {
	certFile, keyFile, caFile string
	client                    string
	now                       func() time.Time
	metrics                   *Metrics
	logger                    *slog.Logger

	config   atomic.Pointer[tls.Config] // nil: refuse every handshake
	goodAt   atomic.Pointer[time.Time]  // the last good read, with its monotonic reading
	mu       sync.Mutex                 // serialises reloads
	failing  bool
	stopOnce sync.Once
	stop     chan struct{}
	stopped  chan struct{}
}

func newCredentials(certFile, keyFile, caFile string, client *url.URL, now func() time.Time, metrics *Metrics,
	logger *slog.Logger,
) (*credentials, error) {
	if client == nil || now == nil || metrics == nil || logger == nil {
		return nil, ErrInvalidCredentials
	}
	source := &credentials{
		certFile: certFile, keyFile: keyFile, caFile: caFile, client: client.String(), now: now,
		metrics: metrics, logger: logger, stop: make(chan struct{}), stopped: make(chan struct{}),
	}
	config, err := source.load()
	if err != nil {
		return nil, err
	}
	source.config.Store(config)
	readAt := now()
	source.goodAt.Store(&readAt)
	metrics.reloaded(readAt)
	return source, nil
}

// serverConfig is the listener's base: every handshake takes its settings
// from the last good read. The base itself refuses what the per-handshake
// one would, should it ever be used.
func (source *credentials) serverConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		SessionTicketsDisabled: true,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			config := source.config.Load()
			if config == nil {
				return nil, ErrNoReceiverCA
			}
			if source.now().Sub(*source.goodAt.Load()) > reloadGrace {
				return nil, ErrStaleCredentials
			}
			return config, nil
		},
	}
}

// run reloads every reloadInterval until stopped.
func (source *credentials) run() {
	defer close(source.stopped)
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-source.stop:
			return
		case <-ticker.C:
			source.reload()
		}
	}
}

func (source *credentials) close() {
	source.stopOnce.Do(func() { close(source.stop) })
}

// reload reads the files again. A missing or empty receiver CA trusts no
// one at once; another failure keeps the last good material (it expires
// after reloadGrace).
func (source *credentials) reload() {
	source.mu.Lock()
	defer source.mu.Unlock()
	config, err := source.load()
	switch {
	case err == nil:
		source.config.Store(config)
		readAt := source.now()
		source.goodAt.Store(&readAt)
		source.metrics.reloaded(readAt)
		if source.failing {
			source.failing = false
			source.logger.Info("connection log receiver TLS files read again")
		}
		return
	case errors.Is(err, ErrNoReceiverCA):
		source.config.Store(nil)
	}
	source.metrics.reloadFailed()
	if !source.failing {
		source.failing = true
		source.logger.Warn("connection log receiver TLS files do not read", "error_code", "flowlog_internal_tls_reload",
			"no_receiver_ca", errors.Is(err, ErrNoReceiverCA))
	}
}

func (source *credentials) load() (*tls.Config, error) {
	// The CA first: a removed one revokes even when the server files do
	// not read either.
	caPEM, err := os.ReadFile(source.caFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoReceiverCA
	}
	if err != nil {
		return nil, errors.Join(ErrInvalidCredentials, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, ErrNoReceiverCA
	}
	certificate, err := tls.LoadX509KeyPair(source.certFile, source.keyFile)
	if err != nil {
		return nil, errors.Join(ErrInvalidCredentials, err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.Join(ErrInvalidCredentials, err)
	}
	// Each direction has its own CA (C38): a server certificate the
	// receiver CA issued would let that CA speak for Core too.
	intermediates := x509.NewCertPool()
	for _, der := range certificate.Certificate[1:] {
		if parsed, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(parsed)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		return nil, errors.Join(ErrInvalidCredentials, errors.New("the server certificate chains to the receiver CA"))
	}
	source.metrics.certificateExpiry(leaf.NotAfter)
	client, metrics := source.client, source.metrics
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		// Without tickets every connection verifies the chain and the
		// identity again: a removed CA takes effect (C38a).
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
		// The chain is verified against ClientCAs for client authentication
		// before this runs; the leaf must name the receiver exactly.
		VerifyConnection: func(state tls.ConnectionState) error {
			reason := verifyClient(state, client)
			if reason != "" {
				metrics.rejected(reason)
				return ErrWrongClient
			}
			return nil
		},
	}, nil
}

// verifyClient names why a verified connection's leaf is not the receiver:
// it must be an end entity for client authentication carrying exactly one
// URI SAN, client. The empty string accepts it.
func verifyClient(state tls.ConnectionState, client string) string {
	switch {
	case len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0:
		return "no_chain"
	case state.PeerCertificates[0].IsCA:
		return "ca_leaf"
	case !slices.Contains(state.PeerCertificates[0].ExtKeyUsage, x509.ExtKeyUsageClientAuth):
		// A leaf without EKU passes chain verification as "any"; the
		// receiver's must say client authentication.
		return "eku"
	case len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != client:
		return "identity"
	}
	return ""
}
