// Package kubediscovery keeps the cluster's discovery as the gateway sees
// it: whether each (API group, resource) lives in a namespace or across the
// cluster. A profile decides by it (K2 §5.3, §10.2), so whatever is not
// known for sure is unknown, and unknown refuses (K2-I11).
package kubediscovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/shared/kubeprofile"
)

const (
	// DefaultRefresh is how often the table is fetched again, with ETags.
	DefaultRefresh = time.Minute
	// DefaultMinimumRefetch spaces fetches an unknown resource asks for.
	DefaultMinimumRefetch = 5 * time.Second
	// DefaultStaleAfter is how long a table outlives failed fetches before
	// every resource is unknown.
	DefaultStaleAfter = 5 * time.Minute
	// fetchTimeout bounds one fetch of both documents.
	fetchTimeout = 10 * time.Second
	// retryFirst is the first wait after a failed fetch, doubled up to the
	// refresh.
	retryFirst = 5 * time.Second
	// maximumDocument bounds one discovery document: thousands of CRDs fit.
	maximumDocument = 32 << 20
	// acceptAggregated asks for aggregated discovery (GA in 1.30; the chart
	// needs 1.32), and nothing else.
	acceptAggregated = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList"
	discoveryVersion = "apidiscovery.k8s.io/v2"
	discoveryKind    = "APIGroupDiscoveryList"
)

// documents are the two aggregated documents: the core group, then the rest.
var documents = [2]string{"/api", "/apis"}

// Options configure the discovery.
type Options struct {
	// Server is the API server's https URL, CAFile its CA, TokenFile the
	// gateway's own token: everyone authenticated may read discovery
	// (system:discovery), and the users' groups never show in its audit.
	Server, CAFile, TokenFile string
	Refresh, MinimumRefetch   time.Duration
	StaleAfter                time.Duration
	// Now is the local clock; nil: time.Now.
	Now    func() time.Time
	Logger *slog.Logger
	// Transport replaces the TLS transport, for tests.
	Transport http.RoundTripper
}

// key is a resource of an API group; the core group is "".
type key struct{ group, resource string }

// table is one fetch's view.
type table struct {
	scopes map[key]kubeprofile.ResourceScope
	// confirmedAt is when the API server last confirmed it (fetched or
	// answered 304), by the local clock.
	confirmedAt time.Time
}

// document is one document as last fetched.
type document struct {
	etag  string
	items []groupDiscovery
}

// Discovery is the cluster's resource scopes, refreshed.
type Discovery struct {
	options Options
	client  *http.Client
	current atomic.Pointer[table]

	// mu guards the fetch in flight, the documents and when the last fetch
	// started.
	mu        sync.Mutex
	inflight  chan struct{}
	startedAt time.Time
	documents [2]document
	// failing: the last fetch failed; logged once until one succeeds.
	failing bool
	// staleLogged: the table outlived StaleAfter; logged once.
	staleLogged atomic.Bool
	successes   atomic.Uint64
	failures    atomic.Uint64
}

// New makes a discovery with no table yet: every resource is unknown until
// the first fetch.
func New(options Options) (*Discovery, error) {
	parsed, err := url.Parse(options.Server)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		strings.Trim(parsed.Path, "/") != "" || options.TokenFile == "" || options.Logger == nil {
		return nil, errors.New("kubediscovery: invalid options")
	}
	if options.Refresh <= 0 {
		options.Refresh = DefaultRefresh
	}
	if options.MinimumRefetch <= 0 {
		options.MinimumRefetch = DefaultMinimumRefetch
	}
	if options.StaleAfter <= 0 {
		options.StaleAfter = DefaultStaleAfter
	}
	if options.Refresh > options.StaleAfter {
		return nil, errors.New("kubediscovery: the refresh must come before the table is stale")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	transport := options.Transport
	if transport == nil {
		pem, err := os.ReadFile(options.CAFile)
		if err != nil {
			return nil, fmt.Errorf("kubediscovery: reading the cluster CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("kubediscovery: the cluster CA file holds no certificate")
		}
		transport = &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second,
		}
	}
	options.Server = strings.TrimSuffix(options.Server, "/")
	return &Discovery{options: options, client: &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Run fetches the table, then again each Refresh, sooner after a failure,
// until ctx ends.
func (d *Discovery) Run(ctx context.Context) {
	wait := retryFirst
	for {
		next := d.options.Refresh
		if err := d.refresh(ctx, true); err != nil {
			next = min(wait, d.options.Refresh)
			wait = min(2*wait, d.options.Refresh)
		} else {
			wait = retryFirst
		}
		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Scope returns what discovery says of resource in group. A resource the
// table does not know has the table fetched again, at most once each
// MinimumRefetch, and waits for it within ctx: kubectl uses a CRD right
// after creating it. A table not confirmed for StaleAfter knows nothing.
func (d *Discovery) Scope(ctx context.Context, group, resource string) kubeprofile.ResourceScope {
	if scope := d.lookup(group, resource); scope != kubeprofile.ScopeUnknown {
		return scope
	}
	if err := d.refresh(ctx, false); err != nil {
		return kubeprofile.ScopeUnknown
	}
	return d.lookup(group, resource)
}

func (d *Discovery) lookup(group, resource string) kubeprofile.ResourceScope {
	current := d.current.Load()
	if current == nil {
		return kubeprofile.ScopeUnknown
	}
	if d.options.Now().Sub(current.confirmedAt) > d.options.StaleAfter {
		if !d.staleLogged.Swap(true) {
			d.options.Logger.Error("cluster discovery is stale: every profile request is refused",
				"error_code", "kubernetes_discovery_stale", "confirmed_at", current.confirmedAt)
		}
		return kubeprofile.ScopeUnknown
	}
	return current.scopes[key{group, resource}]
}

// Status reports when the API server last confirmed the table, zero for
// never, its resources, and the fetches that read and that failed so far,
// each its own counter (review e4–e6 M3).
func (d *Discovery) Status() (confirmedAt time.Time, resources int, successes, failures uint64) {
	if current := d.current.Load(); current != nil {
		confirmedAt, resources = current.confirmedAt, len(current.scopes)
	}
	return confirmedAt, resources, d.successes.Load(), d.failures.Load()
}

// Fresh reports a table confirmed within StaleAfter.
func (d *Discovery) Fresh() bool {
	current := d.current.Load()
	return current != nil && d.options.Now().Sub(current.confirmedAt) <= d.options.StaleAfter
}

// errTooSoon: a fetch an unknown resource asked for came within
// MinimumRefetch of the last.
var errTooSoon = errors.New("kubediscovery: fetched moments ago")

// refresh joins the fetch in flight or starts one; scheduled fetches skip
// MinimumRefetch. The fetch runs apart from ctx, which only bounds the wait.
func (d *Discovery) refresh(ctx context.Context, scheduled bool) error {
	d.mu.Lock()
	done := d.inflight
	if done == nil {
		if !scheduled && d.options.Now().Sub(d.startedAt) < d.options.MinimumRefetch {
			d.mu.Unlock()
			return errTooSoon
		}
		done = make(chan struct{})
		d.inflight, d.startedAt = done, d.options.Now()
		go d.fetch(done) //nolint:gosec // G118: the fetch serves every waiter, not this request
	}
	d.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if d.lastFailed() {
		return errors.New("kubediscovery: the fetch failed")
	}
	return nil
}

func (d *Discovery) lastFailed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failing
}

// fetch reads both documents and publishes the table only when both read.
func (d *Discovery) fetch(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	d.mu.Lock()
	held := d.documents
	d.mu.Unlock()
	fetched, changed, err := d.fetchDocuments(ctx, held)
	d.mu.Lock()
	defer func() {
		d.inflight = nil
		d.mu.Unlock()
		close(done)
	}()
	if err != nil {
		d.failures.Add(1)
		if !d.failing {
			d.options.Logger.Warn("cluster discovery failed: keeping the last table", "error_code",
				"kubernetes_discovery_failed", "error", err)
		}
		d.failing = true
		return
	}
	d.successes.Add(1)
	if d.failing {
		d.options.Logger.Info("cluster discovery read again")
	}
	d.failing = false
	d.staleLogged.Store(false)
	now, previous := d.options.Now(), d.current.Load()
	if changed || previous == nil {
		d.documents = fetched
		d.current.Store(&table{scopes: build(fetched), confirmedAt: now})
		return
	}
	d.current.Store(&table{scopes: previous.scopes, confirmedAt: now})
}

// fetchDocuments reads both documents, and whether either changed.
func (d *Discovery) fetchDocuments(ctx context.Context, held [2]document) ([2]document, bool, error) {
	token, err := os.ReadFile(d.options.TokenFile)
	if err != nil {
		return held, false, fmt.Errorf("reading the gateway's token: %w", err)
	}
	bearer := "Bearer " + strings.TrimSpace(string(token))
	fetched, changed := held, false
	for index, path := range documents {
		var fresh bool
		fetched[index], fresh, err = d.fetchDocument(ctx, path, bearer, held[index])
		if err != nil {
			return held, false, err
		}
		changed = changed || fresh
	}
	return fetched, changed, nil
}

// fetchDocument reads one document, or keeps held when its ETag still holds;
// fresh: it read a new one.
func (d *Discovery) fetchDocument(ctx context.Context, path, bearer string, held document,
) (_ document, fresh bool, _ error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.options.Server+path, http.NoBody)
	if err != nil {
		return held, false, err
	}
	request.Header.Set("Authorization", bearer)
	request.Header.Set("Accept", acceptAggregated)
	if held.etag != "" {
		request.Header.Set("If-None-Match", held.etag)
	}
	response, err := d.client.Do(request)
	if err != nil {
		return held, false, fmt.Errorf("calling the API server for %s: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode == http.StatusNotModified && held.etag != "":
		return held, false, nil
	case response.StatusCode != http.StatusOK:
		return held, false, fmt.Errorf("the API server answered %d for %s", response.StatusCode, path)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumDocument+1))
	if err != nil {
		return held, false, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(payload) > maximumDocument {
		return held, false, fmt.Errorf("%s is past %d bytes", path, maximumDocument)
	}
	items, err := decode(payload)
	if err != nil {
		return held, false, fmt.Errorf("%s: %w", path, err)
	}
	return document{etag: response.Header.Get("ETag"), items: items}, true, nil
}
