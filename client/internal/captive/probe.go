// Package captive finds out whether a host that sends its Internet traffic
// through an exit node stands behind a captive portal (exit node design
// §17.3): the network's RFC 8908 captive portal API when the host learned
// one, a plain HTTP probe of a relay by address whose answer echoes a nonce,
// and the network resolver's answer for the relay's name.
package captive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"syscall"
	"time"
)

// Verdict is what a check concluded.
type Verdict string

const (
	// VerdictNone: the network reaches the Internet; whatever is wrong is
	// elsewhere.
	VerdictNone Verdict = "none"
	// VerdictSuspected: the network answers oddly (a refusal, a DNS answer
	// that is not the relay's), as a portal would.
	VerdictSuspected Verdict = "suspected"
	// VerdictPortal: the network intercepts the probe, or says so itself.
	VerdictPortal Verdict = "portal"
	// VerdictUnknown: nothing answered; the network may simply be down.
	VerdictUnknown Verdict = "unknown"
)

// probePath and nonceHeader are the relay's (meshrelay --probe-http).
const (
	probePath   = "/generate_204"
	nonceHeader = "Meshtransit-Probe-Nonce"
	// probeTimeout bounds one probe.
	probeTimeout = 5 * time.Second
	// maximumBody is read of an answer: a portal page is not needed.
	maximumBody = 4 << 10
)

// Result is one probe's verdict, and the portal's address when it said
// where to sign in.
type Result struct {
	Verdict Verdict
	// URL is the sign-in page the network named (a redirect's Location, or
	// the API's user-portal-url); the network's word, not MeshTransit's.
	URL string
}

// Prober probes relays over plain HTTP.
type Prober struct {
	client *http.Client
	nonce  func() (string, error)
	// port is the relay's probe port, 80 but in tests.
	port uint16
}

// NewProber returns a prober whose connections use control, the client's
// own sockets (kept off the exit routes and let through the kill switch).
func NewProber(control func(network, address string, raw syscall.RawConn) error) *Prober {
	dialer := &net.Dialer{Timeout: probeTimeout, Control: control}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, DisableKeepAlives: true,
		ResponseHeaderTimeout: probeTimeout, MaxResponseHeaderBytes: maximumBody,
	}
	return &Prober{
		client: &http.Client{
			Transport: transport, Timeout: probeTimeout,
			// A redirect is the answer: it is never followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		nonce: randomNonce, port: 80,
	}
}

// Probe asks the relay at address for /generate_204 with a fresh nonce.
func (p *Prober) Probe(ctx context.Context, address netip.Addr) Result {
	nonce, err := p.nonce()
	if err != nil {
		return Result{Verdict: VerdictUnknown}
	}
	target := url.URL{
		Scheme: "http", Host: netip.AddrPortFrom(address, p.port).String(), Path: probePath,
		RawQuery: url.Values{"n": {nonce}}.Encode(),
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return Result{Verdict: VerdictUnknown}
	}
	response, err := p.client.Do(request)
	if err != nil {
		return Result{Verdict: VerdictUnknown}
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(response.Body, maximumBody))
	return classify(response.StatusCode, response.Header.Get(nonceHeader), nonce, len(body),
		response.Header.Get("Location"), target)
}

// classify reads a probe's answer: 204 with the nonce echoed and no body
// reaches the relay; a redirect, 511, or a 200/204 that is not the relay's
// is a portal; any other code is suspected; the relay's own rate limit
// (429) says nothing.
func classify(code int, echoed, nonce string, bodyBytes int, location string, target url.URL) Result {
	switch {
	case code == http.StatusNoContent && echoed == nonce && bodyBytes == 0:
		return Result{Verdict: VerdictNone}
	case code == http.StatusTooManyRequests:
		return Result{Verdict: VerdictUnknown}
	case code == http.StatusNetworkAuthenticationRequired || code == http.StatusOK || code == http.StatusNoContent:
		return Result{Verdict: VerdictPortal, URL: signInURL(location, target)}
	case code >= 300 && code < 400:
		return Result{Verdict: VerdictPortal, URL: signInURL(location, target)}
	default:
		return Result{Verdict: VerdictSuspected}
	}
}

// signInURL resolves a redirect's Location against the probe's address;
// empty when it names no http or https page.
func signInURL(location string, target url.URL) string {
	if location == "" {
		return ""
	}
	parsed, err := target.Parse(location)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	return parsed.String()
}

// PortalEndpoint returns the address and port of a sign-in page on a port
// other than 80 and 443, which the window lets through on its own (§17.5);
// false otherwise.
func PortalEndpoint(signIn string) (string, uint16, bool) {
	parsed, err := url.Parse(signIn)
	if err != nil || parsed.Port() == "" {
		return "", 0, false
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 || port == 80 || port == 443 {
		return "", 0, false
	}
	return parsed.Hostname(), uint16(port), true
}

func randomNonce() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("captive: nonce: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
}
