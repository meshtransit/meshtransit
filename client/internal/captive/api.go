package captive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// apiMediaType is the captive portal API's (RFC 8908 §5).
const apiMediaType = "application/captive+json"

// apiState is what the API says (RFC 8908 §5): whether the host is still
// held, and where to sign in.
type apiState struct {
	Captive          bool   `json:"captive"`
	UserPortalURL    string `json:"user-portal-url"`
	SecondsRemaining *int64 `json:"seconds-remaining"`
}

// FetchAPI asks the network's captive portal API at uri, an https URI the
// network gave (DHCP option 114, RA option 37, RFC 8910).
func (p *Prober) FetchAPI(ctx context.Context, uri string) (Result, error) {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return Result{}, fmt.Errorf("captive: API URI %q is not https", uri)
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("captive: API request: %w", err)
	}
	request.Header.Set("Accept", apiMediaType)
	response, err := p.client.Do(request)
	if err != nil {
		return Result{}, fmt.Errorf("captive: API: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK ||
		!strings.HasPrefix(response.Header.Get("Content-Type"), apiMediaType) {
		return Result{}, fmt.Errorf("captive: API answered %d %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	var state apiState
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumBody)).Decode(&state); err != nil {
		return Result{}, fmt.Errorf("captive: API answer: %w", err)
	}
	if !state.Captive {
		return Result{Verdict: VerdictNone}, nil
	}
	return Result{Verdict: VerdictPortal, URL: signInURL(state.UserPortalURL, *parsed)}, nil
}
