package legacyts2021

import (
	"io"
	"net/url"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

const browserRegistrationPathPrefix = "/register/v1/"

// BrowserRegistrationRequest is the bounded, unauthoritative browser-login
// subset of the legacy registration wire. A handler must still bind it to the
// Noise machine identity and compare FollowupURL to a server-issued intent.
type BrowserRegistrationRequest struct {
	nodeKey     node.Key
	hostname    node.Hostname
	followupURL string
}

// DecodeBrowserRegistration accepts a first browser request or its follow-up.
// It does not authorize the request or choose a Network.
func DecodeBrowserRegistration(body io.Reader) (BrowserRegistrationRequest, error) {
	wire, err := decodeRegistrationWire(body)
	if err != nil {
		return BrowserRegistrationRequest{}, err
	}
	return wire.toBrowserRegistration()
}

func (wire registrationRequestWire) toBrowserRegistration() (BrowserRegistrationRequest, error) {
	if wire.Version != supportedCapabilityVersion || wire.HostInfo == nil ||
		wire.Auth != nil || !isZeroTypedPublicKey(wire.OldNodeKey, nodeKeyPrefix) ||
		wire.hasUnsupportedSemanticsExceptFollowup() ||
		(wire.Followup != "" && !validBrowserFollowupURL(wire.Followup)) {
		return BrowserRegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	nodeKey, err := parseNodeKey(wire.NodeKey)
	if err != nil {
		return BrowserRegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	hostname, err := node.ParseHostname(wire.HostInfo.Hostname)
	if err != nil {
		return BrowserRegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	return BrowserRegistrationRequest{
		nodeKey: nodeKey, hostname: hostname, followupURL: wire.Followup,
	}, nil
}

// NodeKey returns the requested Node key. It is not registration authority.
func (request BrowserRegistrationRequest) NodeKey() node.Key { return request.nodeKey }

// Hostname returns the validated requested Device hostname.
func (request BrowserRegistrationRequest) Hostname() node.Hostname { return request.hostname }

// FollowupURL returns the secret, server-issued URL presented by the client.
func (request BrowserRegistrationRequest) FollowupURL() string { return request.followupURL }

// IsFollowup distinguishes a polling request from a first browser request.
func (request BrowserRegistrationRequest) IsFollowup() bool { return request.followupURL != "" }

// String redacts the URL token and machine-facing identity in diagnostics.
func (BrowserRegistrationRequest) String() string { return "BrowserRegistrationRequest<redacted>" }

// GoString redacts the URL token and machine-facing identity in diagnostics.
func (BrowserRegistrationRequest) GoString() string { return "BrowserRegistrationRequest<redacted>" }

func validBrowserFollowupURL(raw string) bool {
	if len(raw) > 512 {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Scheme != "https" ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		(parsed.Port() != "" && parsed.Port() != "443") {
		return false
	}
	token, ok := strings.CutPrefix(parsed.Path, browserRegistrationPathPrefix)
	if !ok || len(token) != 43 || strings.Contains(token, "/") {
		return false
	}
	_, err = enrollment.DigestPresentedBrowserIntentToken(token)
	return err == nil
}
