// Package controlplane holds the protocol-neutral contract between meshd's
// daemon and its control protocol client (MTCP v1): key material, registration outcomes, map stream options, node
// reports and the errors the daemon classifies.
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/policydigest"
)

var (
	// ErrInvalidFingerprint indicates a malformed operator-supplied control
	// key fingerprint.
	ErrInvalidFingerprint = errors.New("control: invalid control key fingerprint")
	// ErrFingerprintMismatch indicates that the operator pin does not match
	// the discovered control key.
	ErrFingerprintMismatch = errors.New("control: control key fingerprint mismatch")
	// ErrControlKeyChanged indicates that discovery no longer matches the
	// persisted control key.
	ErrControlKeyChanged = errors.New("control: pinned control key changed")
	// ErrControlKeyRotated means Core no longer offers the profile's control
	// key but offers the next key the profile staged from an authenticated
	// KeyUpdate: the caller promotes that key and connects again.
	ErrControlKeyRotated = errors.New("control: control key rotated to the staged next key")
	// ErrInvalidMaterial indicates malformed persisted key material.
	ErrInvalidMaterial = errors.New("control: invalid identity material")
	// ErrRegistration indicates a rejected or inconsistent registration.
	ErrRegistration = errors.New("control: registration failed")
	// ErrRegistrationTemporary indicates a retryable transport or server failure.
	ErrRegistrationTemporary = fmt.Errorf("%w: temporarily unavailable", ErrRegistration)
	// ErrNodeKeyExpired indicates that the Device must register again.
	ErrNodeKeyExpired = errors.New("control: node key expired")
	// ErrNetmapRejected indicates a permanent client or registration error.
	ErrNetmapRejected = errors.New("control: map request rejected")
	// ErrNetmapInvalid indicates that a received update failed validation.
	ErrNetmapInvalid = errors.New("control: invalid map update")
	// ErrNetmapConsumer indicates that the product consumer rejected a snapshot.
	ErrNetmapConsumer = errors.New("control: map consumer failed")
	// ErrNetmapAuthorityRevoked indicates that control withdrew the session's
	// authority.
	ErrNetmapAuthorityRevoked = errors.New("control: map authority revoked")
	// ErrNetmapAuthorityPaused indicates that control suspended this Device:
	// it keeps its identity and retries until an administrator resumes it.
	ErrNetmapAuthorityPaused = errors.New("control: map authority paused")
	// ErrEndpointUpdate indicates that a candidate publication did not complete.
	ErrEndpointUpdate = errors.New("control: endpoint update failed")
)

// Result describes a successful control probe.
type Result struct {
	Protocol         string
	Capability       int
	KeyFingerprint   string
	NoiseEstablished bool
	NoiseVersion     int
}

// KeyMaterial contains serialized keys: "privkey:<hex>" for the machine and
// node private keys and "mkey:<hex>" for the control public key. Both
// control protocols use the same bytes, so a profile moves between them
// without registering again. Formatting is always redacted.
type KeyMaterial struct {
	MachinePrivateKey []byte `json:"-"`
	NodePrivateKey    []byte `json:"-"`
	ControlPublicKey  []byte `json:"-"`
}

func (KeyMaterial) String() string { return "<control key material redacted>" }

// GoString redacts detailed formatting.
func (KeyMaterial) GoString() string { return "controlplane.KeyMaterial{<redacted>}" }

// TrustResult is created only after the operator pin and the protocol
// handshake both verify.
type TrustResult struct {
	Fingerprint string
	Material    KeyMaterial
}

// RegistrationState is a stable product-facing registration outcome.
type RegistrationState string

const (
	// RegistrationStateAuthorized means the Device is registered.
	RegistrationStateAuthorized RegistrationState = "authorized"
	// RegistrationStateAuthorizationRequired means a person must approve
	// the Device at AuthURL.
	RegistrationStateAuthorizationRequired RegistrationState = "authorization_required"
)

// RegisterOptions contains non-persisted inputs for one registration request.
type RegisterOptions struct {
	Hostname          string
	Version           string
	PinnedFingerprint string
	AuthKey           string
	FollowupURL       string
}

// RegistrationResult excludes account data and private material.
type RegistrationResult struct {
	State             RegistrationState
	AuthURL           string
	MachineAuthorized bool
}

// NetmapOptions contains stable host facts, the persisted control-key pin,
// and optional streams of node reports.
type NetmapOptions struct {
	// EnableDeviceAliases explicitly advertises the qualified peer
	// translation contract.
	EnableDeviceAliases bool
	Hostname            string
	Version             string
	PinnedFingerprint   string
	PeerProbePublicKey  string
	Candidates          pathdiscovery.Set
	PreferredRelay      int
	HasPreferredRelay   bool
	EndpointUpdates     <-chan EndpointUpdate
	// EnforcementReports, when set, carries what the packet filter enforces;
	// each report is sent to Core and repeated while it stays current.
	EnforcementReports <-chan EnforcementReport
	// PathStats, when set, carries one report per interval of how traffic
	// reached each peer.
	PathStats <-chan PathStatsReport
	// NextControlKey is the staged next control key ("mkey:" encoding), or
	// nil.
	NextControlKey []byte
	// ControlKeysChanged, when set, receives the next control key an
	// authenticated KeyUpdate announces (encoded, or nil when it announces
	// none) whenever that differs from NextControlKey. It stores the key
	// durably before returning; an error ends the session.
	ControlKeysChanged func(ctx context.Context, next []byte) error
	// ConnectionChanged, when set, is called with false when a connected
	// control session is lost (the stream reconnects and the last map stays
	// applied) and with true when a new session has a usable map again.
	ConnectionChanged func(connected bool)
}

// PathKind is how traffic reaches a peer.
type PathKind uint8

const (
	// PathUnknown means no path is installed yet.
	PathUnknown PathKind = iota
	// PathDirect sends straight to the peer.
	PathDirect
	// PathRelay sends through a relay.
	PathRelay
)

// RelayReason explains a relayed path.
type RelayReason uint8

const (
	// RelayReasonNone applies to paths that are not relayed.
	RelayReasonNone RelayReason = iota
	// RelayBootstrap means direct candidates are still being probed.
	RelayBootstrap
	// RelayNoCandidates means the peer offers no direct candidate.
	RelayNoCandidates
	// RelayNoResponse means direct probes went unanswered.
	RelayNoResponse
)

// PeerPathStats is one peer's path over a report interval.
type PeerPathStats struct {
	DeviceID      string
	Path          PathKind
	RelayRegion   int
	RelayReason   RelayReason
	DirectTxBytes uint64
	DirectRxBytes uint64
	RelayTxBytes  uint64
	RelayRxBytes  uint64
}

// PathStatsReport covers one interval (MTCP PathStatsReport).
type PathStatsReport struct {
	IntervalStart time.Time
	Interval      time.Duration
	Peers         []PeerPathStats
}

// EndpointUpdate is one complete candidate set to publish.
type EndpointUpdate struct {
	Candidates        pathdiscovery.Set
	PreferredRelay    int
	HasPreferredRelay bool
	Connectivity      Connectivity
}

// Connectivity is how the node reaches the Internet, reported with its
// endpoints: its NAT classification and its gateway port mapping. It never
// carries addresses.
type Connectivity struct {
	// NATKnown reports a current classification in NAT and NATStep.
	NATKnown      bool
	NAT           disco.NATInfo
	NATStep       uint16
	NATObservedAt time.Time
	// PortMapping is empty when the node does not map ports.
	PortMapping PortMappingState
}

// PortMappingState is the node's gateway mapping, without its address.
type PortMappingState struct {
	Protocol  string // pcp, nat-pmp, upnp or empty
	State     string // off, idle, searching, mapped, double_nat, unavailable, failed
	ExpiresAt time.Time
}

// EnforcementReport is the evidence of what the packet filter enforces
// (policy digest v1).
type EnforcementReport struct {
	Digest    policydigest.Digest
	Grants    int
	AppliedAt time.Time
}

// NetmapHandler consumes one fully validated, defensive network snapshot.
type NetmapHandler func(context.Context, networkmap.Snapshot) error
