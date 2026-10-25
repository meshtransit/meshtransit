// Package controlplane holds the protocol-neutral contract between meshd's
// daemon and its control protocol client (MTCP v1): key material, registration outcomes, map stream options, node
// reports and the errors the daemon classifies.
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/dnsdigest"
	"meshtransit.net/shared/policydigest"
	"meshtransit.net/shared/routedigest"
)

var (
	// ErrStopping is the cause meshd's context ends with when the service
	// stops: a subnet router then tells Core it is going away.
	ErrStopping = errors.New("control: meshd is stopping")
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
	// ErrNodeKeyRotationRefused reports a definitive refusal of a node key
	// rotation (mtcp-v1 §6.3): Control did not apply it and the current key
	// stays in use, so the staged key may be discarded.
	ErrNodeKeyRotationRefused = fmt.Errorf("%w: node key rotation refused", ErrRegistration)
	// ErrMachineKeyRetired: Core no longer takes this Kubernetes gateway's
	// machine key (mtcp-v1 §6.7); only an administrator recovers.
	ErrMachineKeyRetired = fmt.Errorf("%w: the gateway's machine key is retired", ErrRegistration)
	// ErrNodeKeyNotCurrent: the gateway's machine key holds another node key
	// now; a staged one may be it.
	ErrNodeKeyNotCurrent = fmt.Errorf("%w: the node key is not the gateway's current key", ErrRegistration)
	// ErrMachineKeyUnbound: no Device holds the machine key.
	ErrMachineKeyUnbound = fmt.Errorf("%w: the machine key is not bound", ErrRegistration)
	// ErrGatewayProofRequired: the machine key is a gateway's, so a session
	// must start with a node key proof; a cluster join completed.
	ErrGatewayProofRequired = fmt.Errorf("%w: the machine key is a gateway's", ErrRegistration)
	// ErrGatewayContested: another holder of the gateway's keys pushed this
	// session out or took a newer timestamp; reconnect within 2 seconds,
	// outside the usual backoff (mtcp-v1 §6.8).
	ErrGatewayContested = fmt.Errorf("%w: the gateway's keys are contested", ErrRegistrationTemporary)
	// ErrGatewayClock: the handshake timestamp ran ahead of Core; the clock
	// offset is corrected, so retry.
	ErrGatewayClock = fmt.Errorf("%w: the clock is ahead of Core", ErrRegistrationTemporary)
	// ErrGatewayProofUnsupported: Core does not take node key proofs yet.
	ErrGatewayProofUnsupported = fmt.Errorf("%w: Core does not take node key proofs", ErrRegistrationTemporary)
	// ErrMachineKeyRotationRefused: Core surely did not apply a machine key
	// rotation; the staged key is dropped.
	ErrMachineKeyRotationRefused = fmt.Errorf("%w: machine key rotation refused", ErrRegistration)
	// ErrNodeKeyExpired indicates that the Device must register again.
	ErrNodeKeyExpired = errors.New("control: node key expired")
	// ErrNetmapRejected indicates a permanent client or registration error.
	ErrNetmapRejected = errors.New("control: map request rejected")
	// ErrNetmapInvalid indicates that a received update failed validation.
	ErrNetmapInvalid = errors.New("control: invalid map update")
	// ErrNetmapConsumer indicates that the product consumer rejected a snapshot.
	ErrNetmapConsumer = errors.New("control: map consumer failed")
	// ErrNetmapAuthorityRevoked indicates that control revoked the Device (a
	// REVOKED or LOGGED_OUT lifecycle). The daemon erases the profile's keys
	// on it, so it must never stand for an ambiguous or transient failure.
	ErrNetmapAuthorityRevoked = errors.New("control: map authority revoked")
	// ErrNetmapAuthorityPaused indicates that control suspended this Device:
	// it keeps its identity and retries until an administrator resumes it.
	ErrNetmapAuthorityPaused = errors.New("control: map authority paused")
	// ErrDeviceNotAuthorized means Core does not accept the profile's current
	// keys as a Device: it was revoked or removed, or never registered.
	ErrDeviceNotAuthorized = errors.New("control: the Device is not authorized")
	// ErrEndpointUpdate indicates that a candidate publication did not complete.
	ErrEndpointUpdate = errors.New("control: endpoint update failed")
)

// Result describes a successful control probe.
type Result struct {
	Protocol       string
	Capability     int
	KeyFingerprint string
	// LinkFingerprint is the same key's ck= form, the one install commands
	// and enrollment links carry (mtcp-v1 §2.1); empty when the protocol
	// has none.
	LinkFingerprint  string
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
	// RegistrationStateAdminApprovalRequired means an administrator must
	// approve a Kubernetes cluster join by the replica's code (mtcp-v1 §6.6).
	RegistrationStateAdminApprovalRequired RegistrationState = "admin_approval_required"
)

// ClusterJoin asks to join a Kubernetes cluster as a gateway replica.
type ClusterJoin struct {
	// JoinKey is the cluster's mtk1 join key; never logged.
	JoinKey string
	// Reported is what the pod says about itself, display only: at most 16
	// fields, keys up to 64 bytes, values up to 256.
	Reported map[string]string
}

func (ClusterJoin) String() string { return "<cluster join redacted>" }

// GoString redacts detailed formatting.
func (ClusterJoin) GoString() string { return "controlplane.ClusterJoin{<redacted>}" }

// LogValue redacts structured logging.
func (ClusterJoin) LogValue() slog.Value { return slog.StringValue("<cluster join redacted>") }

// MarshalJSON keeps the join key out of any JSON.
func (ClusterJoin) MarshalJSON() ([]byte, error) { return []byte(`"<cluster join redacted>"`), nil }

// RejectedError is Core's rejected RegisterResponse: Code is its code in
// lower case (mtcp-v1 §6.1), such as "credential_invalid" or "expired".
type RejectedError struct {
	Code    string
	Message string
}

func (err *RejectedError) Error() string {
	return fmt.Sprintf("%s: %s (%s)", ErrRegistration, err.Code, err.Message)
}

// Unwrap makes a rejection an ErrRegistration.
func (err *RejectedError) Unwrap() error { return ErrRegistration }

// AdminApproval is what a replica needs to print its code.
type AdminApproval struct {
	ClusterID    [16]byte
	RequestID    string
	RequestNonce [32]byte
	ExpiresAt    time.Time
}

// RegisterOptions contains non-persisted inputs for one registration request.
type RegisterOptions struct {
	Hostname          string
	Version           string
	PinnedFingerprint string
	AuthKey           string
	FollowupURL       string
	// ClusterJoin, when set, joins a Kubernetes cluster; JoinWait is how
	// long to wait on the session for the approval before answering pending.
	ClusterJoin *ClusterJoin
	JoinWait    time.Duration
}

// RegistrationResult excludes account data and private material.
type RegistrationResult struct {
	State             RegistrationState
	AuthURL           string
	MachineAuthorized bool
	// Approval is set while a cluster join waits for an administrator.
	Approval *AdminApproval
}

// HostOffer is what the host's local settings offer Core (mtcp-v1 §8.2).
type HostOffer struct {
	// Prefixes are the subnets it offers to forward to as a router.
	Prefixes []netip.Prefix
	// Exit reports that it offers to be an exit node.
	Exit bool
}

// Equal reports whether two offers are the same.
func (offer HostOffer) Equal(other HostOffer) bool {
	return offer.Exit == other.Exit && slices.Equal(offer.Prefixes, other.Prefixes)
}

// NetmapOptions contains stable host facts, the persisted control-key pin,
// and optional streams of node reports.
type NetmapOptions struct {
	// EnableDeviceAliases explicitly advertises the qualified peer
	// translation contract.
	EnableDeviceAliases bool
	// EnableSubnetRoutes advertises that the node takes subnet routes
	// (mtcp-v1 §7.6, routes.subnet.v1).
	EnableSubnetRoutes bool
	// EnableSubnetRouter advertises that the node can forward into Sites
	// (mtcp-v1 §7.6, router.subnet.v1): it takes served routes and reports
	// what it offers and serves.
	EnableSubnetRouter bool
	// EnableExits advertises that the node may send its Internet traffic
	// through Exit Pools (mtcp-v1 §7.7, routes.exit.v1): it takes the
	// pools a rule grants and reports the exit node it uses.
	EnableExits bool
	// EnableExitNode advertises that the node can be an exit node
	// (mtcp-v1 §7.7, router.exit.v1): it reports whether its settings offer
	// to be one, and its exit health.
	EnableExitNode bool
	// EnableDNSForward advertises that the node's resolver applies forward
	// DNS zones (mtcp-v1 §7.3, dns.forward1): routes with resolvers and
	// ports, routes no resolver can serve, and their failure modes.
	EnableDNSForward bool
	// HostOffers, with EnableSubnetRouter or EnableExitNode, carries what the
	// host's local settings offer: the subnets it forwards to and whether it
	// may be an exit node; each offer is sent to Core in a HostinfoReport,
	// again in every new session.
	HostOffers <-chan HostOffer
	// RouteHealth, with EnableSubnetRouter, carries the health of every
	// served Site; each set is sent in a RouteHealthReport when Core takes
	// it (router.health1), again every 10 seconds while not empty.
	RouteHealth <-chan []RouteSiteHealth
	// ExitHealth, with EnableExitNode, carries the health of the Exit Pool
	// the node serves (an empty reference when none); it is sent in the
	// RouteHealthReport when Core takes it (router.health1 and
	// router.exit.v1), again every 10 seconds while the node serves one.
	ExitHealth <-chan RouteExitHealth
	// DNSHealth, with EnableDNSForward, carries how the node's resolver sees
	// the resolvers of the zones it applies, the root zone's first; it is
	// sent in a DnsHealthReport when Core takes it (dns.root1), on change
	// and at least every 5 minutes (mtcp-v1 §8.6).
	DNSHealth <-chan []ResolverHealth
	// RouteSelection, with EnableSubnetRoutes, carries the router this node
	// sends each Site's traffic to; each set is sent in a
	// RouteSelectionReport when Core takes it (routes.selection1), again
	// every 60 seconds while not empty.
	RouteSelection <-chan []RouteSiteSelection
	// ExitSelection, with EnableExits, carries the exit node this node sends
	// its Internet traffic to (an empty pool when it uses none); it goes in
	// the RouteSelectionReport when Core takes it (routes.selection1 and
	// routes.exit.v1).
	ExitSelection <-chan RouteExitSelection
	// AnnounceGoingAway, with EnableSubnetRouter, reports whether a router
	// that stops (its context ends with ErrStopping) tells Core with a last
	// RouteHealthReport; false while a restart is expected.
	AnnounceGoingAway func() bool
	// CaptiveWindows, with EnableExits, lists the captive portal windows
	// that closed and are still to report, oldest first; each goes in a
	// CaptiveWindowReport when Core takes it (captive.audit1), and
	// CaptiveWindowsSent is told which were sent.
	CaptiveWindows     func() []CaptiveWindow
	CaptiveWindowsSent func(ids []string)
	Hostname           string
	Version            string
	PinnedFingerprint  string
	PeerProbePublicKey string
	Candidates         pathdiscovery.Set
	PreferredRelay     int
	HasPreferredRelay  bool
	EndpointUpdates    <-chan EndpointUpdate
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

// RouteHealthState is a served Site's state as its router measures it
// (mtcp-v1 §8.3).
type RouteHealthState int

// The states of mtcp-v1 §8.3.
const (
	RouteHealthOK RouteHealthState = iota + 1
	// RouteHealthDegraded is a warning only.
	RouteHealthDegraded
	RouteHealthFailed
)

// RouteSiteHealth is one served Site's health.
// RouteSelectionReason is why a node sends a Site's traffic to a router
// (mtcp-v1 §8.3).
type RouteSelectionReason int

const (
	// RouteSelectionPrimary is the map's primary.
	RouteSelectionPrimary RouteSelectionReason = iota + 1
	// RouteSelectionLocalFailover is another candidate the node chose while
	// the primary does not answer.
	RouteSelectionLocalFailover
	// RouteSelectionNone means the Site is not served: no router.
	RouteSelectionNone
	// RouteSelectionSticky, for an exit node only (mtcp-v1 §7.7), is the
	// one the node kept using after Core chose another primary.
	RouteSelectionSticky
)

// RouteSiteSelection is the router a node uses for one Site; Router is
// empty with RouteSelectionNone.
type RouteSiteSelection struct {
	Ref    string
	Router string
	Reason RouteSelectionReason
}

// CaptiveWindow is a captive portal window that closed (exit node design
// §17.12): its helper ID (32 hex digits), when meshd saw it open and close,
// and how it ended.
type CaptiveWindow struct {
	ID             string
	Opened, Closed time.Time
	End            CaptiveWindowEnd
}

// CaptiveWindowEnd is how a captive portal window ended.
type CaptiveWindowEnd uint8

const (
	// CaptiveWindowExpired: its time ran out.
	CaptiveWindowExpired CaptiveWindowEnd = iota + 1
	// CaptiveWindowClosed: root closed it, or the host stopped using the
	// exit node.
	CaptiveWindowClosed
	// CaptiveWindowTunnelBack: meshd closed it once the tunnel was back.
	CaptiveWindowTunnelBack
)

// RouteExitSelection is the exit node a node sends its Internet traffic
// to: Pool is empty when it uses none, ExitNode (a device ID) is empty with
// RouteSelectionNone.
type RouteExitSelection struct {
	Pool     string
	ExitNode string
	Reason   RouteSelectionReason
}

type RouteSiteHealth struct {
	Ref   string
	State RouteHealthState
	// Code is a short reason, at most 64 bytes.
	Code string
}

// ResolverState is how the node's resolver sees one resolver (mtcp-v1
// §8.6).
type ResolverState int

// Resolver states.
const (
	ResolverOK ResolverState = iota + 1
	ResolverBroken
	ResolverStopped
	ResolverRefusing
	ResolverIdle
)

// ResolverHealth is one resolver of the zones the node applies; LastOK is
// zero when it has not answered.
type ResolverHealth struct {
	Resolver netip.AddrPort
	State    ResolverState
	LastOK   time.Time
}

// ExitFamilies are the address families an exit node reaches the Internet
// in (mtcp-v1 §7.7); zero is not known.
type ExitFamilies int

// The families of mtcp-v1 §7.7.
const (
	ExitFamiliesV4 ExitFamilies = iota + 1
	ExitFamiliesV6
	ExitFamiliesBoth
)

// RouteExitHealth is an exit node's health of the Exit Pool it serves; an
// empty Ref means it serves none.
type RouteExitHealth struct {
	Ref      string
	State    RouteHealthState
	Code     string
	Families ExitFamilies
}

// EnforcementReport is the evidence of what the packet filter enforces
// (policy digest v1).
type EnforcementReport struct {
	Digest    policydigest.Digest
	Grants    int
	AppliedAt time.Time
	// RouteDigest and RouteEntries cover the served routes the node
	// forwards into (mtcp-v1 §8.4); sent only with router.subnet.v1.
	RouteDigest  routedigest.Digest
	RouteEntries int
	// DNSKnown carries the DNS the host applied (mtcp-v1 §8.4, dns.root1):
	// its DNSDigest over DNSRoutes routes, or DNSReason why it applies none.
	DNSKnown  bool
	DNSDigest dnsdigest.Digest
	DNSRoutes int
	DNSReason string
}

// NetmapHandler consumes one fully validated, defensive network snapshot.
type NetmapHandler func(context.Context, networkmap.Snapshot) error
