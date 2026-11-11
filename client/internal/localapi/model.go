package localapi

import (
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/version"
)

const apiVersion = "v1"

type healthResponse struct {
	Status     string `json:"status"`
	APIVersion string `json:"api_version"`
}

type statusResponse struct {
	APIVersion      string       `json:"api_version"`
	Daemon          version.Info `json:"daemon"`
	State           string       `json:"state"`
	DataPlane       string       `json:"data_plane"`
	DNS             string       `json:"dns"`
	DNSError        string       `json:"dns_error,omitempty"`
	ActiveProfileID string       `json:"active_profile_id"`
	ProfileCount    int          `json:"profile_count"`
	ControlTrust    string       `json:"control_trust"`
	Registration    string       `json:"registration"`
	// Disconnected: meshctl down keeps meshd off the network until up.
	Disconnected       bool     `json:"disconnected,omitempty"`
	ControlFingerprint string   `json:"control_key_fingerprint,omitempty"`
	ControlSession     string   `json:"control_session"`
	NetmapRevision     uint64   `json:"netmap_revision"`
	NetworkName        string   `json:"network_name,omitempty"`
	SelfAddresses      []string `json:"self_addresses,omitempty"`
	// DeviceExpiresAt is the Device's expiry (RFC 3339); omitted before a
	// map arrives and for a Device that never expires.
	DeviceExpiresAt string `json:"device_expires_at,omitempty"`
	// DeviceExpiry is unknown, never, ok, soon (14 days or less), imminent
	// (a day or less) or expired.
	DeviceExpiry    string             `json:"device_expiry"`
	PeerCount       int                `json:"peer_count"`
	PolicyRuleCount int                `json:"policy_rule_count"`
	PeerPaths       pathStatus         `json:"paths"`
	SubnetRoutes    subnetRouteStatus  `json:"subnet_routes"`
	SubnetRouter    subnetRouterStatus `json:"subnet_router"`
	ExitNode        exitNodeStatus     `json:"exit_node"`
	Exit            *exitStatus        `json:"exit,omitempty"`
	// KubernetesClusters are the clusters the node may reach (mtcp-v1
	// §7.11); omitted when it does not take them.
	KubernetesClusters []kubernetesClusterStatus `json:"kubernetes_clusters,omitempty"`
	Captive            *captiveStatus            `json:"captive,omitempty"`
	// ConnectionLogs is shown while the Network logs this node's
	// connections (connection logs design §7); omitted when off.
	ConnectionLogs    *connectionLogStatus  `json:"connection_logs,omitempty"`
	PathProbes        pathProbeStatus       `json:"path_probes"`
	Relay             relayStatus           `json:"relay"`
	NetworkChanges    networkChangeStatus   `json:"network_changes"`
	RuntimeRecovery   runtimeRecoveryStatus `json:"runtime_recovery"`
	Runtime           runtimeStatus         `json:"runtime"`
	NAT               natStatus             `json:"nat"`
	PortMapping       portMappingStatus     `json:"port_mapping"`
	Cloud             cloudStatus           `json:"cloud"`
	CompatibilityNote string                `json:"compatibility_note"`
}

// kubernetesClusterStatus is one cluster the node may reach: state is
// pending, trusted, incomplete, invalid or unavailable; roots are SHA-256
// fingerprints (hex), never DER.
// connectionLogStatus is connection logging while it is on.
type connectionLogStatus struct {
	On        bool   `json:"on"`
	Pending   uint64 `json:"pending"`
	LastSent  string `json:"last_sent,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type kubernetesClusterStatus struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	DNSName       string   `json:"dns_name,omitempty"`
	TLSServerName string   `json:"tls_server_name,omitempty"`
	State         string   `json:"state"`
	Roots         []string `json:"root_fingerprints,omitempty"`
	RootsExcluded int      `json:"roots_excluded,omitempty"`
	// HeldUntil is when what meshd holds stops counting while Core cannot
	// say (RFC 3339); empty otherwise.
	HeldUntil string `json:"held_until,omitempty"`
	// CAFile is the cluster's CA file kubectl reads; CAFileState is
	// current, withheld, stale, expired, missing or error (K1e design §3.4).
	CAFile       string `json:"ca_file,omitempty"`
	CAFileState  string `json:"ca_file_state,omitempty"`
	CAFileReason string `json:"ca_file_reason,omitempty"`
}

// cloudStatus is the wire form of the instance's cloud public addresses.
// The addresses appear in netcheck responses only.
type cloudStatus struct {
	State        string   `json:"state"`
	Platform     string   `json:"platform,omitempty"`
	AddressCount int      `json:"address_count"`
	Addresses    []string `json:"addresses,omitempty"`
	ObservedAt   string   `json:"observed_at,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// portMappingStatus is the wire form of the daemon's port mapping. The
// external endpoint appears in netcheck responses only.
type portMappingStatus struct {
	State     string `json:"state"`
	Protocol  string `json:"protocol,omitempty"`
	External  string `json:"external_endpoint,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// natStatus is the wire form of the daemon's NAT classification
// (docs/protocol/nat-classification.md).
type natStatus struct {
	State           string `json:"state"`
	Mapping         string `json:"mapping,omitempty"`
	Filtering       string `json:"filtering,omitempty"`
	Allocation      string `json:"allocation,omitempty"`
	SequentialStep  uint16 `json:"sequential_step,omitempty"`
	Difficulty      string `json:"difficulty,omitempty"`
	PublicEndpoint  string `json:"public_endpoint,omitempty"`
	ServersAnswered int    `json:"servers_answered,omitempty"`
	ObservedAt      string `json:"observed_at,omitempty"`
	Error           string `json:"error,omitempty"`
}

type netcheckResponse struct {
	APIVersion  string            `json:"api_version"`
	NAT         natStatus         `json:"nat"`
	PortMapping portMappingStatus `json:"port_mapping"`
	Cloud       cloudStatus       `json:"cloud"`
}

// subnetRouteStatus is what the node does with the map's subnet routes.
// Health is route_conflict_local when a route overlapped a network the host
// reaches itself, route_install_failed when the helper failed, else ok.
type subnetRouteStatus struct {
	Requested           int                  `json:"requested"`
	Installed           int                  `json:"installed"`
	RefusedTotal        int                  `json:"refused_total"`
	Refused             []subnetRouteRefusal `json:"refused,omitempty"`
	Health              string               `json:"health"`
	Error               string               `json:"error,omitempty"`
	UnreachableAnswered uint64               `json:"unreachable_answered"`
	UnreachableLimited  uint64               `json:"unreachable_limited"`
	// Sites is the router each Site's traffic goes to.
	Sites []subnetRouteSite `json:"sites,omitempty"`
}

// subnetRouteSite is the router one Site's traffic goes to: via primary
// (Core's choice), local_failover (another router this node chose while
// the primary does not answer) or none.
type subnetRouteSite struct {
	Site       string   `json:"site"`
	Name       string   `json:"name,omitempty"`
	Prefixes   []string `json:"prefixes,omitempty"`
	Router     string   `json:"router,omitempty"`
	RouterName string   `json:"router_name,omitempty"`
	Via        string   `json:"via"`
}

// subnetRouterStatus is what the node forwards into as a router. Health is
// prefix_not_advertised when Core asked for a subnet the host does not
// offer, route_forwarding_failed when the helper failed, else ok.
type subnetRouterStatus struct {
	Sites        int                  `json:"sites"`
	Requested    int                  `json:"requested"`
	Served       int                  `json:"served"`
	RefusedTotal int                  `json:"refused_total"`
	Refused      []subnetRouteRefusal `json:"refused,omitempty"`
	Health       string               `json:"health"`
	Error        string               `json:"error,omitempty"`
	// SiteHealth is each served Site's measured health (design §6.5).
	SiteHealth []subnetRouterSiteHealth `json:"site_health,omitempty"`
}

// exitNodeStatus is how the node forwards as an exit node (exit node design
// §8): the served pool, the limits the host applies or why it does not
// forward, and the pool's measured health.
type exitNodeStatus struct {
	Pool                 string `json:"pool,omitempty"`
	Serving              bool   `json:"serving"`
	Refused              string `json:"refused,omitempty"`
	ConntrackPerConsumer int    `json:"conntrack_per_consumer,omitempty"`
	SMTPAllowed          bool   `json:"smtp_allowed"`
	MaxConsumers         int    `json:"max_consumers,omitempty"`
	State                string `json:"state,omitempty"`
	Code                 string `json:"code,omitempty"`
	Families             string `json:"families,omitempty"`
	Error                string `json:"error,omitempty"`
}

// exitStatus is the exit node the node sends its Internet traffic to
// (exit node design §9): what the host's settings ask, the pool and exit
// node used and why, and whether the helper routes the Internet into the
// mesh behind its kill switch or why not.
type exitStatus struct {
	Use          string `json:"use"`
	Pool         string `json:"pool,omitempty"`
	PoolName     string `json:"pool_name,omitempty"`
	ExitNode     string `json:"exit_node,omitempty"`
	ExitNodeName string `json:"exit_node_name,omitempty"`
	Via          string `json:"via"`
	IPv6         bool   `json:"ipv6"`
	Routing      bool   `json:"routing"`
	Refused      string `json:"refused,omitempty"`
	Error        string `json:"error,omitempty"`
	// Tampered: the helper installed the exit routes again lately because
	// another program changed them.
	Tampered bool `json:"tampered,omitempty"`
	// Pending are exit nodes added to the pool that wait for meshctl exit
	// approve, by device ID and name.
	Pending      []string `json:"pending,omitempty"`
	PendingNames []string `json:"pending_names,omitempty"`
	PendingPool  string   `json:"pending_pool,omitempty"`
	// CaptiveOff: the pool turns captive portal windows off.
	CaptiveOff bool `json:"captive_off,omitempty"`
}

// exitApprovalRequest names the exit nodes (device IDs) or pool (its
// reference) to approve, as status listed them.
type exitApprovalRequest struct {
	IDs []string `json:"ids"`
}

// exitApprovalResponse names the exit nodes just approved.
type exitApprovalResponse struct {
	APIVersion string   `json:"api_version"`
	Pool       string   `json:"pool"`
	Approved   []string `json:"approved"`
}

type subnetRouterSiteHealth struct {
	Site  string `json:"site"`
	State string `json:"state"`
	Code  string `json:"code"`
}

type subnetRouteRefusal struct {
	Prefix string `json:"prefix"`
	Reason string `json:"reason"`
}

type networkChangeStatus struct {
	Available         bool   `json:"available"`
	Observed          uint64 `json:"observed"`
	EndpointRefreshes uint64 `json:"endpoint_refreshes"`
}

type runtimeRecoveryStatus struct {
	Failures   uint64 `json:"failures"`
	Recoveries uint64 `json:"recoveries"`
	Pending    bool   `json:"pending"`
}

type runtimeStatus struct {
	Goroutines      int    `json:"goroutines"`
	HeapAllocBytes  uint64 `json:"heap_alloc_bytes"`
	HeapInUseBytes  uint64 `json:"heap_in_use_bytes"`
	HeapObjects     uint64 `json:"heap_objects"`
	StackInUseBytes uint64 `json:"stack_in_use_bytes"`
	SysBytes        uint64 `json:"sys_bytes"`
	GCCycles        uint32 `json:"gc_cycles"`
}

type pathStatus struct {
	Available                 bool   `json:"available"`
	PeerCount                 int    `json:"peer_count"`
	DirectCount               int    `json:"direct_count"`
	RelayCount                int    `json:"relay_count"`
	PendingCount              int    `json:"pending_count"`
	RelayBootstrapCount       uint64 `json:"relay_bootstrap_count"`
	DirectPromotionCount      uint64 `json:"direct_promotion_count"`
	RelayFallbackCount        uint64 `json:"relay_fallback_count"`
	LastDirectPromotionMillis int64  `json:"last_direct_promotion_ms"`
	MaxDirectPromotionMillis  int64  `json:"max_direct_promotion_ms"`
	// InactiveCount counts map peers WireGuard does not hold (lazy peers);
	// the lazy counters count installations, evictions and dropped requests.
	InactiveCount       int    `json:"inactive_count"`
	LazyActivationCount uint64 `json:"lazy_activation_count"`
	LazyEvictionCount   uint64 `json:"lazy_eviction_count"`
	LazyDroppedCount    uint64 `json:"lazy_dropped_count"`
}

type pathProbeStatus struct {
	Available                    bool   `json:"available"`
	MapActivations               uint64 `json:"map_activations"`
	ActivationPreserved          uint64 `json:"activation_preserved"`
	ActivationRetired            uint64 `json:"activation_retired"`
	AuthorityPeerChanges         uint64 `json:"authority_peer_changes"`
	AuthorityNodeKeyChanges      uint64 `json:"authority_node_key_changes"`
	AuthorityDiscoveryKeyChanges uint64 `json:"authority_discovery_key_changes"`
	AuthorityEndpointChanges     uint64 `json:"authority_endpoint_changes"`
	SocketChanges                uint64 `json:"socket_changes"`
	PendingInvalidated           uint64 `json:"pending_invalidated"`
	RoundsStarted                uint64 `json:"rounds_started"`
	RoundsCompleted              uint64 `json:"rounds_completed"`
	ProbeAttempts                uint64 `json:"probe_attempts"`
	ProbesStarted                uint64 `json:"probes_started"`
	ProbesSent                   uint64 `json:"probes_sent"`
	ProbeStartFailures           uint64 `json:"probe_start_failures"`
	ProbeSendFailures            uint64 `json:"probe_send_failures"`
	DatagramDrops                uint64 `json:"datagram_drops"`
	AuthenticatedPings           uint64 `json:"authenticated_pings"`
	PingRateLimited              uint64 `json:"ping_rate_limited"`
	PongsSent                    uint64 `json:"pongs_sent"`
	PongSendFailures             uint64 `json:"pong_send_failures"`
	AuthenticatedPongs           uint64 `json:"authenticated_pongs"`
	ProbeCompletions             uint64 `json:"probe_completions"`
	CompletionRejections         uint64 `json:"completion_rejections"`
	ObservationsQueued           uint64 `json:"observations_queued"`
	ObservationDrops             uint64 `json:"observation_drops"`
	ObservationsAccepted         uint64 `json:"observations_accepted"`
	ObservationRejected          uint64 `json:"observations_rejected"`
	DirectExpirations            uint64 `json:"direct_expirations"`
	CallMeMaybeSent              uint64 `json:"call_me_maybe_sent"`
	CallMeMaybeAccepted          uint64 `json:"call_me_maybe_accepted"`
	PeerReflexiveLearned         uint64 `json:"peer_reflexive_learned"`
}

type relayStatus struct {
	Available        bool                `json:"available"`
	HomeRegion       int                 `json:"home_region,omitempty"`
	ActiveRegions    int                 `json:"active_regions"`
	ConnectedRegions int                 `json:"connected_regions"`
	Regions          []relayRegionStatus `json:"regions,omitempty"`
}

type relayRegionStatus struct {
	RegionID            int    `json:"region_id"`
	Connected           bool   `json:"connected"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastConnected       string `json:"last_connected,omitempty"`
	LastActivity        string `json:"last_activity,omitempty"`
	LastSend            string `json:"last_send,omitempty"`
	LastFailure         string `json:"last_failure,omitempty"`
}

type profileResponse struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ControlURL string    `json:"control_url"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	IsActive   bool      `json:"is_active"`
	// State is the profile's state (profile list only), its own enum:
	// registered, signed_out, authorization_required, unregistered,
	// untrusted (control key not pinned) or unreadable (identity damaged).
	State string `json:"state,omitempty"`
	// Identity is the account's names the profile's map last carried
	// (mtcp-v1 §7.13, S4b §4.2); absent when meshd has none.
	Identity *profileIdentity `json:"identity,omitempty"`
	// Hostname is the profile's Device's name, to tell apart accounts with
	// every other name equal.
	Hostname string `json:"hostname,omitempty"`
	// Removed is set once meshd learned Core removed the profile's Device:
	// signing in again adds a new one.
	Removed bool `json:"removed,omitempty"`
	// CanCancel is set on an added account that never held a Device and
	// waits for its first approval: DELETE /v1/accounts/{id} takes it.
	CanCancel bool `json:"can_cancel,omitempty"`
}

// profileIdentity is the account's names (ownership: member or workspace;
// owner empty for a Workspace's Device).
type profileIdentity struct {
	Network   string `json:"network"`
	Workspace string `json:"workspace"`
	Ownership string `json:"ownership"`
	Owner     string `json:"owner,omitempty"`
	// OwnerEmail is the owner's verified email (S4c §4); absent until a map
	// carried one, and never for a Workspace's Device.
	OwnerEmail string `json:"owner_email,omitempty"`
}

// withDisplay adds what meshd keeps for the profile's display.
func (response profileResponse) withDisplay(display daemon.Display, found, canCancel bool) profileResponse {
	response.CanCancel = canCancel
	if !found {
		return response
	}
	response.Hostname, response.Removed = display.Hostname, display.RemovedAt != nil
	if display.Network != "" && display.Workspace != "" && display.Ownership != "" {
		response.Identity = &profileIdentity{
			Network: display.Network, Workspace: display.Workspace,
			Ownership: display.Ownership, Owner: display.Owner, OwnerEmail: display.OwnerEmail,
		}
	}
	return response
}

// cancelAccountResponse is DELETE /v1/accounts/{id}: the profile removed,
// what became of its Device, and the profile now in use.
type cancelAccountResponse struct {
	APIVersion string          `json:"api_version"`
	Profile    profileResponse `json:"profile"`
	Device     string          `json:"device"`
	Active     profileResponse `json:"active"`
}

// stopSignInRequest names the profile whose pending approval to drop.
type stopSignInRequest struct {
	ProfileID string `json:"profile_id"`
}

// stopSignInResponse is POST /v1/login/stop.
type stopSignInResponse struct {
	APIVersion string `json:"api_version"`
	ProfileID  string `json:"profile_id"`
}

type profilesResponse struct {
	APIVersion string            `json:"api_version"`
	Profiles   []profileResponse `json:"profiles"`
}

type controlProbeResponse struct {
	APIVersion       string `json:"api_version"`
	ProfileID        string `json:"profile_id"`
	ControlURL       string `json:"control_url"`
	Protocol         string `json:"protocol"`
	Capability       int    `json:"capability"`
	KeyFingerprint   string `json:"control_key_fingerprint"`
	NoiseEstablished bool   `json:"noise_established"`
	NoiseVersion     int    `json:"noise_version"`
}

type addAccountRequest struct {
	// Name is optional: "<name in use> N" when empty.
	Name string `json:"name"`
}

type addAccountResponse struct {
	APIVersion string          `json:"api_version"`
	Profile    profileResponse `json:"profile"`
	Previous   profileResponse `json:"previous"`
}

type createProfileRequest struct {
	Name       string `json:"name"`
	ControlURL string `json:"control_url"`
}

type trustControlRequest struct {
	Fingerprint string `json:"fingerprint"`
}

type trustControlResponse struct {
	APIVersion    string `json:"api_version"`
	ProfileID     string `json:"profile_id"`
	Fingerprint   string `json:"control_key_fingerprint"`
	AlreadyPinned bool   `json:"already_pinned"`
}

type loginRequest struct {
	AuthKey string `json:"auth_key,omitempty"`
}

type loginResponse struct {
	APIVersion string `json:"api_version"`
	ProfileID  string `json:"profile_id"`
	State      string `json:"state"`
	AuthURL    string `json:"auth_url,omitempty"`
}

type nodeKeyRotationResponse struct {
	APIVersion string `json:"api_version"`
	ProfileID  string `json:"profile_id"`
	State      string `json:"state"`
}

type connectionResponse struct {
	APIVersion string `json:"api_version"`
	State      string `json:"state"`
	Changed    bool   `json:"changed"`
}

type logoutResponse struct {
	APIVersion     string `json:"api_version"`
	ProfileID      string `json:"profile_id"`
	State          string `json:"state"`
	AlreadyRemoved bool   `json:"already_removed"`
}

type profileRemovalResponse struct {
	APIVersion string          `json:"api_version"`
	Profile    profileResponse `json:"profile"`
	// Device is removed, already_removed, none, pending or left (--local).
	Device string `json:"device"`
}

type errorResponse struct {
	APIVersion string `json:"api_version"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func mapProfile(item profile.Profile, activeID string) profileResponse {
	return profileResponse{
		ID:         item.ID,
		Name:       item.Name,
		ControlURL: item.ControlURL,
		CreatedAt:  item.CreatedAt,
		UpdatedAt:  item.UpdatedAt,
		IsActive:   item.ID == activeID,
	}
}

// captiveStatus is a captive portal found while the host uses an exit node:
// suspected, portal or open, the sign-in page the network named, and since
// when; for a window root holds open, when it ends and the interface.
type captiveStatus struct {
	State     string `json:"state"`
	URL       string `json:"url,omitempty"`
	Since     string `json:"since,omitempty"`
	Until     string `json:"until,omitempty"`
	Interface string `json:"interface,omitempty"`
}

// captiveCheckResponse answers a captive portal window check.
type captiveCheckResponse struct {
	APIVersion string `json:"api_version"`
}
