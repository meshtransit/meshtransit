package localapi

import (
	"time"

	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/version"
)

const apiVersion = "v1"

type healthResponse struct {
	Status     string `json:"status"`
	APIVersion string `json:"api_version"`
}

type statusResponse struct {
	APIVersion         string                `json:"api_version"`
	Daemon             version.Info          `json:"daemon"`
	State              string                `json:"state"`
	DataPlane          string                `json:"data_plane"`
	DNS                string                `json:"dns"`
	ActiveProfileID    string                `json:"active_profile_id"`
	ProfileCount       int                   `json:"profile_count"`
	ControlTrust       string                `json:"control_trust"`
	Registration       string                `json:"registration"`
	ControlFingerprint string                `json:"control_key_fingerprint,omitempty"`
	ControlSession     string                `json:"control_session"`
	NetmapRevision     uint64                `json:"netmap_revision"`
	NetworkName        string                `json:"network_name,omitempty"`
	SelfAddresses      []string              `json:"self_addresses,omitempty"`
	PeerCount          int                   `json:"peer_count"`
	PolicyRuleCount    int                   `json:"policy_rule_count"`
	PeerPaths          pathStatus            `json:"paths"`
	PathProbes         pathProbeStatus       `json:"path_probes"`
	Relay              relayStatus           `json:"relay"`
	NetworkChanges     networkChangeStatus   `json:"network_changes"`
	RuntimeRecovery    runtimeRecoveryStatus `json:"runtime_recovery"`
	Runtime            runtimeStatus         `json:"runtime"`
	NAT                natStatus             `json:"nat"`
	PortMapping        portMappingStatus     `json:"port_mapping"`
	Cloud              cloudStatus           `json:"cloud"`
	CompatibilityNote  string                `json:"compatibility_note"`
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
