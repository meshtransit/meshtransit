package localapi

import "time"

const apiVersion = "v1"

// VersionInfo describes the daemon build returned by the local API.
type VersionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Status is the stable v1 daemon status response.
type Status struct {
	APIVersion         string                 `json:"api_version"`
	Daemon             VersionInfo            `json:"daemon"`
	State              string                 `json:"state"`
	DataPlane          string                 `json:"data_plane"`
	DNS                string                 `json:"dns"`
	ActiveProfileID    string                 `json:"active_profile_id"`
	ProfileCount       int                    `json:"profile_count"`
	ControlTrust       string                 `json:"control_trust"`
	Registration       string                 `json:"registration"`
	ControlFingerprint string                 `json:"control_key_fingerprint,omitempty"`
	ControlSession     string                 `json:"control_session"`
	NetmapRevision     uint64                 `json:"netmap_revision"`
	NetworkName        string                 `json:"network_name,omitempty"`
	SelfAddresses      []string               `json:"self_addresses,omitempty"`
	PeerCount          int                    `json:"peer_count"`
	PolicyRuleCount    int                    `json:"policy_rule_count"`
	PeerPaths          PathStatus             `json:"paths"`
	Relay              RelayStatus            `json:"relay"`
	NetworkChanges     NetworkChangeStatus    `json:"network_changes"`
	RuntimeRecovery    *RuntimeRecoveryStatus `json:"runtime_recovery,omitempty"`
	Runtime            *RuntimeStatus         `json:"runtime,omitempty"`
	CompatibilityNote  string                 `json:"compatibility_note"`
}

// PathStatus summarizes the selected transport for visible peers.
type PathStatus struct {
	Available    bool `json:"available"`
	PeerCount    int  `json:"peer_count"`
	DirectCount  int  `json:"direct_count"`
	RelayCount   int  `json:"relay_count"`
	PendingCount int  `json:"pending_count"`
}

// RelayStatus summarizes relay availability without exposing peer endpoints.
type RelayStatus struct {
	Available        bool                `json:"available"`
	HomeRegion       int                 `json:"home_region,omitempty"`
	ActiveRegions    int                 `json:"active_regions"`
	ConnectedRegions int                 `json:"connected_regions"`
	Regions          []RelayRegionStatus `json:"regions,omitempty"`
}

// RelayRegionStatus describes the redacted health of one relay region.
type RelayRegionStatus struct {
	RegionID            int    `json:"region_id"`
	Connected           bool   `json:"connected"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastConnected       string `json:"last_connected,omitempty"`
	LastActivity        string `json:"last_activity,omitempty"`
	LastSend            string `json:"last_send,omitempty"`
	LastFailure         string `json:"last_failure,omitempty"`
}

// NetworkChangeStatus summarizes endpoint refreshes triggered by host network changes.
type NetworkChangeStatus struct {
	Available         bool   `json:"available"`
	Observed          uint64 `json:"observed"`
	EndpointRefreshes uint64 `json:"endpoint_refreshes"`
}

// RuntimeRecoveryStatus summarizes process-local runtime recovery.
type RuntimeRecoveryStatus struct {
	Failures   uint64 `json:"failures"`
	Recoveries uint64 `json:"recoveries"`
	Pending    bool   `json:"pending"`
}

// RuntimeStatus contains bounded aggregate health counters from meshd.
type RuntimeStatus struct {
	Goroutines      int    `json:"goroutines"`
	HeapAllocBytes  uint64 `json:"heap_alloc_bytes"`
	HeapInUseBytes  uint64 `json:"heap_in_use_bytes"`
	HeapObjects     uint64 `json:"heap_objects"`
	StackInUseBytes uint64 `json:"stack_in_use_bytes"`
	SysBytes        uint64 `json:"sys_bytes"`
	GCCycles        uint32 `json:"gc_cycles"`
}

// Profile describes one isolated control-plane identity.
type Profile struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ControlURL string    `json:"control_url"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	IsActive   bool      `json:"is_active"`
}

// Profiles is the stable v1 profile-list response.
type Profiles struct {
	APIVersion string    `json:"api_version"`
	Profiles   []Profile `json:"profiles"`
}

// ControlProbe is the non-secret result of checking the active control server.
type ControlProbe struct {
	APIVersion       string `json:"api_version"`
	ProfileID        string `json:"profile_id"`
	ControlURL       string `json:"control_url"`
	Protocol         string `json:"protocol"`
	Capability       int    `json:"capability"`
	KeyFingerprint   string `json:"control_key_fingerprint"`
	NoiseEstablished bool   `json:"noise_established"`
	NoiseVersion     int    `json:"noise_version"`
}

// CreateProfile contains fields accepted by the daemon create endpoint.
type CreateProfile struct {
	Name       string `json:"name"`
	ControlURL string `json:"control_url"`
}

// ControlTrust is the non-secret result of creating or verifying a pin.
type ControlTrust struct {
	APIVersion    string `json:"api_version"`
	ProfileID     string `json:"profile_id"`
	Fingerprint   string `json:"control_key_fingerprint"`
	AlreadyPinned bool   `json:"already_pinned"`
}

// Login is the non-secret registration state returned by meshd.
type Login struct {
	APIVersion string `json:"api_version"`
	ProfileID  string `json:"profile_id"`
	State      string `json:"state"`
	AuthURL    string `json:"auth_url,omitempty"`
}

type trustControlRequest struct {
	Fingerprint string `json:"fingerprint"`
}

type loginRequest struct {
	AuthKey string `json:"auth_key,omitempty"`
}

type errorResponse struct {
	APIVersion string `json:"api_version"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}
