package localapi

import (
	"time"

	"github.com/meshtransit/meshd/internal/profile"
	"github.com/meshtransit/meshd/internal/version"
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
	Relay              relayStatus           `json:"relay"`
	NetworkChanges     networkChangeStatus   `json:"network_changes"`
	RuntimeRecovery    runtimeRecoveryStatus `json:"runtime_recovery"`
	Runtime            runtimeStatus         `json:"runtime"`
	CompatibilityNote  string                `json:"compatibility_note"`
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
	Available    bool `json:"available"`
	PeerCount    int  `json:"peer_count"`
	DirectCount  int  `json:"direct_count"`
	RelayCount   int  `json:"relay_count"`
	PendingCount int  `json:"pending_count"`
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
