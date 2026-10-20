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
	DeviceExpiresAt    string                 `json:"device_expires_at,omitempty"`
	DeviceExpiry       string                 `json:"device_expiry,omitempty"`
	PeerCount          int                    `json:"peer_count"`
	PolicyRuleCount    int                    `json:"policy_rule_count"`
	PeerPaths          PathStatus             `json:"paths"`
	SubnetRoutes       *SubnetRouteStatus     `json:"subnet_routes,omitempty"`
	SubnetRouter       *SubnetRouterStatus    `json:"subnet_router,omitempty"`
	ExitNode           *ExitNodeStatus        `json:"exit_node,omitempty"`
	Exit               *ExitStatus            `json:"exit,omitempty"`
	PathProbes         *PathProbeStatus       `json:"path_probes,omitempty"`
	Relay              RelayStatus            `json:"relay"`
	NetworkChanges     NetworkChangeStatus    `json:"network_changes"`
	RuntimeRecovery    *RuntimeRecoveryStatus `json:"runtime_recovery,omitempty"`
	Runtime            *RuntimeStatus         `json:"runtime,omitempty"`
	NAT                *NATStatus             `json:"nat,omitempty"`
	PortMapping        *PortMappingStatus     `json:"port_mapping,omitempty"`
	Cloud              *CloudStatus           `json:"cloud,omitempty"`
	CompatibilityNote  string                 `json:"compatibility_note"`
}

// CloudStatus is the instance's public addresses from its cloud provider's
// metadata service. Addresses are present in netcheck results only.
type CloudStatus struct {
	State        string   `json:"state"`
	Platform     string   `json:"platform,omitempty"`
	AddressCount int      `json:"address_count"`
	Addresses    []string `json:"addresses,omitempty"`
	ObservedAt   string   `json:"observed_at,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// PortMappingStatus is the daemon's mapping of its packet port on the local
// gateway. External is present in netcheck results only.
type PortMappingStatus struct {
	State     string `json:"state"`
	Protocol  string `json:"protocol,omitempty"`
	External  string `json:"external_endpoint,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// NATStatus is the daemon's classification of the NAT in front of its
// encrypted packet socket.
type NATStatus struct {
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

// Netcheck is the result of an on-demand NAT classification.
type Netcheck struct {
	APIVersion  string             `json:"api_version"`
	NAT         NATStatus          `json:"nat"`
	PortMapping *PortMappingStatus `json:"port_mapping,omitempty"`
	Cloud       *CloudStatus       `json:"cloud,omitempty"`
}

// PathStatus summarizes the selected transport for visible peers.
type PathStatus struct {
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

// PathProbeStatus contains redacted process-local direct-path diagnostics.
type PathProbeStatus struct {
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

// SubnetRouteStatus is what the node does with the map's subnet routes.
type SubnetRouteStatus struct {
	Requested           int                  `json:"requested"`
	Installed           int                  `json:"installed"`
	RefusedTotal        int                  `json:"refused_total"`
	Refused             []SubnetRouteRefusal `json:"refused,omitempty"`
	Health              string               `json:"health"`
	Error               string               `json:"error,omitempty"`
	UnreachableAnswered uint64               `json:"unreachable_answered"`
	UnreachableLimited  uint64               `json:"unreachable_limited"`
	Sites               []SubnetRouteSite    `json:"sites,omitempty"`
}

// SubnetRouteSite is the router one Site's traffic goes to.
type SubnetRouteSite struct {
	Site       string   `json:"site"`
	Name       string   `json:"name,omitempty"`
	Prefixes   []string `json:"prefixes,omitempty"`
	Router     string   `json:"router,omitempty"`
	RouterName string   `json:"router_name,omitempty"`
	Via        string   `json:"via"`
}

// ExitStatus is the exit node the node sends its Internet traffic to.
type ExitStatus struct {
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
}

// ExitNodeStatus is how the node forwards as an exit node.
type ExitNodeStatus struct {
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

// SubnetRouterStatus is what the node forwards into as a router.
type SubnetRouterStatus struct {
	Sites        int                  `json:"sites"`
	Requested    int                  `json:"requested"`
	Served       int                  `json:"served"`
	RefusedTotal int                  `json:"refused_total"`
	Refused      []SubnetRouteRefusal `json:"refused,omitempty"`
	Health       string               `json:"health"`
	Error        string               `json:"error,omitempty"`
	// SiteHealth is each served Site's measured health.
	SiteHealth []SubnetRouterSiteHealth `json:"site_health,omitempty"`
}

// SubnetRouterSiteHealth is one served Site's health: state ok, degraded
// or failed, and a code.
type SubnetRouterSiteHealth struct {
	Site  string `json:"site"`
	State string `json:"state"`
	Code  string `json:"code"`
}

// SubnetRouteRefusal is one route the host refused, with its reason code.
type SubnetRouteRefusal struct {
	Prefix string `json:"prefix"`
	Reason string `json:"reason"`
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

// Connection reports a down or up request.
type Connection struct {
	APIVersion string `json:"api_version"`
	State      string `json:"state"`
	Changed    bool   `json:"changed"`
}

// Logout reports a logout request.
type Logout struct {
	APIVersion     string `json:"api_version"`
	ProfileID      string `json:"profile_id"`
	State          string `json:"state"`
	AlreadyRemoved bool   `json:"already_removed"`
}

// NodeKeyRotation is the non-secret result of a committed key transition.
type NodeKeyRotation struct {
	APIVersion string `json:"api_version"`
	ProfileID  string `json:"profile_id"`
	State      string `json:"state"`
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
