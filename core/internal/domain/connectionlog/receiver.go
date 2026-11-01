package connectionlog

import (
	"net/netip"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// What the connection log receiver reads from Core (design §16c, s4c1b).

// MaxReceiverNetworks bounds one page of ReceiverNetworks.
const MaxReceiverNetworks = 5000

// ReceiverRevocationWindow is how far back revoked machine keys are listed:
// the longest token, the clock skew a receiver allows and a margin (C46).
const ReceiverRevocationWindow = 18 * time.Minute

// ReceiverNetwork is a Network with a destination whose Workspace has the
// feature. Enabled reports it takes batches now; the other fields change
// whenever its destination or credential does (C47).
type ReceiverNetwork struct {
	Workspace       workspace.ID
	Network         network.ID
	Enabled         bool
	SettingsVersion int64
	Credential      CredentialID
	SealedVersion   int64
	SealingKeyID    string
	// ExpectedBucketOwner is empty when the credential's account owns it.
	ExpectedBucketOwner string
	// DirectoryRevision is the Network's revision (C59).
	DirectoryRevision int64
}

// ReceiverNetworks is one page, read at GeneratedAt on the database clock.
type ReceiverNetworks struct {
	Networks    []ReceiverNetwork
	GeneratedAt time.Time
}

// Receiver destination reasons (C44).
const (
	ReasonLogging            = "logging"
	ReasonDisabled           = "disabled"
	ReasonFeatureRevoked     = "feature_revoked"
	ReasonNetworkDeleted     = "network_deleted"
	ReasonWorkspaceDeleted   = "workspace_deleted"
	ReasonNetworkSuspended   = "network_suspended"
	ReasonWorkspaceSuspended = "workspace_suspended"
)

// ReceiverDestination is one Network's destination and why it does or does
// not take batches. A deleted Network or Workspace carries no credential.
type ReceiverDestination struct {
	Reason        string
	Forwarded     bool
	WindowSeconds int
	Bucket        string
	Region        string
	Prefix        string
	// ExpectedBucketOwner is empty when the credential's account owns it.
	ExpectedBucketOwner string
	SettingsVersion     int64
	// Credential is the zero ID when the reason is a deletion.
	Credential    CredentialID
	Provider      string
	AccountID     string
	Sealed        []byte
	SealedVersion int64
	SealingKeyID  string
	GeneratedAt   time.Time
}

// ReceiverRevocation is a machine key of a Device that no longer holds.
type ReceiverRevocation struct {
	Network    network.ID
	Device     node.ID
	MachineKey [32]byte
}

// ReceiverRevocations is every revocation within the window.
type ReceiverRevocations struct {
	Revocations []ReceiverRevocation
	GeneratedAt time.Time
}

// MaxReceiverDirectoryDevices bounds one directory: a larger Network's is
// refused, never cut (C61).
const MaxReceiverDirectoryDevices = 100000

// MaxReceiverDeviceNames bounds the tags and the groups one directory Device
// lists; more are cut and flagged (C61).
const MaxReceiverDeviceNames = 64

// Receiver directory Device kinds, states and owner kinds, as the schema
// names them. A Device whose expiry passed reads as expired; a tombstone is
// deleted.
const (
	DeviceKindStandard          = "standard"
	DeviceKindKubernetesGateway = "kubernetes_gateway"
	DeviceStateActive           = "active"
	DeviceStateExpired          = "expired"
	DeviceStateSuspended        = "suspended"
	DeviceStateRevoked          = "revoked"
	DeviceStateDeleted          = "deleted"
	OwnerKindMember             = "member"
	OwnerKindWorkspace          = "workspace"
)

// ReceiverName is a tag's or group's public ID and name.
type ReceiverName struct {
	ID   publicid.ID
	Name string
}

// ReceiverDevice is a live Device, or the 25-hour tombstone of a deleted
// one (ID, kind, state, owner kind and pseudonym only). Pseudonym is a
// random UUID, all zero when the Workspace owns the Device or its owner is
// no longer a member (C60). Tags and Groups index the directory's
// dictionaries.
type ReceiverDevice struct {
	ID             node.ID
	Kind           string
	State          string
	Hostname       string
	Addresses      []netip.Addr
	OwnerKind      string
	Pseudonym      [16]byte
	Tags           []int
	Groups         []int
	NamesTruncated bool
}

// ReceiverSite is a Site's prefixes and routers.
type ReceiverSite struct {
	ID       publicid.ID
	Prefixes []netip.Prefix
	Routers  []node.ID
}

// ReceiverExitPool is an Exit Pool's candidate Devices.
type ReceiverExitPool struct {
	ID         publicid.ID
	Candidates []node.ID
}

// ReceiverDirectory is one Network's directory, read in one snapshot at
// BuiltAt on the database clock (C61).
type ReceiverDirectory struct {
	Revision      int64
	BuiltAt       time.Time
	MeshPrefixes  []netip.Prefix
	AliasPrefixes []netip.Prefix
	Tags          []ReceiverName
	Groups        []ReceiverName
	Devices       []ReceiverDevice
	Sites         []ReceiverSite
	ExitPools     []ReceiverExitPool
}
