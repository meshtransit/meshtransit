package connectionlog

import (
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
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
	Reason          string
	Forwarded       bool
	WindowSeconds   int
	Bucket          string
	Region          string
	Prefix          string
	SettingsVersion int64
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
