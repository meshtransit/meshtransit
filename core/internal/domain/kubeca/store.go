package kubeca

import (
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// State is where a stored CA stands in its lifecycle (K1a4 §3.3): next is
// published but does not sign, active signs, retiring is still trusted,
// retired is neither.
type State string

// The states of a stored CA.
const (
	StateNext     State = "next"
	StateActive   State = "active"
	StateRetiring State = "retiring"
	StateRetired  State = "retired"
)

// Reason says why a CA was created or last moved.
type Reason string

// The reasons a CA was created or moved.
const (
	ReasonInitial        Reason = "initial"
	ReasonScheduled      Reason = "scheduled"
	ReasonNameChanged    Reason = "name_changed"
	ReasonAdmin          Reason = "admin"
	ReasonEmergency      Reason = "emergency"
	ReasonCompromise     Reason = "compromise"
	ReasonClusterDeleted Reason = "cluster_deleted"
	ReasonExpired        Reason = "expired"
)

// CreatesCA reports whether a CA may be created for this reason.
func (reason Reason) CreatesCA() bool {
	switch reason {
	case ReasonInitial, ReasonScheduled, ReasonNameChanged, ReasonAdmin, ReasonEmergency, ReasonCompromise:
		return true
	}
	return false
}

// MovesCA reports whether a CA may move for this reason.
func (reason Reason) MovesCA() bool {
	switch reason {
	case ReasonScheduled, ReasonNameChanged, ReasonAdmin, ReasonEmergency, ReasonCompromise, ReasonClusterDeleted,
		ReasonExpired:
		return true
	}
	return false
}

// StoredDataKey is a Network's data key as stored: wrapped by the custody.
// Only the active one seals new CAs; a retired one still opens the CAs it
// sealed.
type StoredDataKey struct {
	ID      publicid.ID
	Version int64
	Wrapped WrappedKey
	Active  bool
}

// StoredCA is a CA as the worker reads it: a root, or an intermediate with
// the root that signed it (IssuerID). SealedKey is nil once the CA no longer
// signs; ActivatedAt and RetiringAt are zero until set.
type StoredCA struct {
	ID             publicid.ID
	Version        int64
	Kind           Kind
	IssuerID       publicid.ID
	State          State
	Reason         Reason
	DataKeyID      publicid.ID
	Certificate    []byte
	ClusterDNSName string
	NotBefore      time.Time
	NotAfter       time.Time
	SealedKey      []byte
	CreatedAt      time.Time
	ActivatedAt    time.Time
	RetiringAt     time.Time
}

// Cluster is a scheduled cluster of a Network with its CAs that are not
// retired. Active is false for a deleted cluster whose CAs remain.
type Cluster struct {
	ID           publicid.ID
	Name         string
	Active       bool
	NextActionAt time.Time
	Failures     int
	CAs          []StoredCA
}

// Network is what the worker decides a Network's CA changes from, read
// under the Network's CA lock. Now is the database's clock.
type Network struct {
	Now           time.Time
	WorkspaceCode string
	NetworkCode   string
	DataKeys      []StoredDataKey
	Clusters      []Cluster
}

// Creation creates a cluster's CA, sealed under the Network's active data
// key: a root, next or active, or an active intermediate signed by the
// active root IssuerID.
type Creation struct {
	Cluster        publicid.ID
	ID             publicid.ID
	Kind           Kind
	IssuerID       publicid.ID
	State          State
	Reason         Reason
	DataKeyID      publicid.ID
	Certificate    []byte
	ClusterDNSName string
	NotBefore      time.Time
	NotAfter       time.Time
	SealedKey      []byte
}

// Move moves a CA, still at Version, forward to To.
type Move struct {
	CA      publicid.ID
	Version int64
	To      State
	Reason  Reason
}

// Step is one CA change: exactly one of Create and Move is set. Steps
// apply in order, each as its own audited change.
type Step struct {
	Create *Creation
	Move   *Move
}

// Schedule sets when the worker next looks at a cluster. Done ends the
// schedule of a deleted cluster with no CA left; Failed counts a failed
// look.
type Schedule struct {
	Cluster publicid.ID
	At      time.Time
	Failed  bool
	Done    bool
}

// Operator names who made a change by hand and the change record that
// allows it (K1a4 §15.4). The zero Operator is the worker itself.
type Operator struct {
	Name      string
	ChangeRef string
}

// IsWorker reports the worker's own change.
func (operator Operator) IsWorker() bool { return operator == Operator{} }

// Valid reports the worker, or an operator with a name and a change record
// of printable ASCII, each at most 128 bytes.
func (operator Operator) Valid() bool {
	return operator.IsWorker() || printable(operator.Name) && printable(operator.ChangeRef)
}

func printable(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < ' ' || value[index] > '~' {
			return false
		}
	}
	return true
}

// Changes are what the worker applies to a Network in one transaction:
// steps first, then schedules, all by Operator.
type Changes struct {
	Steps     []Step
	Schedules []Schedule
	Operator  Operator
}
