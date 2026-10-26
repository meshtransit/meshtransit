package node

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	minimumPresenceTTL = time.Second
	maximumPresenceTTL = 5 * time.Minute
	maximumReplicaID   = 128
)

// ErrInvalidPresenceLease reports an unusable Node session lease.
var ErrInvalidPresenceLease = errors.New("node: invalid presence lease")

// PresenceLease identifies one generation-fenced, replica-owned observation.
// It is ephemeral state and never grants Node or Network authority.
type PresenceLease struct {
	nodeID     ID
	generation int64
	replicaID  string
	ttl        time.Duration
	// holder and machine are set for a Kubernetes gateway only: holder
	// names one Serve, machine is the fingerprint of the session's machine
	// key (K1a1 plan §16.12).
	holder  PresenceHolder
	machine [32]byte
}

// PresenceHolder names one map stream holding a Kubernetes gateway's
// presence: random, never reused.
type PresenceHolder [16]byte

// NewPresenceHolder returns a fresh random holder.
func NewPresenceHolder() (PresenceHolder, error) {
	var holder PresenceHolder
	if _, err := rand.Read(holder[:]); err != nil {
		return PresenceHolder{}, err
	}
	return holder, nil
}

// IsZero reports a holder never set.
func (holder PresenceHolder) IsZero() bool { return holder == PresenceHolder{} }

// String returns the holder in lower-case hex.
func (holder PresenceHolder) String() string { return hex.EncodeToString(holder[:]) }

// NewPresenceLease validates one bounded session-presence lease.
func NewPresenceLease(
	nodeID ID,
	generation int64,
	replicaID string,
	ttl time.Duration,
) (PresenceLease, error) {
	lease := PresenceLease{
		nodeID:     nodeID,
		generation: generation,
		replicaID:  replicaID,
		ttl:        ttl,
	}
	if !lease.IsValid() {
		return PresenceLease{}, ErrInvalidPresenceLease
	}
	return lease, nil
}

// NodeID returns the globally unique public Node identity.
func (lease PresenceLease) NodeID() ID { return lease.nodeID }

// Generation returns the monotonically increasing session generation.
func (lease PresenceLease) Generation() int64 { return lease.generation }

// ReplicaID returns the bounded process identity that owns this observation.
func (lease PresenceLease) ReplicaID() string { return lease.replicaID }

// TTL returns the bounded Redis expiry for this observation.
func (lease PresenceLease) TTL() time.Duration { return lease.ttl }

// WithGateway returns the lease of a Kubernetes gateway's stream: holder
// names the stream, machine is its machine key's fingerprint.
func (lease PresenceLease) WithGateway(holder PresenceHolder, machine [32]byte) (PresenceLease, error) {
	if !lease.IsValid() || holder.IsZero() || machine == ([32]byte{}) {
		return PresenceLease{}, ErrInvalidPresenceLease
	}
	lease.holder, lease.machine = holder, machine
	return lease, nil
}

// Gateway reports a Kubernetes gateway's lease.
func (lease PresenceLease) Gateway() bool { return !lease.holder.IsZero() }

// Holder returns the stream holding a gateway's lease, zero for a Node's.
func (lease PresenceLease) Holder() PresenceHolder { return lease.holder }

// MachineFingerprint returns a gateway's machine key fingerprint, zero for
// a Node's.
func (lease PresenceLease) MachineFingerprint() [32]byte { return lease.machine }

// IsValid reports whether this lease is safe to send to ephemeral storage.
func (lease PresenceLease) IsValid() bool {
	return lease.nodeID.IsValid() && lease.generation > 0 && validReplicaID(lease.replicaID) &&
		lease.ttl >= minimumPresenceTTL && lease.ttl <= maximumPresenceTTL &&
		lease.holder.IsZero() == (lease.machine == [32]byte{})
}

func validReplicaID(value string) bool {
	if len(value) == 0 || len(value) > maximumReplicaID || strings.TrimSpace(value) != value ||
		!asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' &&
			character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}
