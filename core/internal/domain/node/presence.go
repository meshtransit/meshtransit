package node

import (
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
}

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

// IsValid reports whether this lease is safe to send to ephemeral storage.
func (lease PresenceLease) IsValid() bool {
	return lease.nodeID.IsValid() && lease.generation > 0 && validReplicaID(lease.replicaID) &&
		lease.ttl >= minimumPresenceTTL && lease.ttl <= maximumPresenceTTL
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
