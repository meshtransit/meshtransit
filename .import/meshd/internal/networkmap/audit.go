package networkmap

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const auditTokenBytes = 32

// AuditCredentials are opaque, control-issued credentials scoped to one
// network and reporter node. Formatting is deliberately redacted.
type AuditCredentials struct {
	nodeToken    [auditTokenBytes]byte
	networkToken [auditTokenBytes]byte
	networkID    uint64
	nodeID       uint64
}

// NewAuditCredentials structurally validates a pair of signed control-plane
// tokens. The client cannot validate the HMAC; authenticity comes from the
// pinned and encrypted control channel.
func NewAuditCredentials(nodeToken, networkToken string, selfNodeID uint64) (AuditCredentials, error) {
	var credentials AuditCredentials
	if selfNodeID == 0 {
		return credentials, errors.New("networkmap: audit self node id is invalid")
	}
	if err := decodeAuditToken(nodeToken, &credentials.nodeToken); err != nil {
		return AuditCredentials{}, errors.New("networkmap: node audit token is invalid")
	}
	if err := decodeAuditToken(networkToken, &credentials.networkToken); err != nil {
		return AuditCredentials{}, errors.New("networkmap: network audit token is invalid")
	}
	credentials.networkID = binary.BigEndian.Uint64(credentials.nodeToken[0:8])
	credentials.nodeID = binary.BigEndian.Uint64(credentials.nodeToken[8:16])
	networkScope := binary.BigEndian.Uint64(credentials.networkToken[0:8])
	networkNode := binary.BigEndian.Uint64(credentials.networkToken[8:16])
	if credentials.networkID == 0 || credentials.nodeID != selfNodeID ||
		networkScope != credentials.networkID || networkNode != 0 {
		return AuditCredentials{}, errors.New("networkmap: audit token scopes are invalid")
	}

	return credentials, nil
}

func decodeAuditToken(value string, target *[auditTokenBytes]byte) error {
	if len(value) != hex.EncodedLen(auditTokenBytes) {
		return errors.New("token length is invalid")
	}
	decoded, err := hex.Decode(target[:], []byte(value))
	if err != nil || decoded != auditTokenBytes || hex.EncodeToString(target[:]) != value {
		clear(target[:])

		return errors.New("token encoding is invalid")
	}

	return nil
}

// Enabled reports whether a complete credential pair is present.
func (c AuditCredentials) Enabled() bool { return c.networkID != 0 && c.nodeID != 0 }

// NetworkID returns the embedded network scope.
func (c AuditCredentials) NetworkID() uint64 { return c.networkID }

// NodeID returns the embedded reporter scope.
func (c AuditCredentials) NodeID() uint64 { return c.nodeID }

// NodeToken returns the opaque node credential for an authenticated upload.
func (c AuditCredentials) NodeToken() string { return hex.EncodeToString(c.nodeToken[:]) }

// NetworkToken returns the opaque network credential for an authenticated upload.
func (c AuditCredentials) NetworkToken() string { return hex.EncodeToString(c.networkToken[:]) }

func (AuditCredentials) String() string { return "<audit credentials redacted>" }

func (AuditCredentials) GoString() string {
	return "networkmap.AuditCredentials{<redacted>}"
}
