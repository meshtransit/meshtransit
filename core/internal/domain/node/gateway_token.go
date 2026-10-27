package node

import "time"

// maxGatewayTokenID bounds a token's jti: it is part of a primary key.
const maxGatewayTokenID = 128

// GatewayToken is the evidence of the pod token Core verified for a
// Kubernetes gateway's key rotation (K1.1 design §7.2): the gateway Device
// and the trust version it was checked against, the token's jti and when it
// expires. The database records one use of it in the rotation's
// transaction; it never sees the token.
type GatewayToken struct {
	DeviceID     ID
	TrustVersion int64
	JTI          string
	ExpiresAt    time.Time
}

// IsValid reports whether every field is present and the jti is 1 to 128
// printable ASCII characters other than space.
func (token GatewayToken) IsValid() bool {
	if !token.DeviceID.IsValid() || token.TrustVersion < 1 || token.ExpiresAt.IsZero() ||
		len(token.JTI) == 0 || len(token.JTI) > maxGatewayTokenID {
		return false
	}
	for index := range len(token.JTI) {
		if token.JTI[index] < 0x21 || token.JTI[index] > 0x7e {
			return false
		}
	}
	return true
}
