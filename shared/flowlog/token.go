// Package flowlog holds what both Core and the connection log receiver need
// of connection log v1: the token Core signs for a node (flowlog-v1 §3).
package flowlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
)

const (
	tokenMagic  = "MFT1"
	signContext = "meshtransit/flow-token/v1"
	// MaxTokenLifetime bounds expires_at - issued_at.
	MaxTokenLifetime = 15 * time.Minute
	// ClockSkew is how far not_before and expiry may be off the
	// verifier's clock.
	ClockSkew = 2 * time.Minute
	// MaxTokenSize bounds an encoded token.
	MaxTokenSize = 2048
	maxKIDLength = 32
	// MaxAudienceLength bounds the audience, "meshflow:<deployment ID>".
	MaxAudienceLength = 80
	// MaxScopeIDs bounds site, exit pool and cluster IDs together, so
	// every valid claim set fits MaxTokenSize.
	MaxScopeIDs = 64
)

var (
	// ErrInvalidToken reports a token that is malformed or wrongly signed.
	ErrInvalidToken = errors.New("flowlog: invalid token")
	// ErrTokenExpired reports a token outside its validity window.
	ErrTokenExpired = errors.New("flowlog: token expired or not yet valid")
	// ErrUnknownKey reports a token signed with a key the verifier lacks.
	ErrUnknownKey = errors.New("flowlog: unknown signing key")
)

func signedBytes(claims []byte) []byte {
	message := make([]byte, 0, len(signContext)+1+len(claims))
	message = append(message, signContext...)
	message = append(message, 0)
	return append(message, claims...)
}

// SignToken encodes and signs claims with key. Claims must be valid.
func SignToken(claims *flowlogv1.FlowTokenClaims, key ed25519.PrivateKey) ([]byte, error) {
	if err := checkClaims(claims); err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalidToken
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(claims)
	if err != nil || len(encoded) > MaxTokenSize-len(tokenMagic)-2-ed25519.SignatureSize {
		return nil, ErrInvalidToken
	}
	token := make([]byte, 0, len(tokenMagic)+2+len(encoded)+ed25519.SignatureSize)
	token = append(token, tokenMagic...)
	token = binary.BigEndian.AppendUint16(token, uint16(len(encoded))) //nolint:gosec // bounded above
	token = append(token, encoded...)
	return append(token, ed25519.Sign(key, signedBytes(encoded))...), nil
}

// ErrWrongMachineKey reports a token presented under another machine key
// than the one it was issued for.
var ErrWrongMachineKey = errors.New("flowlog: token issued for another machine key")

// Token is a token whose signature, audience and validity are checked, but
// not yet that the sender holds its machine key. The receiver checks it from
// the request header before reading the body (flowlog-v1 §4); the claims are
// reachable only through Claims, with the Noise static key of the request.
type Token struct {
	claims *flowlogv1.FlowTokenClaims
	raw    []byte
}

// VerifyToken checks token's signature with the key its kid names, its
// audience and its validity at now. Revocation of the Device is the caller's.
func VerifyToken(token []byte, keys map[string]ed25519.PublicKey, audience string, now time.Time) (*Token, error) {
	if len(token) > MaxTokenSize || len(token) < len(tokenMagic)+2+ed25519.SignatureSize ||
		string(token[:len(tokenMagic)]) != tokenMagic {
		return nil, ErrInvalidToken
	}
	length := int(binary.BigEndian.Uint16(token[len(tokenMagic):]))
	body := token[len(tokenMagic)+2:]
	if length != len(body)-ed25519.SignatureSize {
		return nil, ErrInvalidToken
	}
	encoded, signature := body[:length], body[length:]
	claims := &flowlogv1.FlowTokenClaims{}
	if err := proto.Unmarshal(encoded, claims); err != nil {
		return nil, ErrInvalidToken
	}
	// Fields this reader does not know are refused rather than ignored.
	if len(claims.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidToken
	}
	key, known := keys[claims.GetKid()]
	if !known || len(key) != ed25519.PublicKeySize {
		return nil, ErrUnknownKey
	}
	if !ed25519.Verify(key, signedBytes(encoded), signature) {
		return nil, ErrInvalidToken
	}
	if err := checkClaims(claims); err != nil {
		return nil, err
	}
	if claims.GetAudience() != audience {
		return nil, ErrInvalidToken
	}
	at := now.UnixMilli()
	skew := ClockSkew.Milliseconds()
	if at+skew < claims.GetNotBeforeMs() || at-skew >= claims.GetExpiresAtMs() {
		return nil, ErrTokenExpired
	}
	return &Token{claims: claims, raw: bytes.Clone(token)}, nil
}

// Claims returns the token's claims when machineKey, the Noise static key
// the request came under, is the one the token was issued for. A leaked
// token is useless without that key.
func (t *Token) Claims(machineKey []byte) (*flowlogv1.FlowTokenClaims, error) {
	if t == nil || len(machineKey) != 32 || subtle.ConstantTimeCompare(t.claims.GetMachineKey(), machineKey) != 1 {
		return nil, ErrWrongMachineKey
	}
	claims, ok := proto.Clone(t.claims).(*flowlogv1.FlowTokenClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func checkClaims(claims *flowlogv1.FlowTokenClaims) error {
	if claims == nil || claims.GetVersion() != 1 || !validKID(claims.GetKid()) ||
		claims.GetAudience() == "" || len(claims.GetAudience()) > MaxAudienceLength || len(claims.GetWorkspaceId()) != 16 || len(claims.GetNetworkId()) != 16 ||
		len(claims.GetDeviceId()) != 16 || len(claims.GetMachineKey()) != 32 || len(claims.GetTokenId()) != 16 ||
		len(claims.GetRoles()) == 0 || claims.GetWindowS() < 60 || claims.GetWindowS() > 300 {
		return ErrInvalidToken
	}
	issued, notBefore, expires := claims.GetIssuedAtMs(), claims.GetNotBeforeMs(), claims.GetExpiresAtMs()
	if issued <= 0 || notBefore < issued || expires <= notBefore || expires-issued > MaxTokenLifetime.Milliseconds() {
		return ErrInvalidToken
	}
	held := map[flowlogv1.FlowTokenClaims_Role]bool{}
	for _, role := range claims.GetRoles() {
		if role == flowlogv1.FlowTokenClaims_ROLE_UNSPECIFIED || flowlogv1.FlowTokenClaims_Role_name[int32(role)] == "" ||
			held[role] {
			return ErrInvalidToken
		}
		held[role] = true
	}
	scoped := []struct {
		ids  [][]byte
		role flowlogv1.FlowTokenClaims_Role
	}{
		{claims.GetSiteIds(), flowlogv1.FlowTokenClaims_ROUTER},
		{claims.GetExitPoolIds(), flowlogv1.FlowTokenClaims_EXIT},
		{claims.GetClusterIds(), flowlogv1.FlowTokenClaims_GATEWAY},
	}
	total := 0
	for _, scope := range scoped {
		// IDs only for a role that has them, and each role with its IDs.
		if (len(scope.ids) > 0) != held[scope.role] {
			return ErrInvalidToken
		}
		seen := map[string]bool{}
		for _, id := range scope.ids {
			if len(id) != 16 || seen[string(id)] {
				return ErrInvalidToken
			}
			seen[string(id)] = true
		}
		total += len(scope.ids)
	}
	if total > MaxScopeIDs {
		return ErrInvalidToken
	}
	return nil
}

// validKID is 1 to 32 bytes of [A-Za-z0-9._-].
func validKID(kid string) bool {
	if kid == "" || len(kid) > maxKIDLength {
		return false
	}
	for _, r := range kid {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !letter && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
