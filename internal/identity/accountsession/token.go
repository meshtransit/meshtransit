// Package accountsession owns opaque human Account Session authentication.
package accountsession

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/meshtransit/meshtransit/internal/deployment"
)

const (
	tokenPrefix       = "mtas1"
	tokenSecretBytes  = 32
	tokenEncodedBytes = 43
)

var (
	// ErrInvalidToken reports a malformed or non-canonical bearer token.
	ErrInvalidToken = errors.New("account session: invalid token")
)

// Token is a parsed opaque session bearer. Formatting is always redacted.
type Token struct {
	deploymentID  deployment.ID
	recoveryEpoch int64
	secret        [tokenSecretBytes]byte
}

// GenerateToken prepares fresh OS-CSPRNG bearer material before a write unit.
func GenerateToken(id deployment.ID, epoch int64) (Token, error) {
	if !id.IsValid() || epoch <= 0 {
		return Token{}, ErrInvalidToken
	}
	var secret [tokenSecretBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return Token{}, ErrInvalidToken
	}
	token := Token{deploymentID: id, recoveryEpoch: epoch, secret: secret}
	if !token.IsValid() {
		return Token{}, ErrInvalidToken
	}
	return token, nil
}

// Encoded explicitly releases a bearer only at a trusted confirmed boundary.
// Formatting/JSON/logging never invokes this accessor automatically.
func (token Token) Encoded() string {
	if !token.IsValid() {
		return ""
	}
	return tokenPrefix + "." + token.deploymentID.String() + "." +
		strconv.FormatInt(token.recoveryEpoch, 10) + "." +
		base64.RawURLEncoding.EncodeToString(token.secret[:])
}

// ParseToken validates the versioned Account Session token envelope.
func ParseToken(value string) (Token, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != tokenPrefix {
		return Token{}, ErrInvalidToken
	}
	deploymentID, err := deployment.ParseID(parts[1])
	if err != nil {
		return Token{}, ErrInvalidToken
	}
	recoveryEpoch, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || recoveryEpoch <= 0 ||
		strconv.FormatInt(recoveryEpoch, 10) != parts[2] ||
		len(parts[3]) != tokenEncodedBytes {
		return Token{}, ErrInvalidToken
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(secretBytes) != tokenSecretBytes ||
		base64.RawURLEncoding.EncodeToString(secretBytes) != parts[3] {
		return Token{}, ErrInvalidToken
	}
	var secret [tokenSecretBytes]byte
	copy(secret[:], secretBytes)
	if secret == ([tokenSecretBytes]byte{}) {
		return Token{}, ErrInvalidToken
	}
	return Token{
		deploymentID:  deploymentID,
		recoveryEpoch: recoveryEpoch,
		secret:        secret,
	}, nil
}

// DeploymentID returns the public Deployment qualifier carried by the token.
func (token Token) DeploymentID() deployment.ID { return token.deploymentID }

// RecoveryEpoch returns the recovery fence carried by the token.
func (token Token) RecoveryEpoch() int64 { return token.recoveryEpoch }

// IsValid reports whether the parsed token remains structurally safe.
func (token Token) IsValid() bool {
	return token.deploymentID.IsValid() && token.recoveryEpoch > 0 &&
		token.secret != ([tokenSecretBytes]byte{})
}

// String prevents accidental bearer disclosure through formatting.
func (Token) String() string { return "[REDACTED]" }

// GoString prevents accidental bearer disclosure through detailed formatting.
func (Token) GoString() string { return "accountsession.Token([REDACTED])" }

// LogValue prevents accidental bearer disclosure through structured logs.
func (Token) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func (token Token) secretBytes() [tokenSecretBytes]byte { return token.secret }

func tokenDigestInput(token Token) ([tokenSecretBytes]byte, [16]byte, [8]byte, error) {
	if !token.IsValid() {
		return [tokenSecretBytes]byte{}, [16]byte{}, [8]byte{}, ErrInvalidToken
	}
	secret := token.secretBytes()
	deploymentBytes := token.deploymentID.Bytes()
	var epoch [8]byte
	// recoveryEpoch is positive and int64-bounded by ParseToken/IsValid, so the
	// conversion is exact; gosec cannot propagate that invariant through IsValid.
	//nolint:gosec // G115: every positive int64 is losslessly representable as uint64.
	binary.BigEndian.PutUint64(epoch[:], uint64(token.recoveryEpoch))
	return secret, deploymentBytes, epoch, nil
}
