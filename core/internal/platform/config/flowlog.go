package config

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"regexp"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/shared/key"
)

const (
	envFlowLogCredentialKey   = "MESHTRANSIT_FLOWLOG_CREDENTIAL_KEY"
	envFlowLogCredentialKeyID = "MESHTRANSIT_FLOWLOG_CREDENTIAL_KEY_ID"
)

var flowLogKeyID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// FlowLogConfig is the connection log receiver's side Core needs
// (connection logs design §16b). CredentialKey is the receiver's public
// X25519 key storage secrets are sealed to; Core never holds its private
// half.
type FlowLogConfig struct {
	CredentialKey   *ecdh.PublicKey
	CredentialKeyID string
}

// loadFlowLogConfig is all-or-nothing and only for roles that serve the
// management API.
func loadFlowLogConfig(lookup LookupFunc, role app.Role) (*FlowLogConfig, error) {
	keyText, hasKey := lookup(envFlowLogCredentialKey)
	keyID, hasID := lookup(envFlowLogCredentialKeyID)
	if !hasKey && !hasID {
		return nil, nil
	}
	if !hasKey {
		return nil, settingError(envFlowLogCredentialKey)
	}
	if !hasID || !flowLogKeyID.MatchString(keyID) {
		return nil, settingError(envFlowLogCredentialKeyID)
	}
	if role != app.RoleAPI && role != app.RoleAll {
		return nil, settingError(envFlowLogCredentialKey)
	}
	key, ok := parseX25519PublicKey(keyText)
	if !ok {
		return nil, settingError(envFlowLogCredentialKey)
	}
	return &FlowLogConfig{CredentialKey: key, CredentialKeyID: keyID}, nil
}

// parseX25519PublicKey reads a hex X25519 public key. A low-order point
// would make every secret sealed to it, and every Noise session with it,
// readable: X25519 with it yields all zeros, which crypto/ecdh refuses.
func parseX25519PublicKey(text string) (*ecdh.PublicKey, bool) {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return nil, false
	}
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, false
	}
	probe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, false
	}
	if _, err := probe.ECDH(key); err != nil {
		return nil, false
	}
	return key, true
}

const (
	envFlowTicketSigningKeyFile = "MESHTRANSIT_FLOWLOG_SIGNING_KEY_FILE"
	envFlowTicketNextSigningKey = "MESHTRANSIT_FLOWLOG_NEXT_SIGNING_KEY_FILE"
	envFlowTicketDeploymentID   = "MESHTRANSIT_FLOWLOG_DEPLOYMENT_PUBLIC_ID"
	envFlowTicketReceiverKey    = "MESHTRANSIT_FLOWLOG_RECEIVER_KEY"
)

// FlowTicketConfig lets the control role send nodes FlowTickets
// (connection logs design §16b C26): it signs their tokens and names the
// receiver's Noise key. Without it Core offers no flow.report1.
//
// The signing key files hold a 32-byte Ed25519 seed as 43 base64url
// characters, as the relay authority's do. Tokens are signed with the
// current key; the next is published to the receiver ahead of a rotation,
// and promoting it means swapping the files and restarting. The token
// audience is "meshflow:<deployment ID>".
type FlowTicketConfig struct {
	SigningKeyFile     SecretFile
	NextSigningKeyFile *SecretFile
	Deployment         deployment.ID
	ReceiverKey        *ecdh.PublicKey
}

// String redacts the configuration in generic formatting.
func (FlowTicketConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (FlowTicketConfig) GoString() string { return "config.FlowTicketConfig([REDACTED])" }

// LogValue redacts structured formatting.
func (FlowTicketConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// SigningKeys reads the current and, when configured, next signing keys.
func (c FlowTicketConfig) SigningKeys(ctx context.Context) (key.SigningPrivate, *key.SigningPrivate, error) {
	seed, err := c.SigningKeyFile.readPrivateIdentityKey(ctx)
	defer clear(seed[:])
	if err != nil {
		return key.SigningPrivate{}, nil, settingError(envFlowTicketSigningKeyFile)
	}
	current, err := key.SigningPrivateFromSeed(seed[:])
	if err != nil {
		return key.SigningPrivate{}, nil, settingError(envFlowTicketSigningKeyFile)
	}
	if c.NextSigningKeyFile == nil {
		return current, nil, nil
	}
	nextSeed, err := c.NextSigningKeyFile.readPrivateIdentityKey(ctx)
	defer clear(nextSeed[:])
	if err != nil {
		return key.SigningPrivate{}, nil, settingError(envFlowTicketNextSigningKey)
	}
	next, err := key.SigningPrivateFromSeed(nextSeed[:])
	if err != nil || next.Public() == current.Public() {
		return key.SigningPrivate{}, nil, settingError(envFlowTicketNextSigningKey)
	}
	return current, &next, nil
}

// loadFlowTicketConfig is all-or-nothing (the next key aside) and only for
// roles that serve MTCP.
func loadFlowTicketConfig(lookup LookupFunc, role app.Role) (*FlowTicketConfig, error) {
	keyFile, hasKey := lookup(envFlowTicketSigningKeyFile)
	deploymentText, hasDeployment := lookup(envFlowTicketDeploymentID)
	receiverText, hasReceiver := lookup(envFlowTicketReceiverKey)
	_, hasNext := lookup(envFlowTicketNextSigningKey)
	if !hasKey && !hasDeployment && !hasReceiver && !hasNext {
		return nil, nil
	}
	if !hasKey {
		return nil, settingError(envFlowTicketSigningKeyFile)
	}
	if role != app.RoleControl && role != app.RoleAll {
		return nil, settingError(envFlowTicketSigningKeyFile)
	}
	signing, err := NewSecretFile(keyFile)
	if err != nil {
		return nil, settingError(envFlowTicketSigningKeyFile)
	}
	id, err := deployment.ParseID(deploymentText)
	if !hasDeployment || err != nil {
		return nil, settingError(envFlowTicketDeploymentID)
	}
	receiver, ok := parseX25519PublicKey(receiverText)
	if !hasReceiver || !ok {
		return nil, settingError(envFlowTicketReceiverKey)
	}
	cfg := &FlowTicketConfig{SigningKeyFile: signing, Deployment: id, ReceiverKey: receiver}
	if path, present := lookup(envFlowTicketNextSigningKey); present {
		next, err := NewSecretFile(path)
		if err != nil || path == signing.path {
			return nil, settingError(envFlowTicketNextSigningKey)
		}
		cfg.NextSigningKeyFile = &next
	}
	return cfg, nil
}
