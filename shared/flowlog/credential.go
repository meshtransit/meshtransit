package flowlog

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
)

// Storage providers (connection logs design §10.1).
const (
	ProviderS3 = "aws_s3"
	ProviderR2 = "cloudflare_r2"
)

const credentialInfo = "meshtransit/storage-credential/v1"

var (
	// ErrInvalidCredential reports a credential outside the bounds below.
	ErrInvalidCredential = errors.New("flowlog: invalid storage credential")
	// ErrSealedCredential reports a sealed credential that does not open
	// under its binding.
	ErrSealedCredential = errors.New("flowlog: sealed credential does not open")

	accessKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
	accountIDPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// Both sides spell IDs one way, so a binding cannot differ by case.
	canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	errCredentialJSON = errors.New("flowlog: a storage credential is never encoded")
)

// Credential is a storage secret as the receiver uses it.
type Credential struct {
	AccessKeyID     string
	SecretAccessKey string
}

// CredentialBinding is what a sealed credential is bound to: opening it
// under any other Workspace, credential, version, provider or account fails
// (design §10.1, C24).
type CredentialBinding struct {
	WorkspaceID  string // public UUID, canonical lowercase
	CredentialID string // public UUID, canonical lowercase
	// Version is the credential version the secret was sealed under
	// (sealed_version): renaming the credential or changing its Networks
	// keeps it.
	Version   int64
	Provider  string
	AccountID string // R2 only
}

// Check holds a credential to the bounds Core stores.
func (credential Credential) Check(provider string) error {
	if !accessKeyIDPattern.MatchString(credential.AccessKeyID) || len(credential.SecretAccessKey) == 0 ||
		len(credential.SecretAccessKey) > 256 || strings.ContainsFunc(credential.SecretAccessKey, func(r rune) bool {
		return r < 0x21 || r > 0x7e
	}) {
		return ErrInvalidCredential
	}
	if provider == ProviderR2 && len(credential.AccessKeyID) != 32 {
		return ErrInvalidCredential
	}
	return nil
}

// Suffix is the access key's last four characters, all Core shows.
func (credential Credential) Suffix() string {
	return credential.AccessKeyID[len(credential.AccessKeyID)-4:]
}

func (binding CredentialBinding) check() error {
	if !canonicalUUID.MatchString(binding.WorkspaceID) || !canonicalUUID.MatchString(binding.CredentialID) ||
		binding.Version < 1 {
		return ErrInvalidCredential
	}
	switch binding.Provider {
	case ProviderS3:
		if binding.AccountID != "" {
			return ErrInvalidCredential
		}
	case ProviderR2:
		if !accountIDPattern.MatchString(binding.AccountID) {
			return ErrInvalidCredential
		}
	default:
		return ErrInvalidCredential
	}
	return nil
}

// info is HPKE's info string: the binding, unambiguous field by field.
func (binding CredentialBinding) info() []byte {
	return []byte(strings.Join([]string{
		credentialInfo, binding.WorkspaceID, binding.CredentialID, strconv.FormatInt(binding.Version, 10),
		binding.Provider, binding.AccountID,
	}, "\x00"))
}

// suite is HPKE with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
// ChaCha20-Poly1305 (RFC 9180).
func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.ChaCha20Poly1305() }

// SealCredential seals credential to the receiver's credential key for
// binding. Only that key's holder can open it; Core never can.
func SealCredential(receiver *ecdh.PublicKey, credential Credential, binding CredentialBinding) ([]byte, error) {
	if err := binding.check(); err != nil {
		return nil, err
	}
	if err := credential.Check(binding.Provider); err != nil {
		return nil, err
	}
	public, err := hpke.NewDHKEMPublicKey(receiver)
	if err != nil {
		return nil, fmt.Errorf("flowlog: credential key: %w", err)
	}
	plain := make([]byte, 0, 3+len(credential.AccessKeyID)+len(credential.SecretAccessKey))
	plain = append(plain, byte(len(credential.AccessKeyID))) //nolint:gosec // at most 128, checked above
	plain = append(plain, credential.AccessKeyID...)
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(credential.SecretAccessKey))) //nolint:gosec // ≤ 256
	plain = append(plain, credential.SecretAccessKey...)
	defer clear(plain)
	kdf, aead := suite()
	return hpke.Seal(public, kdf, aead, binding.info(), plain)
}

// OpenCredential opens a sealed credential under its binding.
func OpenCredential(receiver *ecdh.PrivateKey, sealed []byte, binding CredentialBinding) (Credential, error) {
	if err := binding.check(); err != nil {
		return Credential{}, err
	}
	private, err := hpke.NewDHKEMPrivateKey(receiver)
	if err != nil {
		return Credential{}, fmt.Errorf("flowlog: credential key: %w", err)
	}
	kdf, aead := suite()
	plain, err := hpke.Open(private, kdf, aead, binding.info(), sealed)
	if err != nil {
		return Credential{}, ErrSealedCredential
	}
	defer clear(plain)
	if len(plain) < 1 {
		return Credential{}, ErrSealedCredential
	}
	idLength := int(plain[0])
	if len(plain) < 1+idLength+2 {
		return Credential{}, ErrSealedCredential
	}
	secretLength := int(binary.BigEndian.Uint16(plain[1+idLength:]))
	if len(plain) != 1+idLength+2+secretLength {
		return Credential{}, ErrSealedCredential
	}
	credential := Credential{
		AccessKeyID: string(plain[1 : 1+idLength]), SecretAccessKey: string(plain[3+idLength:]),
	}
	if credential.Check(binding.Provider) != nil {
		return Credential{}, ErrSealedCredential
	}
	return credential, nil
}

// String never shows the secret.
func (credential Credential) String() string {
	if len(credential.AccessKeyID) < 4 {
		return "flowlog.Credential([REDACTED])"
	}
	return "flowlog.Credential(…" + credential.Suffix() + ")"
}

// GoString never shows the secret.
func (credential Credential) GoString() string { return credential.String() }

// Format never shows the secret.
func (credential Credential) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(credential.String())) }

// LogValue never shows the secret, whatever the handler.
func (credential Credential) LogValue() slog.Value { return slog.StringValue(credential.String()) }

// MarshalJSON refuses: a credential only ever leaves sealed.
func (Credential) MarshalJSON() ([]byte, error) { return nil, errCredentialJSON }
