// Package identity persists per-profile control and node identity material.
package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	recordVersion       = 1
	profileIDLength     = 32
	maxKeyTextBytes     = 128
	maxFingerprintBytes = 71
	maxAuthURLBytes     = 4096
)

var (
	// ErrNotFound indicates that a profile has no trusted identity yet.
	ErrNotFound = errors.New("identity: not found")
	// ErrExists indicates that an identity already exists and must not be overwritten.
	ErrExists = errors.New("identity: already exists")
	// ErrInvalid indicates malformed identity state or caller input.
	ErrInvalid = errors.New("identity: invalid")
	// ErrCorrupt indicates that persisted identity bytes failed validation or authentication.
	ErrCorrupt = errors.New("identity: corrupt")
	// ErrUnsupported indicates a protected identity format this build cannot open safely.
	ErrUnsupported = errors.New("identity: unsupported")
	// ErrMigrationRequired indicates readable state that is not protected by the active key.
	ErrMigrationRequired = errors.New("identity: migration required")
)

// Material contains protocol key encodings. It must never be logged, encoded
// into a public API response, or persisted outside Store.
type Material struct {
	MachinePrivateKey []byte `json:"-"`
	NodePrivateKey    []byte `json:"-"`
	ControlPublicKey  []byte `json:"-"`
}

// String prevents accidental disclosure through ordinary formatted logging.
func (Material) String() string { return "<identity material redacted>" }

// GoString prevents accidental disclosure through %#v formatting.
func (Material) GoString() string { return "identity.Material{<redacted>}" }

// Record is the daemon's private per-profile identity state. Secret fields are
// unexported and are available only through an explicit Material call.
type Record struct {
	profileID             string
	machinePrivateKey     string
	nodePrivateKey        string
	controlPublicKey      string
	controlKeyFingerprint string
	pendingAuthURL        string
	isRegistered          bool
	createdAt             time.Time
	updatedAt             time.Time
}

// NewRecord validates newly generated protocol material before persistence.
func NewRecord(
	profileID string,
	material Material,
	controlKeyFingerprint string,
	now time.Time,
) (Record, error) {
	record := Record{
		profileID:             profileID,
		machinePrivateKey:     string(material.MachinePrivateKey),
		nodePrivateKey:        string(material.NodePrivateKey),
		controlPublicKey:      string(material.ControlPublicKey),
		controlKeyFingerprint: controlKeyFingerprint,
		createdAt:             now.UTC(),
		updatedAt:             now.UTC(),
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}

	return record, nil
}

// ProfileID returns the profile this identity belongs to.
func (r Record) ProfileID() string { return r.profileID }

// ControlKeyFingerprint returns the non-secret pinned key fingerprint.
func (r Record) ControlKeyFingerprint() string { return r.controlKeyFingerprint }

// Material returns defensive copies of private protocol material.
func (r Record) Material() Material {
	return Material{
		MachinePrivateKey: []byte(r.machinePrivateKey),
		NodePrivateKey:    []byte(r.nodePrivateKey),
		ControlPublicKey:  []byte(r.controlPublicKey),
	}
}

// PendingAuthURL returns the pending browser registration URL. Treat the value
// as a short-lived secret because its path contains an authorization handle.
func (r Record) PendingAuthURL() string { return r.pendingAuthURL }

// IsRegistered reports whether the last registration response authorized the node.
func (r Record) IsRegistered() bool { return r.isRegistered }

// HasPendingAuth reports whether browser authorization still needs completion.
func (r Record) HasPendingAuth() bool { return r.pendingAuthURL != "" }

// String deliberately excludes all key and browser authorization material.
func (r Record) String() string {
	return fmt.Sprintf(
		"identity.Record{profileID:%q, fingerprint:%q, registered:%t, pending:%t}",
		r.profileID,
		r.controlKeyFingerprint,
		r.isRegistered,
		r.pendingAuthURL != "",
	)
}

// GoString applies the same redaction to %#v formatting.
func (r Record) GoString() string { return r.String() }

func validateRecord(record Record) error {
	if !isProfileID(record.profileID) {
		return fmt.Errorf("%w: profile id has an invalid format", ErrInvalid)
	}
	for name, value := range map[string]string{
		"machine private key": record.machinePrivateKey,
		"node private key":    record.nodePrivateKey,
		"control public key":  record.controlPublicKey,
	} {
		if value == "" || len(value) > maxKeyTextBytes || strings.TrimSpace(value) != value {
			return fmt.Errorf("%w: %s encoding is invalid", ErrInvalid, name)
		}
	}
	if len(record.controlKeyFingerprint) != maxFingerprintBytes ||
		!strings.HasPrefix(record.controlKeyFingerprint, "sha256:") {
		return fmt.Errorf("%w: control key fingerprint is invalid", ErrInvalid)
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(record.controlKeyFingerprint, "sha256:"))
	if err != nil || len(digest) != 32 ||
		"sha256:"+hex.EncodeToString(digest) != record.controlKeyFingerprint {
		return fmt.Errorf("%w: control key fingerprint is not canonical", ErrInvalid)
	}
	if len(record.pendingAuthURL) > maxAuthURLBytes {
		return fmt.Errorf("%w: pending authorization url is too long", ErrInvalid)
	}
	if record.pendingAuthURL != "" {
		parsed, err := url.Parse(record.pendingAuthURL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
			parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%w: pending authorization url is invalid", ErrInvalid)
		}
	}
	if record.isRegistered && record.pendingAuthURL != "" {
		return fmt.Errorf("%w: registered identity cannot have pending authorization", ErrInvalid)
	}
	if record.createdAt.IsZero() || record.updatedAt.IsZero() {
		return fmt.Errorf("%w: identity timestamps cannot be zero", ErrInvalid)
	}
	if record.updatedAt.Before(record.createdAt) {
		return fmt.Errorf("%w: identity was updated before it was created", ErrInvalid)
	}

	return nil
}

func isProfileID(id string) bool {
	if len(id) != profileIDLength {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}

	return true
}
