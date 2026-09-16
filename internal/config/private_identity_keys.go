package config

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"time"
)

const privateIdentityKeyTimeout = 5 * time.Second

// ResidentKeyFile binds one explicit purpose-owned generation to an opaque file.
// It is not an environment setting or permission to enable public SSO.
type ResidentKeyFile struct {
	ID   string
	File SecretFile
}

// PrivateIdentityKeyOptions names all purposes; only the two previous keys may
// be absent. No constructor reads files or generates replacement keys.
type PrivateIdentityKeyOptions struct {
	Initiation, Capture, Continuation, ManagementCSRF ResidentKeyFile
	TransactionDigest, VerifierEncryption             ResidentKeyFile
	SubjectActive, ProviderSession, SessionActive     ResidentKeyFile
	Idempotency, RateLimit                            ResidentKeyFile
	SubjectPrevious, SessionPrevious                  *ResidentKeyFile
}

// PrivateIdentityKeyFiles owns a validated immutable 11–13-purpose profile.
// Constructors copy optional references; Load always revalidates file custody.
type PrivateIdentityKeyFiles struct {
	keys [13]ResidentKeyFile
}

// ResidentKeyMaterial is a deliberate resident-construction input. Consumers
// copy its bytes and clear the complete owned candidate after construction.
type ResidentKeyMaterial struct {
	ID    string
	Bytes [32]byte
}

// PrivateIdentityKeyMaterial is released only after all current/previous
// purposes pass file and material checks. Clear is exclusive caller ownership,
// not concurrent mutation or a guarantee of Go heap/core-dump zeroization.
type PrivateIdentityKeyMaterial struct {
	Initiation, Capture, Continuation, ManagementCSRF ResidentKeyMaterial
	TransactionDigest, VerifierEncryption             ResidentKeyMaterial
	SubjectActive, ProviderSession, SessionActive     ResidentKeyMaterial
	Idempotency, RateLimit                            ResidentKeyMaterial
	SubjectPrevious, SessionPrevious                  *ResidentKeyMaterial
}

// NewPrivateIdentityKeyFiles rejects missing or aliased references before any
// effect. This private profile narrows IDs without changing existing contracts.
func NewPrivateIdentityKeyFiles(options PrivateIdentityKeyOptions) (*PrivateIdentityKeyFiles, error) {
	files := &PrivateIdentityKeyFiles{keys: [13]ResidentKeyFile{
		options.Initiation, options.Capture, options.Continuation, options.ManagementCSRF,
		options.TransactionDigest, options.VerifierEncryption, options.SubjectActive,
		options.ProviderSession, options.SessionActive, options.Idempotency, options.RateLimit,
	}}
	if options.SubjectPrevious != nil {
		if *options.SubjectPrevious == (ResidentKeyFile{}) {
			return nil, ErrInvalid
		}
		files.keys[11] = *options.SubjectPrevious
	}
	if options.SessionPrevious != nil {
		if *options.SessionPrevious == (ResidentKeyFile{}) {
			return nil, ErrInvalid
		}
		files.keys[12] = *options.SessionPrevious
	}
	for index, key := range files.keys {
		if index >= 11 && key == (ResidentKeyFile{}) {
			continue
		}
		validPath := len(key.File.path) <= 4096 && validateFilePath(key.File.path) == nil
		if !validPrivateIdentityKeyID(key.ID) || !validPath {
			return nil, ErrInvalid
		}
		for _, other := range files.keys[:index] {
			if key.ID == other.ID || key.File.path == other.File.path {
				return nil, ErrInvalid
			}
		}
	}
	return files, nil
}

// Load reads one complete candidate with a five-second caller-clamped context.
// No partial key material or raw filesystem error crosses this boundary. Local
// filesystem syscalls cannot be preempted by context; use trusted local mounts.
func (files *PrivateIdentityKeyFiles) Load(ctx context.Context) (*PrivateIdentityKeyMaterial, error) {
	if files == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityKeyTimeout)
	defer cancel()
	return files.loadCandidate(ctx, func(ctx context.Context, file SecretFile) ([32]byte, privateIdentityKeySnapshot, error) {
		return file.readPrivateIdentityKeySnapshot(ctx)
	})
}

// The private reader seam permits deterministic local-filesystem rotation/error
// fixtures. Public Load always uses the scoped production reader above.
func (files *PrivateIdentityKeyFiles) loadCandidate(
	ctx context.Context,
	read func(context.Context, SecretFile) ([32]byte, privateIdentityKeySnapshot, error),
) (*PrivateIdentityKeyMaterial, error) {
	material := &PrivateIdentityKeyMaterial{}
	accepted := false
	defer func() {
		if !accepted {
			material.Clear()
		}
	}()
	if files.keys[11] != (ResidentKeyFile{}) {
		material.SubjectPrevious = &ResidentKeyMaterial{}
	}
	if files.keys[12] != (ResidentKeyFile{}) {
		material.SessionPrevious = &ResidentKeyMaterial{}
	}
	destinations := material.purposes()
	var snapshots [13]privateIdentityKeySnapshot
	for index, destination := range destinations {
		if destination == nil {
			continue
		}
		key := files.keys[index]
		decoded, snapshot, err := read(ctx, key.File)
		if err != nil {
			clear(decoded[:])
			return nil, ErrInvalid
		}
		*destination = ResidentKeyMaterial{ID: key.ID, Bytes: decoded}
		snapshots[index] = snapshot
		clear(decoded[:])
		for _, previous := range destinations[:index] {
			if previous != nil && subtle.ConstantTimeCompare(destination.Bytes[:], previous.Bytes[:]) == 1 {
				return nil, ErrInvalid
			}
		}
		if ctx.Err() != nil {
			return nil, ErrInvalid
		}
	}
	for index, snapshot := range snapshots {
		if destinations[index] != nil && !snapshot.stillCurrent(ctx) {
			return nil, ErrInvalid
		}
	}
	if !validPrivateIdentityKeyID(material.Initiation.ID) || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	accepted = true
	return material, nil
}

// Clear erases all buffers owned by this result, including optional previous
// keys. It does not erase copies already owned by a resident cryptographic port.
func (material *PrivateIdentityKeyMaterial) Clear() {
	if material == nil {
		return
	}
	for _, key := range material.purposes() {
		if key != nil {
			clear(key.Bytes[:])
			key.ID = ""
		}
	}
	material.SubjectPrevious, material.SessionPrevious = nil, nil
}

func (material *PrivateIdentityKeyMaterial) purposes() [13]*ResidentKeyMaterial {
	return [13]*ResidentKeyMaterial{
		&material.Initiation, &material.Capture, &material.Continuation, &material.ManagementCSRF,
		&material.TransactionDigest, &material.VerifierEncryption, &material.SubjectActive,
		&material.ProviderSession, &material.SessionActive, &material.Idempotency, &material.RateLimit,
		material.SubjectPrevious, material.SessionPrevious,
	}
}

func validPrivateIdentityKeyID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		isLetterOrDigit := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !isLetterOrDigit && (index == 0 || character != '-' && character != '_') {
			return false
		}
	}
	return true
}

// String redacts the complete reference, including its generation.
func (ResidentKeyFile) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (ResidentKeyFile) GoString() string { return redactedValue }

// LogValue redacts structured diagnostics.
func (ResidentKeyFile) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses secret-reference diagnostics.
func (ResidentKeyFile) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts the complete profile.
func (PrivateIdentityKeyOptions) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (PrivateIdentityKeyOptions) GoString() string { return redactedValue }

// LogValue redacts structured diagnostics.
func (PrivateIdentityKeyOptions) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses secret-reference diagnostics.
func (PrivateIdentityKeyOptions) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts the immutable profile.
func (PrivateIdentityKeyFiles) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (PrivateIdentityKeyFiles) GoString() string { return redactedValue }

// LogValue redacts structured diagnostics.
func (PrivateIdentityKeyFiles) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses secret-reference diagnostics.
func (PrivateIdentityKeyFiles) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts all resident bytes and generation.
func (ResidentKeyMaterial) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (ResidentKeyMaterial) GoString() string { return redactedValue }

// LogValue redacts structured diagnostics.
func (ResidentKeyMaterial) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses resident key serialization.
func (ResidentKeyMaterial) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts the entire loaded candidate.
func (PrivateIdentityKeyMaterial) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (PrivateIdentityKeyMaterial) GoString() string { return redactedValue }

// LogValue redacts structured diagnostics.
func (PrivateIdentityKeyMaterial) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses candidate serialization.
func (PrivateIdentityKeyMaterial) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
