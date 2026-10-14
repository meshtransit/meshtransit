package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/privatefile"

	"meshtransit.net/client/internal/secretstore"
)

const (
	identityDirName      = "identities"
	maxRecordBytes       = 64 << 10
	maxPlaintextBytes    = 32 << 10
	maxIdentityRecords   = 4096
	temporaryIDBytes     = 12
	envelopeFormat       = "meshtransit.identity"
	envelopeVersion      = 1
	envelopeAlgorithm    = "aes-256-gcm"
	additionalDataPrefix = "meshtransit/identity/v1\x00"
)

type persistedRecord struct {
	Version               int    `json:"version"`
	ProfileID             string `json:"profile_id"`
	MachinePrivateKey     string `json:"machine_private_key"`
	NodePrivateKey        string `json:"node_private_key"`
	PendingNodePrivateKey string `json:"pending_node_private_key,omitempty"`
	ControlPublicKey      string `json:"control_public_key"`
	ControlKeyFingerprint string `json:"control_key_fingerprint"`
	// Written only once Core announces a next key: older builds refuse the
	// unknown field, so a downgrade is unsupported during a key rotation.
	NextControlPublicKey      string    `json:"next_control_public_key,omitempty"`
	NextControlKeyFingerprint string    `json:"next_control_key_fingerprint,omitempty"`
	PendingAuthURL            string    `json:"pending_auth_url,omitempty"`
	IsRegistered              bool      `json:"is_registered"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type persistedEnvelope struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	ProfileID string `json:"profile_id"`
	Algorithm string `json:"algorithm"`
	Payload   string `json:"payload"`
}

type recordProtector interface {
	Seal(context.Context, []byte, []byte) ([]byte, error)
	OpenWithRotation(context.Context, []byte, []byte) ([]byte, bool, error)
	Close() error
}

// Store owns an os.Root confined to the private identities directory and the
// protector used for every persisted identity. Plaintext records are accepted
// only as a one-way migration source and are atomically protected on first use.
type Store struct {
	mu        sync.Mutex
	dir       string
	root      *os.Root
	protector recordProtector
	clock     func() time.Time
}

// Open creates and opens stateDir/identities with owner-only permissions. The
// store takes ownership of protector only when Open succeeds.
func Open(stateDir string, protector *secretstore.Protector) (*Store, error) {
	return openWith(stateDir, time.Now, protector)
}

func openWith(
	stateDir string,
	clock func() time.Time,
	protector recordProtector,
) (*Store, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("identity store directory must be absolute")
	}
	if clock == nil {
		return nil, errors.New("identity store clock is required")
	}
	if protector == nil {
		return nil, errors.New("identity store protector is required")
	}

	dir := filepath.Join(stateDir, identityDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating identity store directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspecting identity store directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("identity store path must be a directory, not a link")
	}
	if err := privatefile.RestrictDir(dir); err != nil {
		return nil, fmt.Errorf("restricting identity store directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening confined identity store: %w", err)
	}

	return &Store{
		dir:       dir,
		root:      root,
		protector: protector,
		clock:     clock,
	}, nil
}

// Close releases the confined directory handle and clears the envelope key.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}

	var rootErr error
	if s.root != nil {
		rootErr = s.root.Close()
	}
	var protectorErr error
	if s.protector != nil {
		protectorErr = s.protector.Close()
	}

	return errors.Join(rootErr, protectorErr)
}

// Get loads one profile identity without exposing persisted DTO fields. A
// valid legacy plaintext or fallback-key record is migrated before Get returns.
func (s *Store) Get(ctx context.Context, profileID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("reading identity: %w", err)
	}
	if !isProfileID(profileID) {
		return Record{}, ErrNotFound
	}
	if s == nil || s.root == nil || s.protector == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, needsRewrite, err := s.loadLocked(ctx, profileID)
	if err != nil {
		return Record{}, err
	}
	if needsRewrite {
		if err := s.persistLocked(ctx, record, true); err != nil {
			return Record{}, fmt.Errorf("migrating identity record: %w", err)
		}
	}

	return record, nil
}

// MigrateAll rewrites every legacy or fallback-key identity before the daemon
// becomes available. Each record is independently verified and atomically
// replaced, so interruption never removes its last readable copy.
func (s *Store) MigrateAll(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("migrating identities: %w", err)
	}
	if s == nil || s.root == nil || s.protector == nil {
		return errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	profileIDs, err := s.profileIDsLocked()
	if err != nil {
		return err
	}
	for _, profileID := range profileIDs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("migrating identities: %w", err)
		}
		record, needsRewrite, err := s.loadLocked(ctx, profileID)
		if err != nil {
			return fmt.Errorf("migrating identity record: %w", err)
		}
		if !needsRewrite {
			continue
		}
		if err := s.persistLocked(ctx, record, true); err != nil {
			return fmt.Errorf("migrating identity record: %w", err)
		}
	}

	return nil
}

// VerifyAllCurrent proves that every identity is readable without migration.
// It does not change persistent state.
func (s *Store) VerifyAllCurrent(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verifying identities: %w", err)
	}
	if s == nil || s.root == nil || s.protector == nil {
		return errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	profileIDs, err := s.profileIDsLocked()
	if err != nil {
		return err
	}
	for _, profileID := range profileIDs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("verifying identities: %w", err)
		}
		_, needsRewrite, err := s.loadLocked(ctx, profileID)
		if err != nil {
			return fmt.Errorf("verifying identity record: %w", err)
		}
		if needsRewrite {
			return fmt.Errorf("%w: identity record", ErrMigrationRequired)
		}
	}

	return nil
}

func (s *Store) profileIDsLocked() ([]string, error) {
	directory, err := s.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("opening identity directory: %w", err)
	}
	defer func() { _ = directory.Close() }()

	entries, err := directory.ReadDir(maxIdentityRecords + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("listing identity records: %w", err)
	}
	if len(entries) > maxIdentityRecords {
		return nil, fmt.Errorf("%w: too many identity records", ErrCorrupt)
	}

	profileIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		profileID := strings.TrimSuffix(name, ".json")
		if !isProfileID(profileID) || recordFileName(profileID) != name {
			return nil, fmt.Errorf("%w: identity record name", ErrCorrupt)
		}
		profileIDs = append(profileIDs, profileID)
	}

	return profileIDs, nil
}

// Create persists a new identity and refuses to overwrite an existing pin or key.
func (s *Store) Create(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("creating identity: %w", err)
	}
	if err := validateRecord(record); err != nil {
		return err
	}
	if s == nil || s.root == nil || s.protector == nil {
		return errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	name := recordFileName(record.profileID)
	if _, err := s.root.Lstat(name); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspecting identity record: %w", err)
	}

	return s.persistLocked(ctx, record, false)
}

// SetRegistration atomically updates only browser-pending and registered state.
func (s *Store) SetRegistration(
	ctx context.Context,
	profileID string,
	pendingAuthURL string,
	isRegistered bool,
) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("updating identity registration: %w", err)
	}
	if !isProfileID(profileID) {
		return Record{}, ErrNotFound
	}
	if s == nil || s.root == nil || s.protector == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, _, err := s.loadLocked(ctx, profileID)
	if err != nil {
		return Record{}, err
	}
	record.pendingAuthURL = pendingAuthURL
	record.isRegistered = isRegistered
	record.updatedAt = s.clock().UTC()
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.persistLocked(ctx, record, true); err != nil {
		return Record{}, err
	}

	return record, nil
}

// ReplaceCredentials gives the profile a new machine key and node key and
// marks it unregistered, keeping its control key pin. A Device that logged
// out or was revoked cannot reuse its keys: Core remembers them, so the
// profile enrolls again as a new Device.
func (s *Store) ReplaceCredentials(
	ctx context.Context,
	profileID string,
	machinePrivateKey []byte,
	nodePrivateKey []byte,
) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("replacing identity credentials: %w", err)
	}
	if !isProfileID(profileID) {
		return Record{}, ErrNotFound
	}
	if s == nil || s.root == nil || s.protector == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, _, err := s.loadLocked(ctx, profileID)
	if err != nil {
		return Record{}, err
	}
	if string(machinePrivateKey) == record.machinePrivateKey || string(nodePrivateKey) == record.nodePrivateKey {
		return Record{}, errors.New("identity credentials must be replaced by new keys")
	}
	record.machinePrivateKey = string(machinePrivateKey)
	record.nodePrivateKey = string(nodePrivateKey)
	record.pendingNodePrivateKey = ""
	record.pendingAuthURL = ""
	record.isRegistered = false
	record.updatedAt = s.clock().UTC()
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.persistLocked(ctx, record, true); err != nil {
		return Record{}, err
	}

	return record, nil
}

// BeginNodeKeyRotation durably stages one new private key before any remote
// mutation. Repeating the exact staged key is idempotent.
func (s *Store) BeginNodeKeyRotation(
	ctx context.Context,
	profileID string,
	pendingNodePrivateKey []byte,
) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("staging node key rotation: %w", err)
	}
	if !isProfileID(profileID) {
		return Record{}, ErrNotFound
	}
	if s == nil || s.root == nil || s.protector == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, _, err := s.loadLocked(ctx, profileID)
	if err != nil {
		return Record{}, err
	}
	pending := string(pendingNodePrivateKey)
	if record.pendingNodePrivateKey != "" {
		if record.pendingNodePrivateKey == pending {
			return record, nil
		}

		return Record{}, fmt.Errorf("%w: another node key rotation is pending", ErrInvalid)
	}
	record.pendingNodePrivateKey = pending
	record.updatedAt = s.clock().UTC()
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.persistLocked(ctx, record, true); err != nil {
		return Record{}, err
	}

	return record, nil
}

// CompleteNodeKeyRotation atomically promotes the exact staged key and clears
// pending state only after remote authority confirms success.
func (s *Store) CompleteNodeKeyRotation(
	ctx context.Context,
	profileID string,
	expectedPendingNodePrivateKey []byte,
) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("completing node key rotation: %w", err)
	}
	if !isProfileID(profileID) {
		return Record{}, ErrNotFound
	}
	if s == nil || s.root == nil || s.protector == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, _, err := s.loadLocked(ctx, profileID)
	if err != nil {
		return Record{}, err
	}
	expected := string(expectedPendingNodePrivateKey)
	if expected == "" || record.pendingNodePrivateKey != expected {
		return Record{}, fmt.Errorf("%w: pending node key rotation changed", ErrInvalid)
	}
	record.nodePrivateKey = record.pendingNodePrivateKey
	record.pendingNodePrivateKey = ""
	record.updatedAt = s.clock().UTC()
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.persistLocked(ctx, record, true); err != nil {
		return Record{}, err
	}

	return record, nil
}

// StageNextControlKey durably records the next control key Core announced,
// or clears it when publicKey is empty. Repeating the staged key is a no-op.
func (s *Store) StageNextControlKey(
	ctx context.Context,
	profileID string,
	publicKey []byte,
	fingerprint string,
) (Record, error) {
	return s.updateControlKeys(ctx, profileID, func(record *Record) error {
		if string(publicKey) == record.nextControlPublicKey && fingerprint == record.nextControlKeyFingerprint {
			return errUnchanged
		}
		record.nextControlPublicKey = string(publicKey)
		record.nextControlKeyFingerprint = fingerprint
		if len(publicKey) == 0 {
			record.nextControlKeyFingerprint = ""
		}
		return nil
	})
}

// PromoteNextControlKey makes the staged next key the profile's control key,
// only if it is still the expected one.
func (s *Store) PromoteNextControlKey(
	ctx context.Context,
	profileID string,
	expectedPublicKey []byte,
) (Record, error) {
	return s.updateControlKeys(ctx, profileID, func(record *Record) error {
		if len(expectedPublicKey) == 0 || record.nextControlPublicKey != string(expectedPublicKey) {
			return fmt.Errorf("%w: staged next control key changed", ErrInvalid)
		}
		record.controlPublicKey = record.nextControlPublicKey
		record.controlKeyFingerprint = record.nextControlKeyFingerprint
		record.nextControlPublicKey = ""
		record.nextControlKeyFingerprint = ""
		return nil
	})
}

// errUnchanged lets an update skip the write.
var errUnchanged = errors.New("identity: unchanged")

func (s *Store) updateControlKeys(ctx context.Context, profileID string, change func(*Record) error) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("updating control keys: %w", err)
	}
	if !isProfileID(profileID) {
		return Record{}, ErrNotFound
	}
	if s == nil || s.root == nil || s.protector == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, _, err := s.loadLocked(ctx, profileID)
	if err != nil {
		return Record{}, err
	}
	if err := change(&record); errors.Is(err, errUnchanged) {
		return record, nil
	} else if err != nil {
		return Record{}, err
	}
	record.updatedAt = s.clock().UTC()
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.persistLocked(ctx, record, true); err != nil {
		return Record{}, err
	}

	return record, nil
}

func (s *Store) loadLocked(
	ctx context.Context,
	profileID string,
) (Record, bool, error) {
	name := recordFileName(profileID)
	info, err := s.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, ErrNotFound
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("inspecting identity record: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Record{}, false, fmt.Errorf("%w: record must be a regular file, not a link", ErrCorrupt)
	}
	if err := privatefile.CheckFile(filepath.Join(s.dir, name), info); err != nil {
		return Record{}, false, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if info.Size() <= 0 || info.Size() > maxRecordBytes {
		return Record{}, false, fmt.Errorf("%w: record has an invalid size", ErrCorrupt)
	}

	file, err := s.root.Open(name)
	if err != nil {
		return Record{}, false, fmt.Errorf("opening identity record: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoded, err := readBounded(file, maxRecordBytes)
	if err != nil {
		return Record{}, false, err
	}

	return s.decodeRecord(ctx, profileID, encoded)
}

func (s *Store) decodeRecord(
	ctx context.Context,
	profileID string,
	encoded []byte,
) (Record, bool, error) {
	header := struct {
		Format string `json:"format"`
	}{}
	if err := json.Unmarshal(encoded, &header); err != nil {
		return Record{}, false, fmt.Errorf("%w: record is not valid json", ErrCorrupt)
	}
	if header.Format == "" {
		record, _, err := decodePlaintextRecord(encoded, profileID)

		return record, true, err
	}
	if header.Format != envelopeFormat {
		return Record{}, false, fmt.Errorf("%w: identity envelope format", ErrUnsupported)
	}

	envelope := persistedEnvelope{}
	if err := decodeStrict(encoded, &envelope); err != nil {
		return Record{}, false, fmt.Errorf("%w: decoding identity envelope", ErrCorrupt)
	}
	if envelope.Version != envelopeVersion || envelope.Algorithm != envelopeAlgorithm {
		return Record{}, false, fmt.Errorf("%w: identity envelope version or algorithm", ErrUnsupported)
	}
	if envelope.ProfileID != profileID {
		return Record{}, false, fmt.Errorf("%w: envelope profile binding", ErrCorrupt)
	}
	decodedLength := base64.RawStdEncoding.DecodedLen(len(envelope.Payload))
	if decodedLength <= 0 || decodedLength > maxPlaintextBytes+64 {
		return Record{}, false, fmt.Errorf("%w: protected payload size", ErrCorrupt)
	}
	protected := make([]byte, decodedLength)
	decodedBytes, err := base64.RawStdEncoding.Strict().Decode(protected, []byte(envelope.Payload))
	if err != nil {
		clear(protected)

		return Record{}, false, fmt.Errorf("%w: protected payload encoding", ErrCorrupt)
	}
	protected = protected[:decodedBytes]
	plaintext, needsRotation, err := s.protector.OpenWithRotation(
		ctx,
		protected,
		recordAdditionalData(profileID),
	)
	clear(protected)
	if errors.Is(err, secretstore.ErrAuthentication) {
		return Record{}, false, fmt.Errorf("%w: identity envelope authentication", ErrCorrupt)
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("opening identity envelope: %w", err)
	}
	defer clear(plaintext)

	record, needsUpgrade, err := decodePlaintextRecord(plaintext, profileID)
	if err != nil {
		return Record{}, false, err
	}

	return record, needsRotation || needsUpgrade, nil
}

func (s *Store) persistLocked(ctx context.Context, record Record, replace bool) error {
	encoded, err := s.encodeRecord(ctx, record)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if len(encoded) > maxRecordBytes {
		return fmt.Errorf("encoded identity record exceeds %d bytes", maxRecordBytes)
	}

	temporaryName, err := randomTemporaryName()
	if err != nil {
		return err
	}
	temporary, err := s.root.OpenFile(
		temporaryName,
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("creating temporary identity record: %w", err)
	}
	defer func() {
		_ = temporary.Close()
		_ = s.root.Remove(temporaryName)
	}()

	written, err := temporary.Write(encoded)
	if err != nil {
		return fmt.Errorf("writing temporary identity record: %w", err)
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("syncing temporary identity record: %w", err)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewinding temporary identity record: %w", err)
	}
	verifiedBytes, err := readBounded(temporary, maxRecordBytes)
	if err != nil {
		return fmt.Errorf("verifying temporary identity record: %w", err)
	}
	verified, needsRewrite, err := s.decodeRecord(ctx, record.profileID, verifiedBytes)
	clear(verifiedBytes)
	if err != nil {
		return fmt.Errorf("verifying temporary identity record: %w", err)
	}
	if needsRewrite || !sameRecord(verified, record) {
		return errors.New("verifying temporary identity record: record mismatch")
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("closing temporary identity record: %w", err)
	}
	finalName := recordFileName(record.profileID)
	if replace {
		if err := s.root.Rename(temporaryName, finalName); err != nil {
			return fmt.Errorf("replacing identity record: %w", err)
		}
	} else {
		if err := installNew(s.root, temporaryName, finalName); err != nil {
			if errors.Is(err, os.ErrExist) {
				return ErrExists
			}

			return fmt.Errorf("installing new identity record: %w", err)
		}
	}
	if err := privatefile.SyncDir(s.root); err != nil {
		return err
	}

	return nil
}

func (s *Store) encodeRecord(ctx context.Context, record Record) ([]byte, error) {
	plaintext, err := json.Marshal(toPersisted(record))
	if err != nil {
		return nil, fmt.Errorf("encoding identity plaintext: %w", err)
	}
	defer clear(plaintext)
	if len(plaintext) > maxPlaintextBytes {
		return nil, fmt.Errorf("identity plaintext exceeds %d bytes", maxPlaintextBytes)
	}

	protected, err := s.protector.Seal(ctx, plaintext, recordAdditionalData(record.profileID))
	if err != nil {
		return nil, fmt.Errorf("protecting identity record: %w", err)
	}
	defer clear(protected)
	envelope := persistedEnvelope{
		Format:    envelopeFormat,
		Version:   envelopeVersion,
		ProfileID: record.profileID,
		Algorithm: envelopeAlgorithm,
		Payload:   base64.RawStdEncoding.EncodeToString(protected),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encoding identity envelope: %w", err)
	}

	return append(encoded, '\n'), nil
}

func decodePlaintextRecord(encoded []byte, profileID string) (Record, bool, error) {
	if len(encoded) > maxPlaintextBytes {
		return Record{}, false, fmt.Errorf("%w: identity plaintext size", ErrCorrupt)
	}
	persisted := persistedRecord{}
	if err := decodeStrict(encoded, &persisted); err != nil {
		return Record{}, false, fmt.Errorf("%w: decoding identity plaintext", ErrCorrupt)
	}
	if persisted.Version != recordVersion && persisted.Version != legacyRecordVersion {
		return Record{}, false, fmt.Errorf("%w: identity record version", ErrUnsupported)
	}
	if persisted.Version == legacyRecordVersion && persisted.PendingNodePrivateKey != "" {
		return Record{}, false, fmt.Errorf("%w: legacy identity rotation state", ErrCorrupt)
	}

	record := fromPersisted(persisted)
	if record.profileID != profileID {
		return Record{}, false, fmt.Errorf("%w: record profile binding", ErrCorrupt)
	}
	if err := validateRecord(record); err != nil {
		return Record{}, false, fmt.Errorf("%w: validating identity record", ErrCorrupt)
	}

	return record, persisted.Version != recordVersion, nil
}

func decodeStrict(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}

	return ensureJSONEOF(decoder)
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("reading identity record: %w", err)
	}
	if int64(len(encoded)) > maximum {
		clear(encoded)

		return nil, fmt.Errorf("%w: identity record exceeds size limit", ErrCorrupt)
	}

	return encoded, nil
}

func recordAdditionalData(profileID string) []byte {
	return []byte(additionalDataPrefix + profileID)
}

func sameRecord(left, right Record) bool {
	return left.profileID == right.profileID &&
		left.machinePrivateKey == right.machinePrivateKey &&
		left.nodePrivateKey == right.nodePrivateKey &&
		left.pendingNodePrivateKey == right.pendingNodePrivateKey &&
		left.controlPublicKey == right.controlPublicKey &&
		left.controlKeyFingerprint == right.controlKeyFingerprint &&
		left.pendingAuthURL == right.pendingAuthURL &&
		left.isRegistered == right.isRegistered &&
		left.createdAt.Equal(right.createdAt) &&
		left.updatedAt.Equal(right.updatedAt)
}

func toPersisted(record Record) persistedRecord {
	return persistedRecord{
		Version:                   recordVersion,
		ProfileID:                 record.profileID,
		MachinePrivateKey:         record.machinePrivateKey,
		NodePrivateKey:            record.nodePrivateKey,
		PendingNodePrivateKey:     record.pendingNodePrivateKey,
		ControlPublicKey:          record.controlPublicKey,
		ControlKeyFingerprint:     record.controlKeyFingerprint,
		NextControlPublicKey:      record.nextControlPublicKey,
		NextControlKeyFingerprint: record.nextControlKeyFingerprint,
		PendingAuthURL:            record.pendingAuthURL,
		IsRegistered:              record.isRegistered,
		CreatedAt:                 record.createdAt,
		UpdatedAt:                 record.updatedAt,
	}
}

func fromPersisted(record persistedRecord) Record {
	return Record{
		profileID:                 record.ProfileID,
		machinePrivateKey:         record.MachinePrivateKey,
		nodePrivateKey:            record.NodePrivateKey,
		pendingNodePrivateKey:     record.PendingNodePrivateKey,
		controlPublicKey:          record.ControlPublicKey,
		controlKeyFingerprint:     record.ControlKeyFingerprint,
		nextControlPublicKey:      record.NextControlPublicKey,
		nextControlKeyFingerprint: record.NextControlKeyFingerprint,
		pendingAuthURL:            record.PendingAuthURL,
		isRegistered:              record.IsRegistered,
		createdAt:                 record.CreatedAt,
		updatedAt:                 record.UpdatedAt,
	}
}

func recordFileName(profileID string) string { return profileID + ".json" }

func randomTemporaryName() (string, error) {
	buffer := make([]byte, temporaryIDBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("reading identity temporary-name randomness: %w", err)
	}

	return ".identity-" + hex.EncodeToString(buffer) + ".tmp", nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra struct{}
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("identity record contains multiple json values")
	}

	return fmt.Errorf("reading trailing identity record: %w", err)
}
