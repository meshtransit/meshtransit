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
	"sync"
	"time"

	"github.com/meshtransit/meshd/internal/secretstore"
)

const (
	identityDirName      = "identities"
	maxRecordBytes       = 64 << 10
	maxPlaintextBytes    = 32 << 10
	temporaryIDBytes     = 12
	envelopeFormat       = "meshtransit.identity"
	envelopeVersion      = 1
	envelopeAlgorithm    = "aes-256-gcm"
	additionalDataPrefix = "meshtransit/identity/v1\x00"
)

type persistedRecord struct {
	Version               int       `json:"version"`
	ProfileID             string    `json:"profile_id"`
	MachinePrivateKey     string    `json:"machine_private_key"`
	NodePrivateKey        string    `json:"node_private_key"`
	ControlPublicKey      string    `json:"control_public_key"`
	ControlKeyFingerprint string    `json:"control_key_fingerprint"`
	PendingAuthURL        string    `json:"pending_auth_url,omitempty"`
	IsRegistered          bool      `json:"is_registered"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
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
	Open(context.Context, []byte, []byte) ([]byte, error)
	Close() error
}

// Store owns an os.Root confined to the private identities directory and the
// protector used for every persisted identity. Plaintext records are accepted
// only as a migration source and are atomically protected on the first write.
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
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // Directories require execute bits.
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

// Get loads one profile identity without exposing persisted DTO fields. It
// leaves a valid legacy record unchanged so the preceding release remains a
// rollback target during the compatibility deployment stage.
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

	record, _, err := s.loadLocked(ctx, profileID)
	if err != nil {
		return Record{}, err
	}

	return record, nil
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
	if info.Mode().Perm()&0o077 != 0 {
		return Record{}, false, fmt.Errorf("%w: record permissions are too broad", ErrCorrupt)
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
		record, err := decodePlaintextRecord(encoded, profileID)

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
	plaintext, err := s.protector.Open(ctx, protected, recordAdditionalData(profileID))
	clear(protected)
	if errors.Is(err, secretstore.ErrAuthentication) {
		return Record{}, false, fmt.Errorf("%w: identity envelope authentication", ErrCorrupt)
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("opening identity envelope: %w", err)
	}
	defer clear(plaintext)

	record, err := decodePlaintextRecord(plaintext, profileID)
	if err != nil {
		return Record{}, false, err
	}

	return record, false, nil
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
	verified, isLegacy, err := s.decodeRecord(ctx, record.profileID, verifiedBytes)
	clear(verifiedBytes)
	if err != nil {
		return fmt.Errorf("verifying temporary identity record: %w", err)
	}
	if isLegacy || !sameRecord(verified, record) {
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
		if err := s.root.Link(temporaryName, finalName); err != nil {
			if errors.Is(err, os.ErrExist) {
				return ErrExists
			}

			return fmt.Errorf("installing new identity record: %w", err)
		}
		if err := s.root.Remove(temporaryName); err != nil {
			return fmt.Errorf("removing linked temporary identity record: %w", err)
		}
	}
	if err := syncRoot(s.root); err != nil {
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

func decodePlaintextRecord(encoded []byte, profileID string) (Record, error) {
	if len(encoded) > maxPlaintextBytes {
		return Record{}, fmt.Errorf("%w: identity plaintext size", ErrCorrupt)
	}
	persisted := persistedRecord{}
	if err := decodeStrict(encoded, &persisted); err != nil {
		return Record{}, fmt.Errorf("%w: decoding identity plaintext", ErrCorrupt)
	}
	if persisted.Version != recordVersion {
		return Record{}, fmt.Errorf("%w: identity record version", ErrUnsupported)
	}

	record := fromPersisted(persisted)
	if record.profileID != profileID {
		return Record{}, fmt.Errorf("%w: record profile binding", ErrCorrupt)
	}
	if err := validateRecord(record); err != nil {
		return Record{}, fmt.Errorf("%w: validating identity record", ErrCorrupt)
	}

	return record, nil
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
		left.controlPublicKey == right.controlPublicKey &&
		left.controlKeyFingerprint == right.controlKeyFingerprint &&
		left.pendingAuthURL == right.pendingAuthURL &&
		left.isRegistered == right.isRegistered &&
		left.createdAt.Equal(right.createdAt) &&
		left.updatedAt.Equal(right.updatedAt)
}

func toPersisted(record Record) persistedRecord {
	return persistedRecord{
		Version:               recordVersion,
		ProfileID:             record.profileID,
		MachinePrivateKey:     record.machinePrivateKey,
		NodePrivateKey:        record.nodePrivateKey,
		ControlPublicKey:      record.controlPublicKey,
		ControlKeyFingerprint: record.controlKeyFingerprint,
		PendingAuthURL:        record.pendingAuthURL,
		IsRegistered:          record.isRegistered,
		CreatedAt:             record.createdAt,
		UpdatedAt:             record.updatedAt,
	}
}

func fromPersisted(record persistedRecord) Record {
	return Record{
		profileID:             record.ProfileID,
		machinePrivateKey:     record.MachinePrivateKey,
		nodePrivateKey:        record.NodePrivateKey,
		controlPublicKey:      record.ControlPublicKey,
		controlKeyFingerprint: record.ControlKeyFingerprint,
		pendingAuthURL:        record.PendingAuthURL,
		isRegistered:          record.IsRegistered,
		createdAt:             record.CreatedAt,
		updatedAt:             record.UpdatedAt,
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

func syncRoot(root *os.Root) (syncErr error) {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("opening identity directory for sync: %w", err)
	}
	defer func() { syncErr = errors.Join(syncErr, directory.Close()) }()

	if err := directory.Sync(); err != nil {
		return fmt.Errorf("syncing identity directory: %w", err)
	}

	return nil
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
