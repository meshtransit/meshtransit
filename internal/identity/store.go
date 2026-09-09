package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	identityDirName  = "identities"
	maxRecordBytes   = 64 << 10
	temporaryIDBytes = 12
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

// Store owns an os.Root confined to the private identities directory.
type Store struct {
	mu    sync.Mutex
	dir   string
	root  *os.Root
	clock func() time.Time
}

// Open creates and opens stateDir/identities with owner-only permissions.
func Open(stateDir string) (*Store, error) {
	return openWith(stateDir, time.Now)
}

func openWith(stateDir string, clock func() time.Time) (*Store, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("identity store directory must be absolute")
	}
	if clock == nil {
		return nil, errors.New("identity store clock is required")
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

	return &Store{dir: dir, root: root, clock: clock}, nil
}

// Close releases the confined directory handle.
func (s *Store) Close() error {
	if s == nil || s.root == nil {
		return nil
	}

	return s.root.Close()
}

// Get loads one profile identity without exposing persisted DTO fields.
func (s *Store) Get(ctx context.Context, profileID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("reading identity: %w", err)
	}
	if !isProfileID(profileID) {
		return Record{}, ErrNotFound
	}
	if s == nil || s.root == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.loadLocked(profileID)
}

// Create persists a new identity and refuses to overwrite an existing pin or key.
func (s *Store) Create(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("creating identity: %w", err)
	}
	if err := validateRecord(record); err != nil {
		return err
	}
	if s == nil || s.root == nil {
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

	return s.persistLocked(record, false)
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
	if s == nil || s.root == nil {
		return Record{}, errors.New("identity store is not initialized")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.loadLocked(profileID)
	if err != nil {
		return Record{}, err
	}
	record.pendingAuthURL = pendingAuthURL
	record.isRegistered = isRegistered
	record.updatedAt = s.clock().UTC()
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.persistLocked(record, true); err != nil {
		return Record{}, err
	}

	return record, nil
}

func (s *Store) loadLocked(profileID string) (Record, error) {
	name := recordFileName(profileID)
	info, err := s.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("inspecting identity record: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Record{}, errors.New("identity record must be a regular file, not a link")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Record{}, fmt.Errorf("identity record permissions %04o are too broad", info.Mode().Perm())
	}
	if info.Size() > maxRecordBytes {
		return Record{}, fmt.Errorf("identity record exceeds %d bytes", maxRecordBytes)
	}

	file, err := s.root.Open(name)
	if err != nil {
		return Record{}, fmt.Errorf("opening identity record: %w", err)
	}
	defer func() { _ = file.Close() }()

	decoder := json.NewDecoder(io.LimitReader(file, maxRecordBytes+1))
	decoder.DisallowUnknownFields()
	persisted := persistedRecord{}
	if err := decoder.Decode(&persisted); err != nil {
		return Record{}, fmt.Errorf("decoding identity record: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Record{}, err
	}
	if persisted.Version != recordVersion {
		return Record{}, fmt.Errorf("unsupported identity record version %d", persisted.Version)
	}

	record := fromPersisted(persisted)
	if record.profileID != profileID {
		return Record{}, errors.New("identity record profile binding does not match its filename")
	}
	if err := validateRecord(record); err != nil {
		return Record{}, fmt.Errorf("validating identity record: %w", err)
	}

	return record, nil
}

func (s *Store) persistLocked(record Record, replace bool) error {
	persisted := toPersisted(record)
	encoded, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding identity record: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxRecordBytes {
		return fmt.Errorf("encoded identity record exceeds %d bytes", maxRecordBytes)
	}

	temporaryName, err := randomTemporaryName()
	if err != nil {
		return err
	}
	temporary, err := s.root.OpenFile(
		temporaryName,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("creating temporary identity record: %w", err)
	}
	defer func() {
		_ = temporary.Close()
		_ = s.root.Remove(temporaryName)
	}()

	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("writing temporary identity record: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("syncing temporary identity record: %w", err)
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
