package profile

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
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/privatefile"
)

const (
	stateFileName = "profiles.json"
	maxStateBytes = 1 << 20
)

// Store persists profile metadata with atomic replacement and restrictive modes.
type Store struct {
	mu       sync.RWMutex
	dir      string
	root     *os.Root
	state    Snapshot
	clock    func() time.Time
	idSource func() (string, error)
}

// Open initializes a profile store rooted at dir and loads any existing state.
func Open(dir string) (*Store, error) {
	return openWith(dir, time.Now, randomID)
}

func openWith(
	dir string,
	clock func() time.Time,
	idSource func() (string, error),
) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("profile store directory must be absolute")
	}
	if clock == nil || idSource == nil {
		return nil, errors.New("profile store dependencies cannot be nil")
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening confined profile store: %w", err)
	}

	store := &Store{
		dir:      dir,
		root:     root,
		state:    newSnapshot(),
		clock:    clock,
		idSource: idSource,
	}
	if err := store.load(); err != nil {
		return nil, errors.Join(err, root.Close())
	}

	return store, nil
}

// Close releases the confined directory handle.
func (s *Store) Close() error {
	if s == nil || s.root == nil {
		return nil
	}

	return s.root.Close()
}

// Snapshot returns a defensive copy of the current profile state.
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return cloneSnapshot(s.state)
}

// Active returns the selected profile without exposing the store's slice.
func (s *Store) Active(ctx context.Context) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, fmt.Errorf("reading active profile: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, item := range s.state.Profiles {
		if item.ID == s.state.ActiveProfileID {
			return item, nil
		}
	}

	return Profile{}, ErrNotFound
}

// Create validates and atomically persists a new profile. The first profile
// becomes active; later profiles remain inactive until explicitly selected.
func (s *Store) Create(ctx context.Context, input CreateInput) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, fmt.Errorf("creating profile: %w", err)
	}

	normalized, err := normalizeInput(input)
	if err != nil {
		return Profile{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, item := range s.state.Profiles {
		if strings.EqualFold(item.Name, normalized.Name) {
			return Profile{}, ErrDuplicate
		}
	}

	id, err := s.idSource()
	if err != nil {
		return Profile{}, fmt.Errorf("generating profile id: %w", err)
	}
	if !isProfileID(id) {
		return Profile{}, errors.New("generated profile id has an invalid format")
	}

	now := s.clock().UTC()
	created := Profile{
		ID:         id,
		Name:       normalized.Name,
		ControlURL: normalized.ControlURL,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	next := cloneSnapshot(s.state)
	next.Profiles = append(next.Profiles, created)
	if next.ActiveProfileID == "" {
		next.ActiveProfileID = created.ID
	}
	if err := validateSnapshot(next); err != nil {
		return Profile{}, fmt.Errorf("validating next profile state: %w", err)
	}
	if err := s.persist(next); err != nil {
		return Profile{}, err
	}
	s.state = next

	return created, nil
}

// Activate makes id the only active profile and persists the change atomically.
func (s *Store) Activate(ctx context.Context, id string) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, fmt.Errorf("activating profile: %w", err)
	}
	if !isProfileID(id) {
		return Profile{}, ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var selected Profile
	found := false
	for _, item := range s.state.Profiles {
		if item.ID == id {
			selected = item
			found = true
			break
		}
	}
	if !found {
		return Profile{}, ErrNotFound
	}
	if s.state.ActiveProfileID == id {
		return selected, nil
	}

	next := cloneSnapshot(s.state)
	next.ActiveProfileID = id
	if err := s.persist(next); err != nil {
		return Profile{}, err
	}
	s.state = next

	return selected, nil
}

// SetDisconnected persists whether meshd stays off the network (`meshctl
// down`) and reports whether the value changed.
func (s *Store) SetDisconnected(ctx context.Context, disconnected bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("updating connection preference: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Disconnected == disconnected {
		return false, nil
	}
	next := cloneSnapshot(s.state)
	next.Disconnected = disconnected
	if err := s.persist(next); err != nil {
		return false, err
	}
	s.state = next

	return true, nil
}

func (s *Store) load() error {
	info, err := s.root.Lstat(stateFileName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspecting profile state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("profile state must be a regular file, not a link")
	}
	if err := privatefile.CheckFile(filepath.Join(s.dir, stateFileName), info); err != nil {
		return fmt.Errorf("profile state: %w", err)
	}
	if info.Size() > maxStateBytes {
		return fmt.Errorf("profile state exceeds %d bytes", maxStateBytes)
	}

	file, err := s.root.Open(stateFileName)
	if err != nil {
		return fmt.Errorf("opening profile state: %w", err)
	}
	defer func() { _ = file.Close() }()

	decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes+1))
	decoder.DisallowUnknownFields()

	loaded := Snapshot{}
	if err := decoder.Decode(&loaded); err != nil {
		return fmt.Errorf("decoding profile state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if err := validateSnapshot(loaded); err != nil {
		return fmt.Errorf("validating profile state: %w", err)
	}
	s.state = cloneSnapshot(loaded)

	return nil
}

func (s *Store) persist(snapshot Snapshot) error {
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding profile state: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxStateBytes {
		return fmt.Errorf("encoded profile state exceeds %d bytes", maxStateBytes)
	}

	temporaryID, err := randomID()
	if err != nil {
		return fmt.Errorf("generating temporary profile state name: %w", err)
	}
	temporaryName := ".profiles-" + temporaryID + ".tmp"
	temporary, err := s.root.OpenFile(
		temporaryName,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("creating temporary profile state: %w", err)
	}
	defer func() {
		_ = temporary.Close()
		_ = s.root.Remove(temporaryName)
	}()

	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("writing temporary profile state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("syncing temporary profile state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("closing temporary profile state: %w", err)
	}

	if err := s.root.Rename(temporaryName, stateFileName); err != nil {
		return fmt.Errorf("replacing profile state: %w", err)
	}
	if err := privatefile.SyncDir(s.root); err != nil {
		return err
	}

	return nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating profile store directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspecting profile store directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("profile store path must be a directory, not a link")
	}
	if err := privatefile.RestrictDir(dir); err != nil {
		return fmt.Errorf("restricting profile store directory: %w", err)
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
		return errors.New("profile state contains multiple json values")
	}

	return fmt.Errorf("reading trailing profile state: %w", err)
}

func randomID() (string, error) {
	buffer := make([]byte, profileIDBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("reading cryptographic randomness: %w", err)
	}

	return hex.EncodeToString(buffer), nil
}
