package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"meshtransit.net/client/internal/privatefile"
)

// displayVersion is the format of a display file.
const displayVersion = 1

// maxDisplayBytes bounds one display file: names of 128 characters each fit
// many times over.
const maxDisplayBytes = 8 << 10

// ErrInvalidDisplay reports a profile ID a display file cannot be named by.
var ErrInvalidDisplay = errors.New("profile: invalid display file")

// Display is what the apps show for a profile, kept beside the profile
// store in a file of its own (device logout S4b §4.1), so an older meshd,
// which reads profiles.json strictly, never fails on it. Losing one only
// loses names: it is never authority for anything.
type Display struct {
	Version int `json:"version"`
	// DeviceID is the Device the profile holds; a new one resets the names.
	DeviceID string `json:"device_id,omitempty"`
	// Hostname tells apart two accounts with every other name equal.
	Hostname string `json:"hostname,omitempty"`
	// The account's names its map last carried (mtcp-v1 §7.13).
	Network   string `json:"network,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	Ownership string `json:"ownership,omitempty"`
	Owner     string `json:"owner,omitempty"`
	// OwnerEmail is the owner's verified email (S4c §4); empty when the
	// account has none or no map carried it yet.
	OwnerEmail string `json:"owner_email,omitempty"`
	// PreviousProfileID is the profile in use when this one was added as
	// another account: where cancelling it goes back to.
	PreviousProfileID string `json:"previous_profile_id,omitempty"`
	// CreatedByAddAccount marks a profile Add account created; with
	// RegisteredOnce false it never held a Device, so cancelling it removes
	// nothing anyone used.
	CreatedByAddAccount bool `json:"created_by_add_account,omitempty"`
	RegisteredOnce      bool `json:"registered_once,omitempty"`
	// SignInStopped marks a browser approval dropped with StopSignIn. The
	// dropped approval registers nothing, but the keys may hold a Device from
	// before, so Core is asked before they are dropped.
	SignInStopped bool `json:"sign_in_stopped,omitempty"`
	// JoinedProfileID is the profile Core switched this one's sign-in to
	// (already_in_network, duplicate-device design §9) until meshd finished
	// the switch: a crash before then is finished on the next start.
	JoinedProfileID string `json:"joined_profile_id,omitempty"`
	// RemovedAt is when meshd learned Core removed the Device; the names
	// stay so the apps can say which one.
	RemovedAt *time.Time `json:"removed_at,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// DisplayStore keeps one Display per profile in its own directory. It is
// the only writer of those files: every change reads, changes and replaces
// a file under one lock, so concurrent writers never lose each other's
// fields.
type DisplayStore struct {
	mu    sync.Mutex
	dir   string
	root  *os.Root
	clock func() time.Time
}

// OpenDisplayStore opens (creating it private) the display directory.
func OpenDisplayStore(dir string, clock func() time.Time) (*DisplayStore, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("display directory must be absolute")
	}
	if clock == nil {
		clock = time.Now
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening display directory: %w", err)
	}
	return &DisplayStore{dir: dir, root: root, clock: clock}, nil
}

// Close releases the directory.
func (store *DisplayStore) Close() error {
	if store == nil {
		return nil
	}
	return store.root.Close()
}

// Get returns the profile's display, and false when it has none or the
// file cannot be read (which only loses names).
func (store *DisplayStore) Get(id string) (Display, bool) {
	if store == nil || !isProfileID(id) {
		return Display{}, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.read(id)
}

// Update reads the profile's display (empty when none), applies change and
// writes it back when it changed.
func (store *DisplayStore) Update(id string, change func(*Display)) error {
	if store == nil {
		return nil
	}
	if !isProfileID(id) || change == nil {
		return ErrInvalidDisplay
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, _ := store.read(id)
	next := current
	change(&next)
	next.Version = displayVersion
	next.UpdatedAt = current.UpdatedAt
	if displayEqual(current, next) {
		return nil
	}
	next.UpdatedAt = store.clock().UTC()
	return store.write(id, next)
}

// Remove deletes the profile's display, if any.
func (store *DisplayStore) Remove(id string) error {
	if store == nil {
		return nil
	}
	if !isProfileID(id) {
		return ErrInvalidDisplay
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.root.Remove(displayFileName(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing display: %w", err)
	}
	return nil
}

func displayFileName(id string) string { return id + ".json" }

func (store *DisplayStore) read(id string) (Display, bool) {
	name := displayFileName(id)
	info, err := store.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDisplayBytes ||
		privatefile.CheckFile(filepath.Join(store.dir, name), info) != nil {
		return Display{}, false
	}
	file, err := store.root.Open(name)
	if err != nil {
		return Display{}, false
	}
	defer func() { _ = file.Close() }()
	encoded, err := io.ReadAll(io.LimitReader(file, maxDisplayBytes+1))
	if err != nil || len(encoded) > maxDisplayBytes {
		return Display{}, false
	}
	// Lenient on purpose: a newer meshd may add fields.
	var display Display
	if err := json.Unmarshal(encoded, &display); err != nil || display.Version != displayVersion {
		return Display{}, false
	}
	return display, true
}

func (store *DisplayStore) write(id string, display Display) error {
	encoded, err := json.Marshal(display)
	if err != nil {
		return fmt.Errorf("encoding display: %w", err)
	}
	if len(encoded) > maxDisplayBytes {
		return fmt.Errorf("display exceeds %d bytes", maxDisplayBytes)
	}
	temporaryID, err := randomID()
	if err != nil {
		return fmt.Errorf("naming temporary display: %w", err)
	}
	temporaryName := ".display-" + temporaryID + ".tmp"
	temporary, err := store.root.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("creating temporary display: %w", err)
	}
	defer func() {
		_ = temporary.Close()
		_ = store.root.Remove(temporaryName)
	}()
	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("writing temporary display: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("syncing temporary display: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("closing temporary display: %w", err)
	}
	if err := store.root.Rename(temporaryName, displayFileName(id)); err != nil {
		return fmt.Errorf("replacing display: %w", err)
	}
	return privatefile.SyncDir(store.root)
}

func displayEqual(first, second Display) bool {
	firstJSON, firstErr := json.Marshal(first)
	secondJSON, secondErr := json.Marshal(second)
	return firstErr == nil && secondErr == nil && bytes.Equal(firstJSON, secondJSON)
}
