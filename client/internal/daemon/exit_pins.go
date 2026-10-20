package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"meshtransit.net/client/internal/privatefile"
)

// Pinning exit nodes (exit node design §5.4, Q8): the exit nodes a pool
// had when the host first used it are trusted; one Core adds later carries
// no traffic until a user approves it (meshctl exit approve), so a
// compromised Core cannot slip in an exit node of its own. One Core removes
// is dropped at once.

const (
	exitPinsFile     = "exit-pins.json"
	maxExitPinsBytes = 256 << 10
	maxPinnedPools   = 256
)

// exitPins are the approved exit nodes of each pool, by pool reference. A
// store without a directory keeps them in memory only.
type exitPins struct {
	mu    sync.Mutex
	root  *os.Root
	dir   string
	pools map[string][]string
	// names binds a pool name the host's settings use to the pool reference
	// it meant: another pool given that name later needs approval.
	names map[string]string
}

type storedExitPins struct {
	Pools map[string][]string `json:"pools"`
	Names map[string]string   `json:"names,omitempty"`
}

// openExitPins reads the pins kept in dir; an empty dir keeps none.
func openExitPins(dir string) (*exitPins, error) {
	pins := &exitPins{pools: map[string][]string{}, names: map[string]string{}}
	if dir == "" {
		return pins, nil
	}
	if !filepath.IsAbs(dir) {
		return nil, errors.New("daemon: exit pin directory must be absolute")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("daemon: opening the exit pin directory: %w", err)
	}
	pins.root, pins.dir = root, dir
	if err := pins.load(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return pins, nil
}

func (p *exitPins) load() error {
	info, err := p.root.Lstat(exitPinsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("daemon: inspecting exit pins: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxExitPinsBytes {
		return errors.New("daemon: exit pins must be a small regular file")
	}
	if err := privatefile.CheckFile(filepath.Join(p.dir, exitPinsFile), info); err != nil {
		return fmt.Errorf("daemon: exit pins: %w", err)
	}
	file, err := p.root.Open(exitPinsFile)
	if err != nil {
		return fmt.Errorf("daemon: opening exit pins: %w", err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxExitPinsBytes+1))
	decoder.DisallowUnknownFields()
	var stored storedExitPins
	if err := decoder.Decode(&stored); err != nil {
		return fmt.Errorf("daemon: decoding exit pins: %w", err)
	}
	if len(stored.Pools) > maxPinnedPools || len(stored.Names) > maxPinnedPools {
		return errors.New("daemon: too many pinned exit pools")
	}
	for name, pool := range stored.Names {
		if name == "" || len(name) > 64 || pool == "" || len(pool) > 64 {
			return errors.New("daemon: exit pins are malformed")
		}
		p.names[name] = pool
	}
	for pool, nodes := range stored.Pools {
		if pool == "" || len(pool) > 64 || len(nodes) > 16 {
			return errors.New("daemon: exit pins are malformed")
		}
		p.pools[pool] = append([]string{}, nodes...)
	}
	return nil
}

// boundPool returns the pool reference name was bound to.
func (p *exitPins) boundPool(name string) (string, bool) {
	if p == nil {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pool, bound := p.names[name]
	return pool, bound
}

// bind binds name to pool and persists it.
func (p *exitPins) bind(name, pool string) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.names[name] == pool {
		return nil
	}
	if _, bound := p.names[name]; !bound && len(p.names) >= maxPinnedPools {
		return errors.New("daemon: too many exit pool names")
	}
	p.names[name] = pool
	return p.persistLocked()
}

// anyPinned reports whether some pool was ever pinned.
func (p *exitPins) anyPinned() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pools) != 0
}

// approved returns the pinned exit nodes of pool, and whether the pool was
// ever pinned.
func (p *exitPins) approved(pool string) ([]string, bool) {
	if p == nil {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	nodes, pinned := p.pools[pool]
	if !pinned {
		return nil, false
	}
	return append([]string{}, nodes...), true // never nil: an empty pin trusts nobody
}

// set records the pinned exit nodes of pool, kept for its candidates only,
// and persists them when they changed.
func (p *exitPins) set(pool string, nodes []string) error {
	if p == nil {
		return nil
	}
	nodes = append([]string{}, nodes...)
	slices.Sort(nodes)
	nodes = slices.Compact(nodes)
	p.mu.Lock()
	defer p.mu.Unlock()
	if current, pinned := p.pools[pool]; pinned && slices.Equal(current, nodes) {
		return nil
	}
	if _, pinned := p.pools[pool]; !pinned && len(p.pools) >= maxPinnedPools {
		for other := range p.pools {
			delete(p.pools, other) // forget one: it pins again on its next use
			break
		}
	}
	p.pools[pool] = nodes
	return p.persistLocked()
}

func (p *exitPins) persistLocked() error {
	if p.root == nil {
		return nil
	}
	encoded, err := json.Marshal(storedExitPins{Pools: p.pools, Names: p.names})
	if err != nil {
		return fmt.Errorf("daemon: encoding exit pins: %w", err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("daemon: naming exit pins: %w", err)
	}
	temporary := ".exit-pins-" + hex.EncodeToString(suffix[:]) + ".tmp"
	file, err := p.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("daemon: writing exit pins: %w", err)
	}
	defer func() {
		_ = file.Close()
		_ = p.root.Remove(temporary)
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("daemon: writing exit pins: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("daemon: syncing exit pins: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("daemon: closing exit pins: %w", err)
	}
	if err := p.root.Rename(temporary, exitPinsFile); err != nil {
		return fmt.Errorf("daemon: replacing exit pins: %w", err)
	}
	return privatefile.SyncDir(p.root)
}
