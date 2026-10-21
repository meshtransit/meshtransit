package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"

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
	// used orders the pools by their last use, so a full store forgets the
	// pool used longest ago; clock counts the uses.
	used  map[string]uint64
	clock uint64
	// writeMu orders the writes; dirty and flushing coalesce the writes made
	// in the background (persistLater), which flushed waits for.
	writeMu  sync.Mutex
	dirty    atomic.Bool
	flushing atomic.Bool
	flushed  sync.WaitGroup
	// logger reports a background write that failed; nil logs nothing.
	logger *slog.Logger
}

type storedExitPins struct {
	Pools map[string][]string `json:"pools"`
	Names map[string]string   `json:"names,omitempty"`
}

// openExitPins reads the pins kept in dir; an empty dir keeps none.
func openExitPins(dir string) (*exitPins, error) {
	pins := &exitPins{pools: map[string][]string{}, names: map[string]string{}, used: map[string]uint64{}}
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

// bind binds name to pool and persists it before it returns.
func (p *exitPins) bind(name, pool string) error {
	changed, err := p.bindInMemory(name, pool)
	if err != nil || !changed {
		return err
	}
	return p.persist()
}

// bindLater binds name to pool and persists it in the background: for
// callers holding a lock a write must not stall.
func (p *exitPins) bindLater(name, pool string) error {
	changed, err := p.bindInMemory(name, pool)
	if changed {
		p.persistLater()
	}
	return err
}

func (p *exitPins) bindInMemory(name, pool string) (bool, error) {
	if p == nil {
		return false, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.names[name] == pool {
		return false, nil
	}
	if _, bound := p.names[name]; !bound && len(p.names) >= maxPinnedPools {
		return false, errors.New("daemon: too many exit pool names")
	}
	p.names[name] = pool
	return true, nil
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

// trust returns the exit nodes of pool the host trusts among candidates:
// all of them at the pool's first use, which pins them, else the pinned
// ones Core still lists, forgetting the others. It reads and writes under
// one lock, so an approval made meanwhile is never undone; the change is
// written in the background. A nil store trusts every candidate.
func (p *exitPins) trust(pool string, candidates []string) []string {
	if p == nil {
		return slices.Clone(candidates)
	}
	p.mu.Lock()
	trusted := slices.Clone(candidates)
	if current, pinned := p.pools[pool]; pinned {
		trusted = slices.DeleteFunc(slices.Clone(current), func(id string) bool { return !slices.Contains(candidates, id) })
	}
	changed := p.setLocked(pool, trusted)
	p.mu.Unlock()
	if changed {
		p.persistLater()
	}
	return trusted
}

// approve adds nodes to the pins of pool, a pool pinned before, and writes
// them before it returns; it returns those not approved already.
func (p *exitPins) approve(pool string, nodes []string) ([]string, error) {
	if p == nil {
		return nil, nil
	}
	p.mu.Lock()
	current, pinned := p.pools[pool]
	var added []string
	for _, node := range nodes {
		if pinned && !slices.Contains(current, node) && !slices.Contains(added, node) {
			added = append(added, node)
		}
	}
	if len(added) != 0 {
		p.setLocked(pool, append(slices.Clone(current), added...))
	}
	p.mu.Unlock()
	if len(added) == 0 {
		return nil, nil
	}
	return added, p.persist()
}

func (p *exitPins) touchLocked(pool string) {
	p.clock++
	p.used[pool] = p.clock
}

// set records the pinned exit nodes of pool, kept for its candidates only,
// and persists them before it returns when they changed.
func (p *exitPins) set(pool string, nodes []string) error {
	if !p.setInMemory(pool, nodes) {
		return nil
	}
	return p.persist()
}

// setInMemory records the pins of pool and reports whether they changed. A
// full store forgets the pool used longest ago, which pins again on its
// next use.
func (p *exitPins) setInMemory(pool string, nodes []string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.setLocked(pool, nodes)
}

// setLocked records the pins of pool as a use of it and reports whether
// they changed.
func (p *exitPins) setLocked(pool string, nodes []string) bool {
	nodes = append([]string{}, nodes...)
	slices.Sort(nodes)
	nodes = slices.Compact(nodes)
	p.touchLocked(pool)
	if current, pinned := p.pools[pool]; pinned && slices.Equal(current, nodes) {
		return false
	}
	if _, pinned := p.pools[pool]; !pinned && len(p.pools) >= maxPinnedPools {
		oldest := ""
		for other := range p.pools {
			if oldest == "" || p.used[other] < p.used[oldest] ||
				(p.used[other] == p.used[oldest] && other < oldest) {
				oldest = other
			}
		}
		delete(p.pools, oldest)
		delete(p.used, oldest)
	}
	p.pools[pool] = nodes
	return true
}

// persistLater writes the pins in the background, one write at a time, the
// last one with the pins as they are then.
func (p *exitPins) persistLater() {
	if p.root == nil {
		return
	}
	p.dirty.Store(true)
	if !p.flushing.CompareAndSwap(false, true) {
		return
	}
	p.flushed.Add(1)
	go func() {
		defer p.flushed.Done()
		for {
			for p.dirty.Swap(false) {
				// Kept in memory when it cannot be written; a restart then
				// pins again what Core lists, so say so.
				if err := p.persist(); err != nil && p.logger != nil {
					p.logger.Warn("writing the exit pins failed", "error", err)
				}
			}
			p.flushing.Store(false)
			if !p.dirty.Load() || !p.flushing.CompareAndSwap(false, true) {
				return
			}
		}
	}()
}

// settle waits for the writes made in the background.
func (p *exitPins) settle() {
	if p != nil {
		p.flushed.Wait()
	}
}

// persist writes the pins as they are when it starts.
func (p *exitPins) persist() error {
	if p.root == nil {
		return nil
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	encoded, err := json.Marshal(storedExitPins{Pools: p.pools, Names: p.names})
	p.mu.Unlock()
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
