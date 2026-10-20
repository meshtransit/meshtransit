// Package routesettings holds the host's own subnet route settings
// (mtcp-v1 §7.6): whether the node installs the routes Core grants it, which
// subnets it forwards as a router, and whether it may be an exit node
// (mtcp-v1 §7.7) and within which limits. They live in a file only root (or,
// on Windows, SYSTEM and administrators) can write, so a compromised meshd
// or Core cannot turn routes on, make the host a router or an exit node, or
// widen its limits.
package routesettings

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
)

const (
	// MaximumAdvertised bounds the subnets a host offers (mtcp-v1 §8.2).
	MaximumAdvertised = 256
	// maximumFileBytes bounds the settings file.
	maximumFileBytes = 64 << 10
	// DefaultExitConntrackPerConsumer is how many connections one consumer
	// may hold through this exit node unless the settings lower it (exit
	// node design §4.3); Core's value only lowers it further.
	DefaultExitConntrackPerConsumer = 16384
	// DefaultExitMaxConsumers is how many consumers the exit node forwards
	// for unless the settings say otherwise.
	DefaultExitMaxConsumers = 256
	// Bounds of the exit limits.
	MinimumExitConntrack = 1024
	MaximumExitConntrack = 262144
	MaximumExitConsumers = 4096
)

var (
	// ErrInvalid reports settings that are malformed or unsafe.
	ErrInvalid = errors.New("routesettings: invalid settings")
	// ErrUnsafeFile reports a settings file someone other than root could
	// have written.
	ErrUnsafeFile = errors.New("routesettings: settings file is writable by others than root")
)

// Settings are one host's subnet route settings. The zero value, which a
// missing file means, turns everything off.
type Settings struct {
	// AcceptRoutes installs the private subnet routes Core grants.
	AcceptRoutes bool
	// AcceptPublicRoutes also installs granted routes to public ranges.
	AcceptPublicRoutes bool
	// RouterMode lets the host forward into the subnets it advertises.
	RouterMode bool
	// AdvertiseRoutes are the subnets the host offers to forward, canonical
	// and sorted.
	AdvertiseRoutes []netip.Prefix
	// ExitMode offers the host as an exit node: it forwards other Devices'
	// Internet traffic for the Exit Pool Core assigns it to.
	ExitMode bool
	// ExitSMTPAllowed lets consumers open TCP port 25 to the Internet; off,
	// a pool that allows it cannot.
	ExitSMTPAllowed bool
	// ExitConntrackPerConsumerMax and ExitMaxConsumers bound what Core may
	// ask of the exit node; zero is the default.
	ExitConntrackPerConsumerMax int
	ExitMaxConsumers            int
}

type document struct {
	AcceptRoutes                bool     `json:"accept_routes"`
	AcceptPublicRoutes          bool     `json:"accept_public_routes"`
	RouterMode                  bool     `json:"router_mode"`
	AdvertiseRoutes             []string `json:"advertise_routes"`
	ExitMode                    bool     `json:"exit_mode,omitempty"`
	ExitSMTPAllowed             bool     `json:"exit_smtp_allowed,omitempty"`
	ExitConntrackPerConsumerMax int      `json:"exit_conntrack_per_consumer_max,omitempty"`
	ExitMaxConsumers            int      `json:"exit_max_consumers,omitempty"`
}

// ExitConntrackLimit is the connections one consumer may hold through this
// exit node: the settings' maximum (or the default), lowered to Core's when
// Core asks for fewer. Core never raises it.
func (settings Settings) ExitConntrackLimit(core int) int {
	limit := settings.ExitConntrackPerConsumerMax
	if limit == 0 {
		limit = DefaultExitConntrackPerConsumer
	}
	if core > 0 && core < limit {
		limit = core
	}
	return limit
}

// ExitConsumerLimit is how many consumers the exit node forwards for.
func (settings Settings) ExitConsumerLimit() int {
	if settings.ExitMaxConsumers == 0 {
		return DefaultExitMaxConsumers
	}
	return settings.ExitMaxConsumers
}

// ExitSMTP reports whether consumers may open TCP port 25: only when both
// the host and Core's pool allow it.
func (settings Settings) ExitSMTP(core bool) bool { return settings.ExitSMTPAllowed && core }

// Validate accepts at most MaximumAdvertised advertised subnets, each one a
// Site could use (Usable) and none listed twice.
func (settings Settings) Validate() error {
	if limit := settings.ExitConntrackPerConsumerMax; limit != 0 &&
		(limit < MinimumExitConntrack || limit > MaximumExitConntrack) {
		return fmt.Errorf("%w: exit connection limit outside %d..%d", ErrInvalid, MinimumExitConntrack,
			MaximumExitConntrack)
	}
	if consumers := settings.ExitMaxConsumers; consumers < 0 || consumers > MaximumExitConsumers {
		return fmt.Errorf("%w: exit consumer limit outside 1..%d", ErrInvalid, MaximumExitConsumers)
	}
	if len(settings.AdvertiseRoutes) > MaximumAdvertised {
		return fmt.Errorf("%w: more than %d advertised routes", ErrInvalid, MaximumAdvertised)
	}
	for index, prefix := range settings.AdvertiseRoutes {
		if reason := Usable(prefix); reason != "" {
			return fmt.Errorf("%w: advertised route %s: %s", ErrInvalid, prefix, reason)
		}
		if slices.Contains(settings.AdvertiseRoutes[:index], prefix) {
			return fmt.Errorf("%w: advertised route %s listed twice", ErrInvalid, prefix)
		}
	}
	return nil
}

// Canonical returns settings with the advertised routes sorted.
func (settings Settings) Canonical() Settings {
	settings.AdvertiseRoutes = slices.Clone(settings.AdvertiseRoutes)
	slices.SortFunc(settings.AdvertiseRoutes, comparePrefixes)
	return settings
}

// Load reads the settings at path. A missing file means everything off; a
// file others than root could write is refused (ErrUnsafeFile).
func Load(path string) (Settings, error) {
	file, err := openSettings(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("routesettings: opening %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return Settings{}, fmt.Errorf("routesettings: reading %s: %w", path, err)
	}
	if err := checkOwner(info); err != nil {
		return Settings{}, err
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumFileBytes+1))
	if err != nil {
		return Settings{}, fmt.Errorf("routesettings: reading %s: %w", path, err)
	}
	if len(encoded) > maximumFileBytes {
		return Settings{}, fmt.Errorf("%w: file larger than %d bytes", ErrInvalid, maximumFileBytes)
	}
	return Decode(encoded)
}

// Decode parses settings, refusing unknown fields and trailing data.
func Decode(encoded []byte) (Settings, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value document
	if err := decoder.Decode(&value); err != nil {
		return Settings{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if decoder.More() {
		return Settings{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	settings := Settings{
		AcceptRoutes: value.AcceptRoutes, AcceptPublicRoutes: value.AcceptPublicRoutes,
		RouterMode: value.RouterMode, ExitMode: value.ExitMode, ExitSMTPAllowed: value.ExitSMTPAllowed,
		ExitConntrackPerConsumerMax: value.ExitConntrackPerConsumerMax, ExitMaxConsumers: value.ExitMaxConsumers,
	}
	for _, text := range value.AdvertiseRoutes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return Settings{}, fmt.Errorf("%w: advertised route %q", ErrInvalid, text)
		}
		settings.AdvertiseRoutes = append(settings.AdvertiseRoutes, prefix)
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, err
	}
	return settings.Canonical(), nil
}

// Encode returns the canonical file form of settings.
func Encode(settings Settings) ([]byte, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	settings = settings.Canonical()
	value := document{
		AcceptRoutes: settings.AcceptRoutes, AcceptPublicRoutes: settings.AcceptPublicRoutes,
		RouterMode: settings.RouterMode, AdvertiseRoutes: make([]string, len(settings.AdvertiseRoutes)),
		ExitMode: settings.ExitMode, ExitSMTPAllowed: settings.ExitSMTPAllowed,
		ExitConntrackPerConsumerMax: settings.ExitConntrackPerConsumerMax, ExitMaxConsumers: settings.ExitMaxConsumers,
	}
	for index, prefix := range settings.AdvertiseRoutes {
		value.AdvertiseRoutes[index] = prefix.String()
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("routesettings: encoding: %w", err)
	}
	return append(encoded, '\n'), nil
}

// Save writes settings to path atomically, readable by everyone and
// writable by its owner only. Only root (or SYSTEM) runs it.
func Save(path string, settings Settings) error {
	encoded, err := Encode(settings)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := prepareDirectory(directory); err != nil {
		return fmt.Errorf("routesettings: preparing %s: %w", directory, err)
	}
	temporary, err := os.CreateTemp(directory, ".routes-*.json")
	if err != nil {
		return fmt.Errorf("routesettings: writing %s: %w", path, err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("routesettings: writing %s: %w", path, err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("routesettings: writing %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("routesettings: writing %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("routesettings: writing %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("routesettings: replacing %s: %w", path, err)
	}
	return syncDirectory(directory)
}

func comparePrefixes(first, second netip.Prefix) int {
	return cmp.Or(first.Addr().Compare(second.Addr()), cmp.Compare(first.Bits(), second.Bits()))
}
