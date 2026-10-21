package captive

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// A captive portal window lets the host's own HTTP and HTTPS out to the
// physical network for a short while, so its user can sign in to a portal
// while the host uses an exit node (exit node design §17.4). Only root (or
// an administrator on Windows) opens one, by writing the window file the
// helper reads; the helper counts the window from when it read it, on its
// monotonic clock, so neither the file's times nor a clock that jumps make
// it longer.
const (
	// DefaultWindow is how long a window stays open unless asked otherwise.
	DefaultWindow = 2 * time.Minute
	// MaximumWindow is the longest window; the helper clamps it too.
	MaximumWindow = 5 * time.Minute
	// maximumWindowFileBytes bounds the file read.
	maximumWindowFileBytes = 1 << 10
)

// ErrWindowInvalid is a window file the helper does not honour.
var ErrWindowInvalid = errors.New("captive: window file is invalid")

// windowIDPattern is a window's identifier: 16 random bytes in hex.
var windowIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Window is one window as root opened it.
type Window struct {
	// ID tells one window from the next: opening again is a new window,
	// counted from when the helper reads it.
	ID string `json:"id"`
	// Seconds is how long the window stays open.
	Seconds int `json:"seconds"`
	// Opened is when root opened it, for status only.
	Opened time.Time `json:"opened"`
}

// Duration is how long the window stays open, clamped to MaximumWindow.
func (w Window) Duration() time.Duration {
	return min(time.Duration(w.Seconds)*time.Second, MaximumWindow)
}

// OpenWindow writes a new window of duration to path, replacing any open
// one, readable by its owner only. Root runs it.
func OpenWindow(path string, duration time.Duration, now time.Time) (Window, error) {
	if duration <= 0 || duration > MaximumWindow {
		return Window{}, fmt.Errorf("captive: a window lasts up to %s", MaximumWindow)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Window{}, fmt.Errorf("captive: choosing a window id: %w", err)
	}
	window := Window{
		ID: hex.EncodeToString(id[:]), Seconds: int(duration.Round(time.Second) / time.Second),
		Opened: now.UTC().Truncate(time.Second),
	}
	window.Seconds = max(window.Seconds, 1)
	encoded, err := json.Marshal(window)
	if err != nil {
		return Window{}, fmt.Errorf("captive: encoding the window: %w", err)
	}
	if err := writeWindowFile(path, append(encoded, '\n')); err != nil {
		return Window{}, err
	}
	return window, nil
}

// CloseWindow removes the window file; closing none is no error.
func CloseWindow(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("captive: closing the window: %w", err)
	}
	return nil
}

// ReadWindow reads the window at path: os.ErrNotExist when none is open,
// ErrWindowInvalid for a file root did not write as OpenWindow does.
func ReadWindow(path string) (Window, error) {
	file, err := openWindowFile(filepath.Clean(path))
	if err != nil {
		return Window{}, err
	}
	defer func() { _ = file.Close() }()
	encoded, err := io.ReadAll(io.LimitReader(file, maximumWindowFileBytes+1))
	if err != nil {
		return Window{}, fmt.Errorf("captive: reading the window: %w", err)
	}
	return decodeWindow(encoded)
}

// decodeWindow parses a window file, refusing anything OpenWindow would not
// write.
func decodeWindow(encoded []byte) (Window, error) {
	if len(encoded) > maximumWindowFileBytes {
		return Window{}, fmt.Errorf("%w: larger than %d bytes", ErrWindowInvalid, maximumWindowFileBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var window Window
	if err := decoder.Decode(&window); err != nil || decoder.More() {
		return Window{}, fmt.Errorf("%w: not a window", ErrWindowInvalid)
	}
	if !windowIDPattern.MatchString(window.ID) || window.Seconds < 1 ||
		window.Seconds > int(MaximumWindow/time.Second) {
		return Window{}, fmt.Errorf("%w: id or duration out of range", ErrWindowInvalid)
	}
	return window, nil
}

// writeWindowFile replaces path with data atomically, owner-only.
func writeWindowFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".captive-*.json")
	if err != nil {
		return fmt.Errorf("captive: writing the window: %w", err)
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("captive: writing the window: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("captive: writing the window: %w", err)
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return fmt.Errorf("captive: writing the window: %w", err)
	}
	return nil
}
