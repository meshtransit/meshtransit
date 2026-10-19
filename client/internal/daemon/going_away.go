package daemon

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"time"
)

// restartMarkerFresh is how long a restart marker holds: a package upgrade
// restarts meshd within it.
const restartMarkerFresh = 2 * time.Minute

// restartExpected reports whether path holds a restart marker written within
// restartMarkerFresh of now.
func restartExpected(path string, now time.Time) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) <= restartMarkerFresh
}

// clearRestartMarker removes the marker of a restart that has happened, so
// it cannot keep a later stop from being announced.
func clearRestartMarker(path string, logger *slog.Logger) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) && logger != nil {
		logger.Warn("removing the restart marker failed", "error", err)
	}
}
