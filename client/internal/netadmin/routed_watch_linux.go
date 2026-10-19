//go:build linux

package netadmin

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
)

// routeSettingsPoll is how often the helper notices a change of its route
// settings, such as routes turned off.
const routeSettingsPoll = 5 * time.Second

// watchRouteSettings applies a change of the route settings file to the
// routes meshd last requested, until ctx ends.
func (s *Server) watchRouteSettings(ctx context.Context) {
	ticker := time.NewTicker(routeSettingsPoll)
	defer ticker.Stop()
	last := settingsStamp(s.routed.SettingsPath)
	defer s.clearRouted()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		stamp := settingsStamp(s.routed.SettingsPath)
		if stamp == last {
			continue
		}
		s.mu.Lock()
		applied := true
		if s.hasActiveTUN && s.requestedRouted != nil {
			if _, _, err := s.applyRouted(s.requestedRouted); err != nil {
				// Kept unseen: the next tick tries again, so routes turned
				// off never stay installed after a failure.
				applied = false
				s.logger.Warn("applying changed route settings failed", "error", err)
			} else {
				s.logger.Info("route settings changed; subnet routes reapplied", "routes", len(s.activeRouted))
			}
		}
		s.mu.Unlock()
		if applied {
			last = stamp
		}
	}
}

// clearRouted removes this helper's routed routes and rule when it stops.
func (s *Server) clearRouted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.routedConfigurer.Clear(*s.routed, s.allowedUID); err != nil {
		s.logger.Warn("clearing subnet routes failed", "error", err)
	}
	s.activeRouted, s.requestedRouted = nil, nil
}

// settingsStamp identifies one version of the settings file.
func settingsStamp(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "absent"
	}
	inode := uint64(0)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		inode = stat.Ino
	}
	return fmt.Sprintf("%d:%d:%d:%v", inode, info.Size(), info.ModTime().UnixNano(), info.Mode())
}
