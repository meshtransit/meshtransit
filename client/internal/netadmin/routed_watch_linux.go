//go:build linux

package netadmin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
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
	last := s.routedStamp()
	defer s.clearRouted()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.checkServedRules()
		stamp := s.routedStamp()
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
				s.logger.Info("route settings changed; subnet routes reapplied", "routes", len(s.activeRouted.Routes))
			}
		}
		if s.hasActiveTUN && s.requestedServed != nil && s.servedConfigurer != nil {
			if _, _, err := s.applyServed(*s.requestedServed); err != nil {
				applied = false
				s.logger.Warn("applying changed route settings to forwarding failed", "error", err)
			} else {
				s.logger.Info("route settings changed; subnet forwarding reapplied", "served", len(s.activeServed))
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
	s.activeRouted, s.requestedRouted = routedState{}, nil
	s.clearServed()
}

// checkServedRules installs the router rules again when another tool removed
// them, such as a firewall reload flushing every table.
func (s *Server) checkServedRules() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.servedConfigurer == nil || len(s.activeServed) == 0 || s.requestedServed == nil {
		return
	}
	present, err := s.servedConfigurer.Present()
	if err == nil && present {
		return
	}
	s.logger.Warn("subnet router rules are missing; installing them again", "error", err)
	if _, _, err := s.applyServed(*s.requestedServed); err != nil {
		s.logger.Warn("installing subnet router rules again failed", "error", err)
	}
}

// routedStamp identifies what the routes installed depend on: the settings
// file, the host's own routes and its resolvers. A change of either, such
// as a laptop joining another network, applies the last request again.
func (s *Server) routedStamp() string {
	s.mu.Lock()
	name := s.activeName
	s.mu.Unlock()
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "settings %s\n", settingsStamp(s.routed.SettingsPath))
	local, err := s.hostRouting.LocalRoutes(name)
	if err != nil {
		_, _ = fmt.Fprintf(digest, "local unknown\n")
	}
	slices.SortFunc(local, func(first, second localRoute) int { return compareRoutedPrefixes(first.Prefix, second.Prefix) })
	for _, route := range local {
		_, _ = fmt.Fprintf(digest, "local %s %t\n", route.Prefix, route.Connected)
	}
	for _, resolver := range s.hostRouting.Resolvers() {
		_, _ = fmt.Fprintf(digest, "resolver %s\n", resolver)
	}
	return hex.EncodeToString(digest.Sum(nil))
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
