//go:build darwin

package netadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/hostroute"
)

// A captive portal window on macOS (exit node design §17.6): rules in the
// kill switch's own anchor let the host's TCP to ports 80 and 443, and to
// the portal, out by the physical default route's interface from its own
// address, without state, so they stop the moment the rules go; the /1
// routes into the utun go for the window, since a route cannot tell ports
// apart, and everything else is dropped rather than sent through the
// tunnel. Two things outside the helper end the window should it die or
// hang: a child process the helper starts for the window, which sleeps until
// it ends, and a launchd job every 30 s; both load the kill switch without
// the window's rules, which the helper keeps in the holes state file, and
// put the /1 routes back.

const (
	// captiveLabel marks the window's pf rules.
	captiveLabel = "meshtransit-captive"
	// maximumCaptiveInterfaces bounds the interfaces a window opens.
	maximumCaptiveInterfaces = 4
	// maximumCaptiveState bounds the holes state file read.
	maximumCaptiveState = 64 << 10
)

// DarwinCaptiveStatePath is where the helper keeps what ends a window
// without it, next to its socket.
func DarwinCaptiveStatePath(helperSocket string) string {
	return filepath.Join(filepath.Dir(helperSocket), "captive-holes.json")
}

// darwinCaptiveState is what ends a window without the helper: the window,
// when it ends on the wall clock, the utun the /1 routes go back to, and the
// kill switch without the window's rules.
type darwinCaptiveState struct {
	ID    string    `json:"id"`
	Until time.Time `json:"until"`
	UTun  string    `json:"utun,omitempty"`
	Rules string    `json:"rules"`
}

// pfCaptiveRules are the window's rules on interfaces: TCP from each one's
// own address to ports 80 and 443 anywhere, and to the portals.
func pfCaptiveRules(interfaces []string, portals [2]netip.AddrPort) string {
	var rules strings.Builder
	for _, name := range interfaces {
		for _, family := range []struct {
			name string
			slot int
		}{{"inet", 0}, {"inet6", 1}} {
			prefix := "pass out quick on " + name + " " + family.name + " proto tcp from (" + name + ") to "
			rules.WriteString(prefix + "any port { 80 443 } no state label \"" + captiveLabel + "\"\n")
			if portal := portals[family.slot]; portal.IsValid() {
				rules.WriteString(prefix + portal.Addr().String() + " port " + strconv.Itoa(int(portal.Port())) +
					" no state label \"" + captiveLabel + "\"\n")
			}
		}
	}
	return rules.String()
}

// darwinCaptiveInterfaces names the interfaces of the host's physical
// default routes, where the window opens.
func darwinCaptiveInterfaces() []string {
	table, err := hostroute.Read()
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range physicalDefaults(table) {
		name := interfaceName(entry.Index)
		if validHostInterfaceName(name) && !slices.Contains(names, name) && len(names) < maximumCaptiveInterfaces {
			names = append(names, name)
		}
	}
	return names
}

// openCaptive keeps what ends window without the helper and starts the
// child process that ends it on time, once per window. It returns the
// interfaces the window opens; none when the host has no physical default
// route, or the window cannot be made to end without the helper.
func (c *darwinExitRouteConfigurer) openCaptive(name, closed string, window *exitCaptive) []string {
	interfaces := c.interfaces()
	if len(interfaces) == 0 || c.holesPath == "" {
		return nil
	}
	state := darwinCaptiveState{ID: window.ID, Until: time.Now().Round(0).Add(window.Remaining), UTun: name, Rules: closed}
	if err := writeCaptiveState(c.holesPath, state); err != nil {
		c.warnf("keeping the captive portal window's end failed; not opening it", "error", err)
		return nil
	}
	if c.expiring != window.ID {
		if err := c.spawnExpiry(window.ID, window.Remaining); err != nil {
			// The launchd job still ends it within 30 s of its time.
			c.warnf("starting the captive portal window's timer failed", "error", err)
		}
		c.expiring = window.ID
	}
	return interfaces
}

// closeCaptive forgets the window's state: the kill switch was loaded
// without its rules.
func (c *darwinExitRouteConfigurer) closeCaptive() {
	c.expiring = ""
	if c.holesPath == "" {
		return
	}
	if err := os.Remove(c.holesPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		c.warnf("removing the captive portal window's state failed", "error", err)
	}
}

func (c *darwinExitRouteConfigurer) warnf(message string, args ...any) {
	if c.warn != nil {
		c.warn(message, args...)
	}
}

// removeDarwinExitHalves removes the /1 routes into the utun, keeping the
// scoped defaults meshd's sockets use: during a window the host's packets
// follow its own default routes, where the kill switch lets the window's
// through and drops the rest.
func removeDarwinExitHalves() error {
	table, err := hostroute.Read()
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range table {
		if entry.ExitOwned() {
			failures = append(failures, deleteDarwinExitRoute(entry.Prefix, entry.Gateway))
		}
	}
	return errors.Join(failures...)
}

// writeCaptiveState replaces path with state, readable by root only.
func writeCaptiveState(path string, state darwinCaptiveState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".captive-holes-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// readCaptiveState reads the holes state at path, only when root owns it
// and no one else may write it.
func readCaptiveState(path string) (darwinCaptiveState, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the helper's own state
	if err != nil {
		return darwinCaptiveState{}, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return darwinCaptiveState{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || !info.Mode().IsRegular() {
		return darwinCaptiveState{}, errors.New("netadmin: the captive portal window state is not root's alone")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumCaptiveState+1))
	if err != nil {
		return darwinCaptiveState{}, err
	}
	var state darwinCaptiveState
	if len(encoded) > maximumCaptiveState || json.Unmarshal(encoded, &state) != nil ||
		!strings.Contains(state.Rules, "block drop out quick all") || strings.Contains(state.Rules, captiveLabel) ||
		(state.UTun != "" && !strings.HasPrefix(state.UTun, "utun")) {
		return darwinCaptiveState{}, errors.New("netadmin: the captive portal window state is invalid")
	}
	return state, nil
}

// ExpireDarwinCaptive ends a captive portal window the helper did not: the
// one named id (the child process the helper started for it), or with no id
// any window past its time (the launchd job). It loads the kill switch
// without the window's rules, puts the /1 routes back on the utun, and
// empties the host's DNS cache. A window the helper already closed, or a
// newer one, is left alone.
func ExpireDarwinCaptive(statePath, id string, now time.Time) error {
	unlock, err := lockCaptive(statePath)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := readCaptiveState(statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if (id != "" && state.ID != id) || (id == "" && now.Before(state.Until)) {
		return nil
	}
	configurer := newDarwinExitRouteConfigurer(0, "")
	if err := configurer.load(state.Rules); err != nil {
		return err
	}
	if state.UTun != "" {
		if _, err := net.InterfaceByName(state.UTun); err == nil {
			if err := replaceDarwinExitRoutes(state.UTun, nil); err != nil {
				return err
			}
		}
	}
	flushDarwinDNSCache(context.Background())
	if err := os.Remove(statePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// spawnDarwinExpiry starts the child process that ends window id after
// remaining, in a session of its own, so it outlives a helper that dies.
func spawnDarwinExpiry(statePath string) func(id string, remaining time.Duration) error {
	return func(id string, remaining time.Duration) error {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		command := exec.CommandContext(context.Background(), self, "captive", "close-at", //nolint:gosec // G204: this binary
			"--state", statePath, "--id", id, "--after", remaining.Round(time.Millisecond).String())
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := command.Start(); err != nil {
			return err
		}
		return command.Process.Release()
	}
}

// flushDarwinDNSCache empties mDNSResponder's cache, best effort.
func flushDarwinDNSCache(ctx context.Context) {
	for _, command := range [][]string{{"/usr/bin/dscacheutil", "-flushcache"}, {"/usr/bin/killall", "-HUP", "mDNSResponder"}} {
		run, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = exec.CommandContext(run, command[0], command[1:]...).Run() //nolint:gosec // G204: fixed system tools
		cancel()
	}
}

// FlushCaches empties the host's DNS cache: answers a captive portal's
// network gave during a window must not outlive it.
func (c *scutilConfigurator) FlushCaches(ctx context.Context) error {
	flushDarwinDNSCache(ctx)
	return nil
}

// lockCaptive takes the lock the helper and what ends a window without it
// share, next to the holes state at statePath: neither loads the kill
// switch while the other reads or changes it. Without a state path there is
// nothing to share.
func lockCaptive(statePath string) (func(), error) {
	if statePath == "" {
		return func() {}, nil
	}
	path := filepath.Join(filepath.Dir(statePath), "captive.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: the helper's runtime directory
	if err != nil {
		return nil, fmt.Errorf("netadmin: opening the captive portal window lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("netadmin: taking the captive portal window lock: %w", err)
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}
