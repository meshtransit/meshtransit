//go:build windows

package dataplane

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/windns"
	"meshtransit.net/client/internal/winfw"
	"meshtransit.net/client/internal/winnet"
)

// A captive portal window on Windows (exit node design §17.6): the service
// reads the window file an administrator writes (meshctl exit captive) and
// starts a short-lived child, meshd captive hold, whose dynamic WFP session
// holds the window's permits in the kill switch's sublayer; the session
// goes with the child, which ends at the window's end, or once the file is
// gone, also when the service is hung or dead. The /1 routes leave the
// adapter for the window: a route cannot tell ports apart, so everything
// but the window's traffic meets the kill switch rather than the tunnel.

// Following a captive portal window.
const (
	// captiveWindowPoll is how often the service reads the window file.
	captiveWindowPoll = time.Second
	// captiveReadyWithin bounds the wait for the child to hold the permits.
	captiveReadyWithin = 5 * time.Second
	// maximumCaptiveSeen bounds the windows a run remembers having opened.
	maximumCaptiveSeen = 64
	// captiveFlushAgain is when the DNS cache is emptied a second time
	// after a window: meshd may answer a name from the network's resolvers
	// in the second it takes to see the window closed.
	captiveFlushAgain = 6 * time.Second
)

// windowsCaptive is the window the service holds open.
type windowsCaptive struct {
	id string
	// until and untilWall end it on the monotonic and the wall clock.
	until     time.Time
	untilWall time.Time
	// opened names the interface it opens; holes are what the child holds.
	opened string
	holes  winfw.Captive
	child  *os.Process
}

// watchCaptive follows the window file for the service's life.
func (o *WindowsTUNOpener) watchCaptive() {
	ticker := time.NewTicker(captiveWindowPoll)
	defer ticker.Stop()
	for range ticker.C {
		o.mu.Lock()
		o.pollCaptiveLocked(time.Now())
		o.mu.Unlock()
	}
}

// pollCaptiveLocked opens a new window, follows the portal meshd found,
// and closes a window that ended or that an administrator closed.
func (o *WindowsTUNOpener) pollCaptiveLocked(now time.Time) {
	window, err := captive.ReadWindow(o.captivePath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		o.closeCaptiveLocked()
		return
	case err != nil:
		o.closeCaptiveLocked()
		_ = captive.CloseWindow(o.captivePath)
		return
	}
	if o.captive != nil && o.captive.id == window.ID {
		if o.captiveRemaining(now) <= 0 {
			o.closeCaptiveLocked()
			_ = captive.CloseWindow(o.captivePath)
			return
		}
		o.followPortalLocked(now)
		return
	}
	o.closeCaptiveLocked()
	settings, err := routesettings.Load(o.routeSettings)
	// A window this run already opened whose file stayed (a delete that
	// failed), or one older than any window lasts, never opens (again).
	if err != nil || settings.ExitCaptiveOff || !o.exitRouting.Routing ||
		slices.Contains(o.captiveSeen, window.ID) || window.Stale(now) {
		_ = captive.CloseWindow(o.captivePath)
		return
	}
	opening, name := windowsCaptiveOpening(o.luid)
	if opening.Interface == 0 {
		_ = captive.CloseWindow(o.captivePath)
		return
	}
	o.captiveSeen = append(o.captiveSeen[max(0, len(o.captiveSeen)-maximumCaptiveSeen+1):], window.ID)
	o.captive = &windowsCaptive{
		id: window.ID, until: now.Add(window.Duration()), untilWall: now.Round(0).Add(window.Duration()),
		opened: name, holes: winfw.Captive{Openings: []winfw.CaptiveOpening{opening}, Portals: o.requestedPortals()},
	}
	if err := o.holdCaptiveLocked(now); err != nil {
		o.closeCaptiveLocked()
		_ = captive.CloseWindow(o.captivePath)
		return
	}
	// The holes first, then the /1 routes go.
	_ = o.replaceAdapterRoutesLocked()
}

// captiveRemaining is how long the window stays open after now.
func (o *WindowsTUNOpener) captiveRemaining(now time.Time) time.Duration {
	if o.captive == nil {
		return 0
	}
	return min(o.captive.until.Sub(now), o.captive.untilWall.Sub(now.Round(0)))
}

// requestedPortals are the portals meshd last proposed.
func (o *WindowsTUNOpener) requestedPortals() [2]netip.AddrPort {
	if o.exitRequest == nil {
		return [2]netip.AddrPort{}
	}
	return o.exitRequest.CaptivePortals
}

// followPortalLocked holds the window again when meshd proposed another
// portal.
func (o *WindowsTUNOpener) followPortalLocked(now time.Time) {
	if o.captive == nil || o.captive.holes.Portals == o.requestedPortals() {
		return
	}
	o.captive.holes.Portals = o.requestedPortals()
	o.stopCaptiveChildLocked()
	if err := o.holdCaptiveLocked(now); err != nil {
		o.closeCaptiveLocked()
		_ = captive.CloseWindow(o.captivePath)
	}
}

// holdCaptiveLocked starts the child that holds the window's permits until
// it ends.
func (o *WindowsTUNOpener) holdCaptiveLocked(now time.Time) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	opening := o.captive.holes.Openings[0]
	remaining := o.captiveRemaining(now)
	args := []string{
		"captive", "hold", "--file", o.captivePath, "--id", o.captive.id,
		"--after", remaining.Round(time.Millisecond).String(),
		"--until", now.Round(0).Add(remaining).UTC().Format(time.RFC3339Nano),
		"--interface", strconv.FormatUint(opening.Interface, 10),
	}
	for _, address := range opening.Addresses {
		args = append(args, "--address", address.String())
	}
	for _, portal := range o.captive.holes.Portals {
		if portal.IsValid() {
			args = append(args, "--portal", portal.String())
		}
	}
	command := exec.Command(self, args...) //nolint:gosec,noctx // G204: this binary; it outlives every context on purpose
	ready, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	child := command.Process
	// The window opens only once the child holds its permits: without them
	// taking the /1 routes away would only cut the host off.
	held := make(chan bool, 1)
	go func() {
		line, _ := bufio.NewReader(ready).ReadString('\n')
		held <- strings.TrimSpace(line) == captiveHoldReady
		_, _ = io.Copy(io.Discard, ready)
	}()
	select {
	case ok := <-held:
		if !ok {
			_ = child.Kill()
			_ = command.Wait()
			return errors.New("dataplane: the captive portal window's permits could not be held")
		}
	case <-time.After(captiveReadyWithin):
		_ = child.Kill()
		_ = command.Wait()
		return errors.New("dataplane: the captive portal window's permits were not held in time")
	}
	o.captive.child = child
	go o.captiveChildEnded(command, child)
	return nil
}

// captiveHoldReady is what meshd captive hold prints once it holds the
// window's permits.
const captiveHoldReady = "held"

// captiveChildEnded closes the window when its child ends while the window
// is still open: its permits are gone, so the /1 routes come back.
func (o *WindowsTUNOpener) captiveChildEnded(command *exec.Cmd, child *os.Process) {
	_ = command.Wait()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.captive != nil && o.captive.child == child {
		o.captive.child = nil
		o.closeCaptiveLocked()
		_ = captive.CloseWindow(o.captivePath)
	}
}

// stopCaptiveChildLocked ends the child: its permits go with its session.
func (o *WindowsTUNOpener) stopCaptiveChildLocked() {
	if o.captive != nil && o.captive.child != nil {
		_ = o.captive.child.Kill()
		o.captive.child = nil
	}
}

// closeCaptiveLocked ends the window, if one is open: the permits go, the
// /1 routes come back, and the DNS cache forgets the portal's network.
func (o *WindowsTUNOpener) closeCaptiveLocked() {
	if o.captive == nil {
		return
	}
	o.stopCaptiveChildLocked()
	o.captive = nil
	_ = o.replaceAdapterRoutesLocked()
	_ = windns.FlushCache()
	time.AfterFunc(captiveFlushAgain, func() { _ = windns.FlushCache() })
}

// replaceAdapterRoutesLocked installs the adapter's routes as they are now.
func (o *WindowsTUNOpener) replaceAdapterRoutesLocked() error {
	if o.luid == 0 {
		return nil
	}
	_, err := winnet.ReplaceRoutesReporting(o.luid, o.adapterRoutesLocked(o.routed))
	return err
}

// captiveView is the window for meshd.
func (o *WindowsTUNOpener) captiveView(now time.Time) netadmin.CaptiveWindow {
	remaining := o.captiveRemaining(now)
	if o.captive == nil || remaining <= 0 || !o.exitRouting.Routing {
		return netadmin.CaptiveWindow{}
	}
	return netadmin.CaptiveWindow{ID: o.captive.id, Remaining: remaining.Round(time.Second), Interface: o.captive.opened}
}

// windowsCaptiveOpening is where a window opens: the interface of the
// default route with the lowest metric but the adapter's, IPv4 first, with
// its addresses but link-local ones, and its alias.
func windowsCaptiveOpening(adapter uint64) (winfw.CaptiveOpening, string) {
	var best *winipcfg.MibIPforwardRow2
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			continue
		}
		bestMetric := uint64(0)
		for index := range rows {
			row := &rows[index]
			if row.DestinationPrefix.Prefix().Bits() != 0 || uint64(row.InterfaceLUID) == adapter {
				continue
			}
			// Windows ranks routes by the route's metric plus its
			// interface's.
			metric := uint64(row.Metric)
			if link, err := row.InterfaceLUID.IPInterface(family); err == nil {
				metric += uint64(link.Metric)
			}
			if best == nil || metric < bestMetric {
				best, bestMetric = row, metric
			}
		}
		if best != nil {
			break
		}
	}
	if best == nil {
		return winfw.CaptiveOpening{}, ""
	}
	opening := winfw.CaptiveOpening{Interface: uint64(best.InterfaceLUID)}
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return winfw.CaptiveOpening{}, ""
	}
	for index := range rows {
		row := &rows[index]
		address := row.Address.Addr().Unmap().WithZone("")
		if row.InterfaceLUID == best.InterfaceLUID && address.IsValid() && !address.IsLinkLocalUnicast() &&
			!slices.Contains(opening.Addresses, address) && len(opening.Addresses) < 8 {
			opening.Addresses = append(opening.Addresses, address)
		}
	}
	if len(opening.Addresses) == 0 {
		return winfw.CaptiveOpening{}, ""
	}
	name := "the network"
	if row, err := best.InterfaceLUID.Interface(); err == nil && row.Alias() != "" {
		name = row.Alias()
	}
	return opening, name
}
