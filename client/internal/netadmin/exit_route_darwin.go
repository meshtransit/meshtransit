//go:build darwin

package netadmin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/hostroute"
)

const (
	// exitAnchor is the pf anchor of the kill switch. macOS's own
	// /etc/pf.conf evaluates every anchor under com.apple, so the rules
	// apply without changing the host's pf.conf.
	exitAnchor = "com.apple/250.MeshTransitExit"
	// DefaultPfctlPath is the trusted pfctl binary.
	DefaultPfctlPath = "/sbin/pfctl"
	// pfctlTimeout bounds one pfctl run.
	pfctlTimeout = 10 * time.Second
	// maximumDarwinExitLAN bounds the LAN subnets the kill switch admits.
	maximumDarwinExitLAN = 64
)

// darwinExitRoutes send the host's Internet traffic into the utun: halves
// of each family, more specific than any default route. A more specific
// route still wins, which the kill switch answers (exit node design §6.3).
var darwinExitRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
}

// pfToken matches the reference pfctl -E prints.
var pfToken = regexp.MustCompile(`(?m)^Token\s*:\s*([0-9]+)\s*$`)

// darwinExitRouteConfigurer sends the host's Internet traffic into the mesh
// utun behind a pf kill switch in an anchor of its own, which lets out only
// loopback, the utun, meshd's sockets (by user), DHCP, neighbour discovery,
// link-local addresses and the allowed LAN. pf is enabled with a reference
// (pfctl -E), released when the kill switch goes, so a host whose pf was off
// gets it back off. pf keeps the rules while the helper is down; a reboot
// drops them until the helper starts again.
type darwinExitRouteConfigurer struct {
	uid       uint32
	pfctl     string
	tokenPath string
	run       func(ctx context.Context, path string, args []string, stdin string) ([]byte, error)
	lan       func() []netip.Prefix
	// warn reports what failed without failing the exit route; nil drops it.
	warn func(message string, args ...any)
	// holesPath keeps what ends a captive portal window without the
	// helper; empty opens no window. interfaces names where a window
	// opens, spawnExpiry starts the child process that ends one, and
	// expiring is the window it was started for.
	holesPath   string
	interfaces  func() []string
	spawnExpiry func(id string, remaining time.Duration) error
	expiring    string
}

func newDarwinExitRouteConfigurer(uid uint32, statePath string) *darwinExitRouteConfigurer {
	return &darwinExitRouteConfigurer{
		uid: uid, pfctl: DefaultPfctlPath, tokenPath: statePath, run: runPfctl, lan: darwinAttachedLAN,
		interfaces: darwinCaptiveInterfaces,
	}
}

// withCaptive lets the configurer open captive portal windows, keeping
// their state at holesPath.
func (c *darwinExitRouteConfigurer) withCaptive(holesPath string) *darwinExitRouteConfigurer {
	c.holesPath, c.spawnExpiry = holesPath, spawnDarwinExpiry(holesPath)
	return c
}

// DarwinExitStatePath is where the pf enable reference is kept, next to
// the helper's socket.
func DarwinExitStatePath(helperSocket string) string {
	return filepath.Join(filepath.Dir(helperSocket), "exit-pf-token")
}

// Replace installs the kill switch, then the routes on name; without a
// utun the host stays closed. A captive portal window opens the kill switch
// for its rules on the physical default routes' interfaces and takes the
// /1 routes away until it ends.
func (c *darwinExitRouteConfigurer) Replace(name string, _, allowLAN bool, window *exitCaptive) (string, error) {
	if name != "" && (!validInterfaceName(name) || !strings.HasPrefix(name, "utun")) {
		return "", errors.New("netadmin: exit route target is invalid")
	}
	unlock, err := lockCaptive(c.holesPath)
	if err != nil {
		return "", err
	}
	defer unlock()
	var lan []netip.Prefix
	if allowLAN {
		lan = c.lan()
	}
	if err := c.enable(); err != nil {
		return "", err
	}
	closed := pfExitRules(name, c.uid, lan, "")
	var opened []string
	if window != nil {
		opened = c.openCaptive(name, closed, window)
	}
	rules := closed
	if len(opened) != 0 {
		rules = pfExitRules(name, c.uid, lan, pfCaptiveRules(opened, window.Portals))
	}
	if err := c.load(rules); err != nil {
		return "", err
	}
	if len(opened) == 0 {
		c.closeCaptive()
	}
	if name == "" {
		return firstOf(opened), nil
	}
	if len(opened) != 0 {
		return opened[0], removeDarwinExitHalves()
	}
	return "", replaceDarwinExitRoutes(name, c.warn)
}

func firstOf(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// Present reports whether the anchor holds rules.
func (c *darwinExitRouteConfigurer) Present() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	output, err := c.run(ctx, c.pfctl, []string{"-a", exitAnchor, "-s", "rules"}, "")
	if err != nil || !bytes.Contains(output, []byte("block drop out")) {
		return false, err
	}
	return c.enabled()
}

// Stamp identifies the utun, the attached LAN the rules follow and the
// physical default routes the scoped defaults copy.
func (c *darwinExitRouteConfigurer) Stamp(name string) string {
	values := []string{name}
	for _, prefix := range c.lan() {
		values = append(values, prefix.String())
	}
	if table, err := hostroute.Read(); err == nil {
		var defaults []string
		for _, entry := range physicalDefaults(table) {
			defaults = append(defaults, fmt.Sprintf("default %d %v", entry.Index, entry.Gateway))
		}
		slices.Sort(defaults)
		values = append(values, defaults...)
	}
	return strings.Join(values, ",")
}

// Clear removes the routes first and the kill switch last.
func (c *darwinExitRouteConfigurer) Clear() error {
	unlock, err := lockCaptive(c.holesPath)
	if err != nil {
		return err
	}
	defer unlock()
	c.closeCaptive()
	if err := clearDarwinExitRoutes(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	if _, err := c.run(ctx, c.pfctl, []string{"-a", exitAnchor, "-F", "rules"}, ""); err != nil {
		return fmt.Errorf("netadmin: flushing the exit kill switch: %w", err)
	}
	return c.release()
}

// enabled reports whether pf filters at all: a reference kept from before
// a reboot, or pf turned off by someone else, holds nothing.
func (c *darwinExitRouteConfigurer) enabled() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	output, err := c.run(ctx, c.pfctl, []string{"-s", "info"}, "")
	if err != nil {
		return false, fmt.Errorf("netadmin: reading pf status: %w", err)
	}
	return bytes.Contains(output, []byte("Status: Enabled")), nil
}

// enable turns pf on with a reference of the helper's own, once while pf
// stays on.
func (c *darwinExitRouteConfigurer) enable() error {
	if token, err := os.ReadFile(c.tokenPath); err == nil && len(bytes.TrimSpace(token)) != 0 {
		if on, err := c.enabled(); err != nil || on {
			return err
		}
		_ = os.Remove(c.tokenPath) // a reference pf no longer holds
	}
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	output, err := c.run(ctx, c.pfctl, []string{"-E"}, "")
	if err != nil {
		return fmt.Errorf("netadmin: enabling pf: %w", err)
	}
	match := pfToken.FindSubmatch(output)
	if match == nil {
		return errors.New("netadmin: enabling pf returned no reference")
	}
	if err := os.WriteFile(c.tokenPath, append(match[1], '\n'), 0o600); err != nil {
		return fmt.Errorf("netadmin: keeping the pf reference: %w", err)
	}
	return nil
}

// release gives pf's enable reference back, if the helper holds one.
func (c *darwinExitRouteConfigurer) release() error {
	token, err := os.ReadFile(c.tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netadmin: reading the pf reference: %w", err)
	}
	value := strings.TrimSpace(string(token))
	if _, err := strconv.ParseUint(value, 10, 64); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
		defer cancel()
		// A reference pf no longer knows (after a reboot) is gone anyway.
		_, _ = c.run(ctx, c.pfctl, []string{"-X", value}, "")
	}
	if err := os.Remove(c.tokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("netadmin: removing the pf reference: %w", err)
	}
	return nil
}

// load replaces the anchor's rules in one pfctl run.
func (c *darwinExitRouteConfigurer) load(rules string) error {
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	if _, err := c.run(ctx, c.pfctl, []string{"-a", exitAnchor, "-f", "-"}, rules); err != nil {
		return fmt.Errorf("netadmin: loading the exit kill switch: %w", err)
	}
	return nil
}

// pfExitRules is the kill switch: out by the utun, loopback, meshd's own
// sockets, DHCP, neighbour discovery, link-local and the allowed LAN;
// every other outbound packet is dropped, replies to connections opened
// from outside too (they would follow the exit routes anyway). One family
// per rule; "flags any" keeps connections opened before the anchor loaded.
// Without a utun nothing goes into the mesh either. captive are a captive
// portal window's rules, before the drop.
func pfExitRules(name string, uid uint32, lan []netip.Prefix, captive string) string {
	var rules strings.Builder
	rules.WriteString("pass out quick on lo0 all flags any\n")
	if name != "" {
		rules.WriteString("pass out quick on " + name + " all flags any\n")
	}
	rules.WriteString("pass out quick proto { tcp udp } user " + strconv.FormatUint(uint64(uid), 10) + " flags any\n")
	rules.WriteString("pass out quick inet proto udp from any port 68 to any port 67\n")
	rules.WriteString("pass out quick inet6 proto udp from any port 546 to any port 547\n")
	rules.WriteString("pass out quick inet6 proto icmp6 icmp6-type { routersol neighbrsol neighbradv }\n")
	rules.WriteString("pass out quick inet to 169.254.0.0/16\n")
	rules.WriteString("pass out quick inet6 to fe80::/10\n")
	for _, family := range []struct {
		name string
		is4  bool
	}{{"inet", true}, {"inet6", false}} {
		var values []string
		for _, prefix := range lan {
			if prefix.Addr().Is4() == family.is4 {
				values = append(values, prefix.Masked().String())
			}
		}
		if len(values) > 0 {
			rules.WriteString("pass out quick " + family.name + " to { " + strings.Join(values, " ") + " }\n")
		}
	}
	rules.WriteString(captive)
	rules.WriteString("block drop out quick all\n")
	return rules.String()
}

// darwinAttachedLAN returns the private subnets of the host's own
// addresses, but the mesh's, and link-local multicast (exit node design
// §6.2).
func darwinAttachedLAN() []netip.Prefix {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var lan []netip.Prefix
	for _, link := range interfaces {
		if strings.HasPrefix(link.Name, "utun") || link.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			network, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ip, valid := netip.AddrFromSlice(network.IP)
			bits, _ := network.Mask.Size()
			if !valid {
				continue
			}
			prefix := netip.PrefixFrom(ip.Unmap(), bits).Masked()
			if ExitLANSubnet(prefix) && !slices.Contains(lan, prefix) && len(lan) < maximumDarwinExitLAN {
				lan = append(lan, prefix)
			}
		}
	}
	slices.SortFunc(lan, compareRoutedPrefixes)
	return append(lan, ExitLANMulticast...)
}

// replaceDarwinExitRoutes puts the exit routes on name, removing those on
// another link; warn, when set, hears of the scoped defaults that failed.
func replaceDarwinExitRoutes(name string, warn func(message string, args ...any)) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("netadmin: finding the utun for the exit route: %w", err)
	}
	table, err := hostroute.Read()
	if err != nil {
		return err
	}
	// The physical interfaces' scoped defaults first: a socket meshd keeps
	// on one (IP_BOUND_IF) finds no route once 0/1 sends the destination to
	// the utun, unless its interface has a default of its own.
	// Best effort, one default at a time: they only help meshd's own
	// sockets, and the exit routes must come behind the kill switch anyway.
	// A failed one leaves only meshd's own sockets without a path.
	if err := replaceScopedDefaults(table); err != nil && warn != nil {
		warn("keeping a scoped default route for the client's own sockets failed", "error", err)
	}
	present := map[netip.Prefix]bool{}
	for _, entry := range table {
		if !entry.ExitOwned() {
			continue
		}
		if entry.Index == link.Index && slices.Contains(darwinExitRoutes, entry.Prefix) {
			present[entry.Prefix] = true
			continue
		}
		if err := deleteDarwinExitRoute(entry.Prefix, entry.Gateway); err != nil {
			return err
		}
	}
	gateway := &route.LinkAddr{Index: link.Index}
	for _, prefix := range darwinExitRoutes {
		if present[prefix] {
			continue
		}
		err := writeRoute(exitRouteMessage(unix.RTM_ADD, prefix, gateway))
		if err != nil && prefix.Addr().Is4() && !errors.Is(err, unix.EEXIST) {
			// IPv6 may be off on the utun: the kill switch drops it then.
			return fmt.Errorf("netadmin: adding exit route %s: %w", prefix, err)
		}
	}
	return nil
}

// clearDarwinExitRoutes removes every exit route, then the scoped
// defaults, whatever run left them.
func clearDarwinExitRoutes() error {
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
	for _, entry := range table {
		if entry.ExitScoped() {
			failures = append(failures, writeScopedDefault(unix.RTM_DELETE, entry))
		}
	}
	return errors.Join(failures...)
}

// physicalDefaults returns the host's own default routes: unscoped (a
// scoped one, macOS's own or another's, is never copied), through a
// gateway, none of meshnetd's, and not on a tunnel (another VPN's utun,
// ipsec or ppp).
func physicalDefaults(table []hostroute.Route) []hostroute.Route {
	var defaults []hostroute.Route
	for _, entry := range table {
		if entry.Prefix.Bits() != 0 || entry.Gateway == nil || entry.Flags&unix.RTF_GATEWAY == 0 ||
			entry.Cloned() || entry.Marked() || entry.ExitOwned() || entry.ExitScoped() || tunnelInterface(interfaceName(entry.Index)) {
			continue
		}
		defaults = append(defaults, entry)
	}
	return defaults
}

// interfaceName names the interface at index, or returns "" when there is
// none; tests replace it.
var interfaceName = func(index int) string {
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return link.Name
}

// tunnelInterface reports an interface of a tunnel, by its name. ppp is not
// one: PPPoE and USB modems are a host's real uplink.
func tunnelInterface(name string) bool {
	for _, prefix := range []string{"utun", "ipsec", "tun", "tap", "gif", "stf"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// replaceScopedDefaults gives each physical default route a scoped copy on
// its interface (RTF_IFSCOPE), as NetBird does, and removes the copies of
// defaults that are gone. One macOS already holds is used as it is. Each
// one is tried apart: the failures are returned together.
func replaceScopedDefaults(table []hostroute.Route) error {
	var failures []error
	wanted := physicalDefaults(table)
	same := func(scoped, physical hostroute.Route) bool {
		return scoped.Index == physical.Index && scoped.Prefix == physical.Prefix &&
			hostroute.SameGateway(scoped.Gateway, physical.Gateway)
	}
	present := make([]bool, len(wanted))
	for _, entry := range table {
		if !entry.ExitScoped() {
			continue
		}
		index := slices.IndexFunc(wanted, func(physical hostroute.Route) bool { return same(entry, physical) })
		if index >= 0 {
			present[index] = true
			continue
		}
		failures = append(failures, writeScopedDefault(unix.RTM_DELETE, entry))
	}
	for index, physical := range wanted {
		if present[index] {
			continue
		}
		failures = append(failures, writeScopedDefault(unix.RTM_ADD, physical))
	}
	return errors.Join(failures...)
}

// writeScopedDefault adds or deletes the scoped copy of a default route.
func writeScopedDefault(messageType int, physical hostroute.Route) error {
	message := routedMessage(messageType, physical.Prefix, physical.Gateway, unix.RTF_GATEWAY)
	message.Flags = message.Flags&^hostroute.Mark | hostroute.ExitMark | unix.RTF_IFSCOPE
	message.Index = physical.Index
	err := writeRoute(message)
	switch {
	case err == nil, messageType == unix.RTM_ADD && errors.Is(err, unix.EEXIST),
		messageType == unix.RTM_DELETE && errors.Is(err, unix.ESRCH):
		return nil
	default:
		return fmt.Errorf("netadmin: scoped default on interface %d: %w", physical.Index, err)
	}
}

func deleteDarwinExitRoute(prefix netip.Prefix, gateway route.Addr) error {
	err := writeRoute(exitRouteMessage(unix.RTM_DELETE, prefix, gateway))
	if err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("netadmin: removing exit route %s: %w", prefix, err)
	}
	return nil
}

// exitRouteMessage builds the message of one exit route on a link, marked
// apart from subnet routes (hostroute.ExitMark).
func exitRouteMessage(messageType int, prefix netip.Prefix, gateway route.Addr) *route.RouteMessage {
	message := routedMessage(messageType, prefix, gateway, 0)
	message.Flags = message.Flags&^hostroute.Mark | hostroute.ExitMark
	return message
}

// runPfctl runs pfctl with stdin, its output and errors together.
func runPfctl(ctx context.Context, path string, args []string, stdin string) ([]byte, error) {
	command := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: the trusted pfctl path
	command.Stdin = strings.NewReader(stdin)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 512 {
			message = message[:512]
		}
		return output, fmt.Errorf("running pfctl: %w: %s", err, message)
	}
	return output, nil
}

// ReleaseDarwinExitRoute removes the exit routes and the kill switch any
// run left, and gives back the pf reference kept at statePath: the way out
// for root (meshnetd --release-exit).
func ReleaseDarwinExitRoute(statePath string) error {
	return newDarwinExitRouteConfigurer(0, statePath).Clear()
}
