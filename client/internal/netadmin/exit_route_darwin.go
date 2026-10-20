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
}

func newDarwinExitRouteConfigurer(uid uint32, statePath string) *darwinExitRouteConfigurer {
	return &darwinExitRouteConfigurer{
		uid: uid, pfctl: DefaultPfctlPath, tokenPath: statePath, run: runPfctl, lan: darwinAttachedLAN,
	}
}

// DarwinExitStatePath is where the pf enable reference is kept, next to
// the helper's socket.
func DarwinExitStatePath(helperSocket string) string {
	return filepath.Join(filepath.Dir(helperSocket), "exit-pf-token")
}

// Replace installs the kill switch, then the routes on name; without a
// utun the host stays closed.
func (c *darwinExitRouteConfigurer) Replace(name string, _, allowLAN bool) error {
	if name != "" && (!validInterfaceName(name) || !strings.HasPrefix(name, "utun")) {
		return errors.New("netadmin: exit route target is invalid")
	}
	var lan []netip.Prefix
	if allowLAN {
		lan = c.lan()
	}
	if err := c.enable(); err != nil {
		return err
	}
	if err := c.load(pfExitRules(name, c.uid, lan)); err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	return replaceDarwinExitRoutes(name)
}

// Present reports whether the anchor holds rules.
func (c *darwinExitRouteConfigurer) Present() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	output, err := c.run(ctx, c.pfctl, []string{"-a", exitAnchor, "-s", "rules"}, "")
	if err != nil {
		return false, err
	}
	return bytes.Contains(output, []byte("block drop out")), nil
}

// Stamp identifies the utun and the attached LAN the rules follow.
func (c *darwinExitRouteConfigurer) Stamp(name string) string {
	values := []string{name}
	for _, prefix := range c.lan() {
		values = append(values, prefix.String())
	}
	return strings.Join(values, ",")
}

// Clear removes the routes first and the kill switch last.
func (c *darwinExitRouteConfigurer) Clear() error {
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

// enable turns pf on with a reference of the helper's own, once.
func (c *darwinExitRouteConfigurer) enable() error {
	if token, err := os.ReadFile(c.tokenPath); err == nil && len(bytes.TrimSpace(token)) != 0 {
		return nil
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
// every other outbound packet is dropped. Inbound connections keep state,
// so their replies leave. Without a utun nothing goes into the mesh either.
func pfExitRules(name string, uid uint32, lan []netip.Prefix) string {
	var rules strings.Builder
	rules.WriteString("pass out quick on lo0 all\n")
	if name != "" {
		rules.WriteString("pass out quick on " + name + " all\n")
	}
	rules.WriteString("pass out quick proto { tcp udp } user " + strconv.FormatUint(uint64(uid), 10) + "\n")
	rules.WriteString("pass out quick inet proto udp from any port 68 to any port 67\n")
	rules.WriteString("pass out quick inet6 proto udp from any port 546 to any port 547\n")
	rules.WriteString("pass out quick inet6 proto icmp6 icmp6-type { routersol neighbrsol neighbradv }\n")
	rules.WriteString("pass out quick to { 169.254.0.0/16 fe80::/10 }\n")
	if len(lan) > 0 {
		values := make([]string, 0, len(lan))
		for _, prefix := range lan {
			values = append(values, prefix.Masked().String())
		}
		rules.WriteString("pass out quick to { " + strings.Join(values, " ") + " }\n")
	}
	rules.WriteString("pass in quick all\n")
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
// another link.
func replaceDarwinExitRoutes(name string) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("netadmin: finding the utun for the exit route: %w", err)
	}
	table, err := hostroute.Read()
	if err != nil {
		return err
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

// clearDarwinExitRoutes removes every exit route, whatever run left it.
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
	return errors.Join(failures...)
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
