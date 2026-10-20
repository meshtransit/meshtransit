package netadmin

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// The dynamic-store entries of the MeshTransit DNS service: its resolver and
// the link that holds it. configd merges a service's resolver into the system
// DNS configuration only together with the service's interface state. The
// dynamic store lives in memory, so a reboot clears them; meshnetd removes them
// at startup and when its DNS link goes away.
const (
	scutilDNSKey  = "State:/Network/Service/net.meshtransit.dns/DNS"
	scutilIPv4Key = "State:/Network/Service/net.meshtransit.dns/IPv4"
)

// DefaultScutilPath is the macOS system configuration tool.
const DefaultScutilPath = "/usr/sbin/scutil"

type scriptRunner interface {
	RunScript(ctx context.Context, path, script string) ([]byte, error)
}

type execScriptRunner struct{}

func (execScriptRunner) RunScript(ctx context.Context, path, script string) ([]byte, error) {
	command := exec.CommandContext(ctx, path)
	command.Stdin = strings.NewReader(script)
	return command.CombinedOutput()
}

// scutilConfigurator installs a supplemental resolver: macOS sends queries for
// the match domains to the MeshTransit resolver and keeps every other query on
// the system resolvers.
type scutilConfigurator struct {
	path   string
	runner scriptRunner
}

func newScutilConfigurator(path string) (*scutilConfigurator, error) {
	if err := requireTrustedBinary(path); err != nil {
		return nil, fmt.Errorf("netadmin: scutil: %w", err)
	}
	return &scutilConfigurator{path: path, runner: execScriptRunner{}}, nil
}

func (c *scutilConfigurator) Apply(ctx context.Context, config DNSConfig) error {
	if c == nil || c.runner == nil {
		return errors.New("netadmin: scutil configurator is not initialized")
	}
	script, err := scutilApplyScript(config)
	if err != nil {
		return err
	}
	if _, err := c.run(ctx, script); err != nil {
		return errors.Join(err, wrapCommandError("rolling back scutil dns", c.remove(ctx)))
	}
	return nil
}

func (c *scutilConfigurator) Reset(ctx context.Context, _ DNSEndpoint) error {
	if c == nil || c.runner == nil {
		return errors.New("netadmin: scutil configurator is not initialized")
	}
	return c.remove(ctx)
}

func (c *scutilConfigurator) remove(ctx context.Context) error {
	_, err := c.run(ctx, "remove "+scutilDNSKey+"\nremove "+scutilIPv4Key+"\n")
	return err
}

func (c *scutilConfigurator) run(ctx context.Context, script string) ([]byte, error) {
	output, err := c.runner.RunScript(ctx, c.path, script)
	message := strings.TrimSpace(string(output))
	if err == nil && message == "" {
		return output, nil
	}
	if len(message) > 512 {
		message = message[:512]
	}
	if err == nil {
		// scutil reports script errors on stdout and still exits 0.
		return output, fmt.Errorf("running scutil: %s", message)
	}
	return output, fmt.Errorf("running scutil: %w: %s", err, message)
}

// scutilApplyScript builds the dictionary meshnetd stores. Names come from
// validateDNSConfig (lowercase letters, digits, hyphens and dots), so they
// cannot break out of the script.
func scutilApplyScript(config DNSConfig) (string, error) {
	if err := validateDNSConfig(config); err != nil {
		return "", err
	}
	// validateDNSConfig has already refused duplicates across both lists and
	// the root domain, which only a DefaultRoute config carries.
	matchDomains := append(append([]string{}, config.RouteDomains...), config.SearchDomains...)
	resolver := config.Endpoint.Resolver.Addr().String()
	var script strings.Builder
	script.WriteString("d.init\n")
	script.WriteString("d.add Addresses * " + resolver + "\n")
	script.WriteString("d.add InterfaceName " + config.Endpoint.InterfaceName + "\n")
	if config.DefaultRoute {
		// Every name, while the host uses an exit node (exit node design
		// §7.1): the service becomes the primary one, whose resolver is
		// the host's default. Removing the entry gives the host's own
		// resolvers back.
		script.WriteString("d.add OverridePrimary # 1\n")
	}
	script.WriteString("set " + scutilIPv4Key + "\n")
	script.WriteString("d.init\n")
	script.WriteString("d.add ServerAddresses * " + resolver + "\n")
	script.WriteString("d.add ServerPort # " + strconv.Itoa(int(config.Endpoint.Resolver.Port())) + "\n")
	if !config.DefaultRoute {
		script.WriteString("d.add SupplementalMatchDomains * " + strings.Join(matchDomains, " ") + "\n")
	}
	if len(config.SearchDomains) != 0 {
		script.WriteString("d.add SearchDomains * " + strings.Join(config.SearchDomains, " ") + "\n")
	}
	script.WriteString("d.add InterfaceName " + config.Endpoint.InterfaceName + "\n")
	script.WriteString("set " + scutilDNSKey + "\n")
	return script.String(), nil
}
