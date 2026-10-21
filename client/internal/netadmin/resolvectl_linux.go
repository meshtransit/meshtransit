//go:build linux

package netadmin

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// execRunner runs a fixed, root-owned binary chosen at helper startup, never
// one named in an IPC request. Arguments go directly to the program, without
// a shell.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, path, args...).CombinedOutput() //nolint:gosec // G204: path is checked by requireTrustedBinary
}

type resolvectlConfigurator struct {
	path   string
	runner commandRunner
}

func newResolvectlConfigurator(path string) (*resolvectlConfigurator, error) {
	if err := requireTrustedBinary(path); err != nil {
		return nil, fmt.Errorf("netadmin: resolvectl: %w", err)
	}

	return &resolvectlConfigurator{path: path, runner: execRunner{}}, nil
}

func (c *resolvectlConfigurator) Apply(ctx context.Context, config DNSConfig) error {
	if c == nil || c.runner == nil {
		return errors.New("netadmin: resolvectl configurator is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	domains := make([]string, 0, len(config.SearchDomains)+len(config.RouteDomains))
	domains = append(domains, config.SearchDomains...)
	for _, domain := range config.RouteDomains {
		domains = append(domains, "~"+domain)
	}
	commands := [][]string{
		{"dns", config.Endpoint.InterfaceName, config.Endpoint.Resolver.String()},
		append([]string{"domain", config.Endpoint.InterfaceName}, domains...),
		{"default-route", config.Endpoint.InterfaceName, strconv.FormatBool(config.DefaultRoute)},
		{"llmnr", config.Endpoint.InterfaceName, "no"},
		{"mdns", config.Endpoint.InterfaceName, "no"},
	}
	for _, args := range commands {
		if _, err := c.run(ctx, args...); err != nil {
			_, rollbackErr := c.run(ctx, "revert", config.Endpoint.InterfaceName)

			return errors.Join(err, wrapCommandError("rolling back resolved link", rollbackErr))
		}
	}

	return nil
}

func (c *resolvectlConfigurator) Reset(ctx context.Context, endpoint DNSEndpoint) error {
	if c == nil || c.runner == nil {
		return errors.New("netadmin: resolvectl configurator is not initialized")
	}
	_, err := c.run(ctx, "revert", endpoint.InterfaceName)

	return err
}

func (c *resolvectlConfigurator) run(ctx context.Context, args ...string) ([]byte, error) {
	output, err := c.runner.Run(ctx, c.path, args...)
	if err == nil {
		return output, nil
	}
	message := strings.TrimSpace(string(output))
	if len(message) > 512 {
		message = message[:512]
	}
	if message == "" {
		return output, fmt.Errorf("running resolvectl %s: %w", args[0], err)
	}

	return output, fmt.Errorf("running resolvectl %s: %w: %s", args[0], err, message)
}

// FlushCaches empties resolved's cache: answers a captive portal's network
// gave during a window must not outlive it (exit node design §17.5).
func (c *resolvectlConfigurator) FlushCaches(ctx context.Context) error {
	if c == nil || c.runner == nil {
		return errors.New("netadmin: resolvectl configurator is not initialized")
	}
	_, err := c.run(ctx, "flush-caches")
	return err
}
