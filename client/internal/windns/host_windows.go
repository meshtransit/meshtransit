//go:build windows

package windns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"meshtransit.net/client/internal/dnsconfig"
)

// NRPTHost installs the MeshTransit NRPT rule. It removes a rule left by a
// previous run when created. While Group Policy NRPT is in force, the DNS
// client ignores local rules, so the rule also goes under the Group Policy
// key; the DNS client reads that key only when machine policy with NRPT
// settings is applied, and policy processing may remove the rule, which the
// next Apply writes again.
type NRPTHost struct {
	mu       sync.Mutex
	endpoint dnsconfig.EndpointSource
	logger   *slog.Logger
	current  Rule
	active   bool
	// dirty means a write or removal failed, so the registry may hold a rule
	// although active is false.
	dirty bool
}

// NewNRPTHost removes any MeshTransit rule a previous run left behind.
func NewNRPTHost(endpoint dnsconfig.EndpointSource, logger *slog.Logger) (*NRPTHost, error) {
	if endpoint == nil {
		return nil, errors.New("windns: endpoint source is required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if err := removeRules(); err != nil {
		return nil, fmt.Errorf("windns: removing a stale rule: %w", err)
	}

	return &NRPTHost{endpoint: endpoint, logger: logger}, nil
}

// Apply installs the rule for an enabled plan, or removes it for a disabled
// one. A failed install puts the previous rule back.
func (h *NRPTHost) Apply(ctx context.Context, plan dnsconfig.Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !plan.Enabled {
		if !h.active && !h.dirty {
			return nil
		}
		if err := removeRules(); err != nil {
			h.dirty = true

			return err
		}
		h.current = Rule{}
		h.active = false
		h.dirty = false

		return nil
	}
	endpoint, ok := h.endpoint.Endpoint()
	if !ok {
		return errors.New("windns: resolver endpoint is not ready")
	}
	rule, err := RuleFromPlan(plan, endpoint.Resolver.Addr())
	if err != nil {
		return err
	}
	if h.active && h.current.Equal(rule) {
		intact, err := ruleIntact(rule)
		if intact {
			return nil
		}
		// A missing or unreadable copy is written again in full.
		h.logger.Info("writing the DNS rule again: the registry copy is missing or changed", "error", err)
	}
	if err := installRule(rule); err != nil {
		var rollbackErr error
		if h.active {
			rollbackErr = installRule(h.current)
		} else {
			rollbackErr = removeRules()
		}

		if rollbackErr != nil {
			h.dirty = true
		}

		return errors.Join(err, rollbackError(rollbackErr))
	}
	h.current = rule
	h.active = true
	h.dirty = false
	if groupPolicyPresent() {
		h.logger.Warn("Group Policy NRPT is in force: MeshTransit names resolve only after machine policy with NRPT settings is applied again")
	}

	return nil
}

// installRule writes the rule where the DNS client reads it: the local key,
// and also the Group Policy key while Group Policy NRPT is in force.
func installRule(rule Rule) error {
	if err := writeRule(localPolicyKey, rule); err != nil {
		return err
	}
	groupPolicy := groupPolicyPresent()
	if groupPolicy {
		if err := writeRule(groupPolicyKey, rule); err != nil {
			return err
		}
	}

	return reloadPolicy(groupPolicy)
}

// RemoveRule removes the MeshTransit rule any run left, as an administrator
// releasing the exit route does.
func RemoveRule() error { return removeRules() }

// removeRules removes the rule from both keys.
func removeRules() error {
	if err := errors.Join(deleteRule(localPolicyKey), deleteRule(groupPolicyKey)); err != nil {
		return err
	}

	return reloadPolicy(groupPolicyPresent())
}

// ruleIntact reports whether rule is where installRule puts it.
func ruleIntact(rule Rule) (bool, error) {
	bases := []string{localPolicyKey}
	if groupPolicyPresent() {
		bases = append(bases, groupPolicyKey)
	}
	for _, base := range bases {
		stored, found, err := readRule(base)
		if err != nil || !found || !stored.Equal(rule) {
			return false, err
		}
	}

	return true, nil
}

func rollbackError(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("windns: rolling back the NRPT rule: %w", err)
}

var _ dnsconfig.HostConfigurator = (*NRPTHost)(nil)
