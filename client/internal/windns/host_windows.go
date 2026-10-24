//go:build windows

package windns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

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
	// search is the adapter's search list as last set; searchSet whether it
	// was set (searchlist_windows.go); searchWarned whether the machine's
	// own search list was reported.
	search    []string
	searchSet bool
	// searchAt is when the search list was last set: an adapter made again
	// with the same list gets it at the first apply past searchRecheck
	// (TD-CLI-73).
	searchAt     time.Time
	searchFailed bool
	searchWarned bool
	// probeAnswered is whether the installed rule's probe answered, or
	// needs none; probed and reported are the outcome last logged.
	probeAnswered bool
	probed        bool
	reported      bool
	// probing is a probe running: one at a time. probeAgain asks it to
	// start again with probePlan when it ends; probeGeneration changes with
	// each rule installed or removed, so a probe of an older one writes and
	// logs nothing.
	probing         bool
	probeAgain      bool
	probePlan       dnsconfig.Plan
	probeFlush      bool
	probeGeneration uint64
	// probeEnded is when the installed rule's last probe ended: one that
	// did not answer is made again at most every groupPolicyReprobe.
	probeEnded time.Time
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
	host := &NRPTHost{endpoint: endpoint, logger: logger}
	// A search list a previous run left on the adapter goes too.
	host.syncSearchList(nil)

	return host, nil
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
		h.syncSearchList(nil)
		h.probeGeneration++
		h.probeAnswered, h.probeAgain, h.probeFlush = false, false, false

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
			h.syncSearchList(plan.SearchDomains)
			// A probe that failed or was skipped is made again.
			if !h.probeAnswered && !h.probing && time.Since(h.probeEnded) >= groupPolicyReprobe {
				h.probeGroupPolicyLocked(ctx, plan, false)
			}

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
	h.syncSearchList(plan.SearchDomains)
	h.probeGeneration++
	h.probeAnswered, h.probeEnded = false, time.Time{}
	h.probeGroupPolicyLocked(ctx, plan, true)

	return nil
}

// groupPolicyProbeWait bounds the probe of a name through the system
// resolver while Group Policy NRPT is in force: applying machine policy on
// a domain-joined machine can take a while.
const groupPolicyProbeWait = time.Minute

// groupPolicyReprobe spaces the probes of a rule whose probe did not
// answer: each may flush the system's DNS cache.
const groupPolicyReprobe = 10 * time.Minute

// probeGroupPolicyLocked starts a probe while Group Policy NRPT is in force,
// one at a time; it holds h.mu. flush is a rule just installed: its probe
// empties the DNS cache before each retry.
func (h *NRPTHost) probeGroupPolicyLocked(ctx context.Context, plan dnsconfig.Plan, flush bool) {
	if !groupPolicyPresent() {
		h.probeAnswered = true // nothing to check
		return
	}
	host, ok := probeHost(plan)
	if !ok {
		return // probed once a plan names a host
	}
	if h.probing {
		h.probeAgain, h.probePlan = true, plan
		h.probeFlush = h.probeFlush || flush
		return
	}
	h.probing = true
	// It outlives the apply, on its own deadline.
	go h.probeGroupPolicy(context.WithoutCancel(ctx), host, h.probeGeneration, flush)
}

// probeGroupPolicy asks the system resolver, with growing pauses, for host
// and says whether Group Policy NRPT lets MeshTransit answer it
// (TD-CLI-08): a warning when it does not, once per change.
func (h *NRPTHost) probeGroupPolicy(parent context.Context, host dnsconfig.Host, generation uint64, flush bool) {
	answered := resolvesTo(parent, host, flush)
	h.mu.Lock()
	h.probing = false
	current := generation == h.probeGeneration
	changed := current && (!h.probed || h.reported != answered)
	if current {
		h.probeAnswered, h.probeEnded = answered, time.Now()
	}
	if changed {
		h.probed, h.reported = true, answered
	}
	if h.probeAgain {
		again := h.probeFlush
		h.probeAgain, h.probeFlush = false, false
		if h.active {
			h.probeGroupPolicyLocked(parent, h.probePlan, again)
		}
	}
	h.mu.Unlock()
	if !changed {
		return
	}
	if answered {
		h.logger.Info("Group Policy NRPT is in force, and MeshTransit names resolve", "name", host.Name)
		return
	}
	h.logger.Warn("Group Policy NRPT is in force and MeshTransit names do not resolve: the policy overrides "+
		"MeshTransit's rule; apply machine policy again, or add the rule to the policy", "name", host.Name)
}

// resolvesTo reports whether the system resolver answers host with one of
// its addresses within groupPolicyProbeWait: the DNS client loads the
// policy it was just told to read again. With flush, the cache is emptied
// before each retry: a refusal the policy's server gave before the policy
// loaded may sit in it for up to 15 minutes.
func resolvesTo(parent context.Context, host dnsconfig.Host, flush bool) bool {
	ctx, cancel := context.WithTimeout(parent, groupPolicyProbeWait)
	defer cancel()
	for pause := time.Second; ; pause = min(2*pause, 15*time.Second) {
		answers, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", host.Name)
		if slices.ContainsFunc(answers, func(address netip.Addr) bool {
			return slices.Contains(host.Addresses, address.Unmap())
		}) {
			return true
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
		if flush {
			_ = FlushCache() // a failed flush leaves the retry to the cache
		}
	}
}

// probeHost is a name of the plan's with an IPv4 address, else one with an
// address: a host without IPv6 may not ask for AAAA.
func probeHost(plan dnsconfig.Plan) (dnsconfig.Host, bool) {
	var fallback dnsconfig.Host
	for _, host := range plan.Hosts {
		if host.Name == "" || len(host.Addresses) == 0 {
			continue
		}
		if slices.ContainsFunc(host.Addresses, netip.Addr.Is4) {
			return host, true
		}
		if fallback.Name == "" {
			fallback = host
		}
	}
	return fallback, fallback.Name != ""
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

// searchRecheck is how long an unchanged search list is taken as still set.
const searchRecheck = time.Minute

// syncSearchList puts domains on the adapter's search list when they
// changed. A failure is logged and tried again with the next plan: names
// still resolve in full.
func (h *NRPTHost) syncSearchList(domains []string) {
	if h.searchSet && slices.Equal(h.search, domains) && time.Since(h.searchAt) < searchRecheck {
		return
	}
	exists, err := setSearchList(domains)
	switch {
	case err != nil:
		if !h.searchFailed {
			h.logger.Warn("setting the DNS search list failed; short names may not resolve", "error", err)
		}
		h.searchFailed, h.searchSet = true, false

		return
	case !exists:
		h.searchSet = false

		return
	}
	h.search, h.searchSet, h.searchFailed, h.searchAt = slices.Clone(domains), true, false, time.Now()
	if len(domains) != 0 && !h.searchWarned && policySearchListSet() {
		h.searchWarned = true
		h.logger.Warn("Group Policy sets this machine's DNS search list, so Windows does not use MeshTransit's: " +
			"short mesh names resolve only in full")
	}
}

func rollbackError(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("windns: rolling back the NRPT rule: %w", err)
}

var _ dnsconfig.HostConfigurator = (*NRPTHost)(nil)
