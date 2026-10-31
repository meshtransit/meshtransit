package rbaccheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/kubeprofile"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// A measurement of the groups' ceilings (K2h h4, mtcp-v1 §6.12): what each
// group's own RBAC lets it do, for people to read. It never decides
// anything, and never holds up the checker (§33.9 H3).
const (
	ceilingDeadline = 3 * time.Minute
	ceilingParallel = 4
	// ceilingLook is how often the measurer looks for a newer pass.
	ceilingLook = time.Minute
	// maximumCeilingNamespace is a DNS label's length.
	maximumCeilingNamespace = 63
)

// RulesReviewer asks the API server what a token may do in a namespace.
type RulesReviewer interface {
	RulesReview(ctx context.Context, token, namespace string) (RulesAnswer, error)
}

// CeilingGroup is one group to measure: its ClusterRole as the chart binds
// it (may be empty) and the namespaces it is declared for.
type CeilingGroup struct {
	Name, ClusterRole string
	Namespaces        []string
}

// CeilingOptions bound a measurer.
type CeilingOptions struct {
	Groups   []CeilingGroup
	Reviewer RulesReviewer
	Tokens   Tokens
	// RuleNamespaces, when set, are the namespaces the map's rules name, by
	// group: measured after the declared ones, within the same 16.
	RuleNamespaces func() map[string][]string
	// Passes is when the checker last ended a pass: a measurement follows
	// each newer one.
	Passes func() time.Time
	// Limit is the largest ceiling in bytes; 0: the message's limit.
	Limit int
	Now   func() time.Time
	// Look is how often Run looks for a newer pass; 0: a minute.
	Look time.Duration
	// Deadline bounds one measurement; 0: 3 minutes.
	Deadline time.Duration
}

// CeilingStats are the measurer's counts, for metrics.
type CeilingStats struct {
	Measurements uint64
	LastDuration time.Duration
	// Failed counts scopes left unmeasured, by reason: "unauthorized",
	// "too_large", "error", "deadline".
	Failed map[string]uint64
	// Invalid counts measurements not kept: one §6.12 refuses, or larger
	// than the limit (a bug, never the cluster's doing).
	Invalid uint64
	// Bytes is the kept ceiling's size.
	Bytes int
}

// Ceilings measures the groups' ceilings after each RBAC check pass, one
// measurement at a time, and keeps the latest.
type Ceilings struct {
	options CeilingOptions
	latest  atomic.Pointer[mtcpv1.GatewayGroupCeiling]

	mu    sync.Mutex
	stats CeilingStats
}

// NewCeilings checks the options.
func NewCeilings(options CeilingOptions) (*Ceilings, error) {
	if options.Reviewer == nil || options.Tokens == nil || options.Passes == nil {
		return nil, errors.New("rbaccheck: a ceiling measurer needs a reviewer, tokens and passes")
	}
	if options.Limit <= 0 {
		options.Limit = sharedmtcp.MessageGatewayGroupCeiling.Limit()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Look <= 0 {
		options.Look = ceilingLook
	}
	if options.Deadline <= 0 {
		options.Deadline = ceilingDeadline
	}
	return &Ceilings{options: options, stats: CeilingStats{Failed: map[string]uint64{}}}, nil
}

// Latest is the last measurement, nil before the first.
func (ceilings *Ceilings) Latest() *mtcpv1.GatewayGroupCeiling { return ceilings.latest.Load() }

// Stats copies the counts.
func (ceilings *Ceilings) Stats() CeilingStats {
	ceilings.mu.Lock()
	defer ceilings.mu.Unlock()
	stats := ceilings.stats
	stats.Failed = make(map[string]uint64, len(ceilings.stats.Failed))
	for reason, count := range ceilings.stats.Failed {
		stats.Failed[reason] = count
	}
	return stats
}

// Run measures after each pass newer than the last measured, until ctx
// ends.
func (ceilings *Ceilings) Run(ctx context.Context) error {
	var measured time.Time
	ticker := time.NewTicker(ceilings.options.Look)
	defer ticker.Stop()
	for {
		if pass := ceilings.options.Passes(); pass.After(measured) {
			measured = pass
			ceilings.Measure(ctx)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// scopeWork is one review of a measurement.
type scopeWork struct {
	group     string
	namespace string // the probe namespace for everywhere
	scope     *mtcpv1.GatewayCeilingScope
}

// Measure reviews every group's scopes now and keeps the ceiling. A
// measurement cut short by parent's end (the gateway stopping) keeps
// nothing: the last one stays.
func (ceilings *Ceilings) Measure(parent context.Context) *mtcpv1.GatewayGroupCeiling {
	started := ceilings.options.Now()
	ctx, cancel := context.WithTimeout(parent, ceilings.options.Deadline)
	defer cancel()
	var made [4]byte
	if _, err := rand.Read(made[:]); err != nil {
		return ceilings.latest.Load()
	}
	probe := probePrefix + hex.EncodeToString(made[:])
	ruleNamespaces := map[string][]string{}
	if ceilings.options.RuleNamespaces != nil {
		ruleNamespaces = ceilings.options.RuleNamespaces()
	}
	groups := ceilings.options.Groups
	ceiling := &mtcpv1.GatewayGroupCeiling{Truncated: len(groups) > sharedmtcp.GatewayGroupReportMaximum}
	var work []scopeWork
	for _, group := range groups[:min(len(groups), sharedmtcp.GatewayGroupReportMaximum)] {
		measured := &mtcpv1.GatewayCeilingGroup{
			Group: group.Name, ClusterRole: group.ClusterRole,
			Everywhere: &mtcpv1.GatewayCeilingScope{},
		}
		work = append(work, scopeWork{group: group.Name, namespace: probe, scope: measured.Everywhere})
		names, truncated := ceilingNamespaces(group.Namespaces, ruleNamespaces[group.Name])
		measured.NamespacesTruncated = truncated
		for _, name := range names {
			scope := &mtcpv1.GatewayCeilingScope{Namespace: name}
			measured.Namespaces = append(measured.Namespaces, scope)
			work = append(work, scopeWork{group: group.Name, namespace: name, scope: scope})
		}
		ceiling.Groups = append(ceiling.Groups, measured)
	}
	failed := ceilings.review(ctx, work)
	if parent.Err() != nil {
		return ceilings.latest.Load()
	}
	fitCeiling(ceiling, ceilings.options.Limit)
	ended := ceilings.options.Now()
	ceiling.CheckedAtMs = ended.UnixMilli()
	size := proto.Size(ceiling)
	invalid := sharedmtcp.ValidateGatewayGroupCeiling(ceiling) != nil || size > ceilings.options.Limit
	if invalid {
		// A bug, not the cluster's doing: keep the last good one, and never
		// send one Core refuses (it would end the session, again and again).
		ceiling = ceilings.latest.Load()
	} else {
		ceilings.latest.Store(ceiling)
	}
	ceilings.mu.Lock()
	ceilings.stats.Measurements++
	ceilings.stats.LastDuration = ended.Sub(started)
	for reason, count := range failed {
		ceilings.stats.Failed[reason] += count
	}
	if invalid {
		ceilings.stats.Invalid++
	} else {
		ceilings.stats.Bytes = size
	}
	ceilings.mu.Unlock()
	return ceiling
}

// refusals bound token replacements within one measurement: one per group,
// so a group whose tokens the API server refuses (its signing key rotated)
// mints once, not once per scope, and never spends the checker's budget
// (review h4b M1).
type refusals struct {
	mu       sync.Mutex
	replaced map[string]bool
	refused  map[string]bool
}

// replace reports whether this caller should forget the group's token: the
// first refusal of the measurement only.
func (r *refusals) replace(group string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replaced[group] {
		return false
	}
	r.replaced[group] = true
	return true
}

func (r *refusals) refuse(group string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refused[group] = true
}

func (r *refusals) isRefused(group string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refused[group]
}

// review runs the work on ceilingParallel workers; a scope it cannot
// measure stays unmeasured. It returns the failures by reason.
func (ceilings *Ceilings) review(ctx context.Context, work []scopeWork) map[string]uint64 {
	jobs := make(chan scopeWork)
	var mu sync.Mutex
	failed := map[string]uint64{}
	tried := &refusals{replaced: map[string]bool{}, refused: map[string]bool{}}
	var workers sync.WaitGroup
	for range ceilingParallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				if reason := ceilings.measureScope(ctx, job, tried); reason != "" {
					mu.Lock()
					failed[reason]++
					mu.Unlock()
				}
			}
		}()
	}
	for _, job := range work {
		jobs <- job
	}
	close(jobs)
	workers.Wait()
	return failed
}

// measureScope fills one scope. A refused token is asked again once: the
// group's first refusal of the measurement forgets it, so a fresh one is
// minted; a group refused twice is not asked again until the next
// measurement.
func (ceilings *Ceilings) measureScope(ctx context.Context, job scopeWork, tried *refusals) string {
	if ctx.Err() != nil {
		return "deadline"
	}
	if tried.isRefused(job.group) {
		return "unauthorized"
	}
	var answer RulesAnswer
	var err error
	// tokens are the ones asked with: a group is refused only when a token
	// other than the first was refused too, not when a retry raced the
	// Forget and got the first again (review h4b re-check).
	var tokens [2]string
	for attempt := range 2 {
		tokens[attempt], err = ceilings.options.Tokens.Token(ctx, job.group)
		if err != nil {
			break
		}
		answer, err = ceilings.options.Reviewer.RulesReview(ctx, tokens[attempt], job.namespace)
		if !errors.Is(err, ErrUnauthorized) || attempt == 1 {
			break
		}
		if tried.replace(job.group) {
			ceilings.options.Tokens.Forget(job.group, tokens[attempt])
		}
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrUnauthorized):
		if tokens[1] != "" && tokens[1] != tokens[0] {
			tried.refuse(job.group)
		}
		return "unauthorized"
	case errors.Is(err, ErrRulesAnswerTooLarge):
		return "too_large"
	case ctx.Err() != nil:
		return "deadline"
	default:
		return "error"
	}
	rules, dropped := ceilingRules(answer.Rules)
	job.scope.Measured, job.scope.Rules, job.scope.Incomplete = true, rules, answer.Incomplete
	job.scope.RulesDropped = uint32(dropped) //nolint:gosec // at most the answer's rules, under 4 MiB
	return ""
}

// ceilingNamespaces are the declared namespaces, then those the rules
// name, each a DNS label once, at most 16; truncated when there were more.
func ceilingNamespaces(declared, named []string) ([]string, bool) {
	var names []string
	seen := map[string]bool{}
	add := func(list []string) bool {
		sorted := slices.Clone(list)
		slices.Sort(sorted)
		for _, name := range sorted {
			if seen[name] || len(name) > maximumCeilingNamespace || !dnsLabel(name) {
				continue
			}
			if len(names) == sharedmtcp.GatewayCeilingNamespaceMaximum {
				return true
			}
			seen[name] = true
			names = append(names, name)
		}
		return false
	}
	return names, add(declared) || add(named)
}

// ceilingRules turns an answer's rules into the ceiling's: distinct, in a
// stable order, at most 576; a rule §6.12 refuses is dropped whole and
// counted, never shortened.
func ceilingRules(answer []kubeprofile.Rule) ([]*mtcpv1.KubernetesProfileRule, int) {
	kept := map[string]*mtcpv1.KubernetesProfileRule{}
	dropped := 0
	for _, rule := range answer {
		converted := &mtcpv1.KubernetesProfileRule{
			ApiGroups: rule.APIGroups, Resources: rule.Resources,
			Verbs: rule.Verbs, ResourceNames: rule.ResourceNames, NonResourceUrls: rule.NonResourceURLs,
		}
		if !sharedmtcp.ValidGatewayCeilingRule(converted) {
			dropped++
			continue
		}
		key, err := proto.MarshalOptions{Deterministic: true}.Marshal(converted)
		if err != nil {
			dropped++
			continue
		}
		kept[string(key)] = converted
	}
	keys := make([]string, 0, len(kept))
	for key := range kept {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rules := make([]*mtcpv1.KubernetesProfileRule, 0, min(len(keys), sharedmtcp.GatewayCeilingRuleMaximum))
	for _, key := range keys {
		if len(rules) == sharedmtcp.GatewayCeilingRuleMaximum {
			dropped++
			continue
		}
		rules = append(rules, kept[key])
	}
	return rules, dropped
}

// fitCeiling brings the ceiling within limit bytes (§6.12): a group whose
// everywhere scope alone does not fit drops rules from that scope's end;
// then namespaces go, from the end of the group with the most (the last of
// equals); then groups, from the end. Sizes are taken once and kept as a
// running total that may only overestimate (a shorter length prefix), so a
// ceiling of many megabytes is cut in linear time (review h4b M3).
func fitCeiling(ceiling *mtcpv1.GatewayGroupCeiling, limit int) {
	// Room for the ceiling's own fields beside one group.
	const envelope = 64
	for _, group := range ceiling.Groups {
		alone := &mtcpv1.GatewayCeilingGroup{
			Group: group.Group, ClusterRole: group.ClusterRole,
			Everywhere: group.Everywhere,
		}
		size := proto.Size(alone) + envelope
		everywhere := group.Everywhere
		for len(everywhere.Rules) > 0 && size > limit {
			last := everywhere.Rules[len(everywhere.Rules)-1]
			size -= embedded(proto.Size(last))
			everywhere.Rules = everywhere.Rules[:len(everywhere.Rules)-1]
			everywhere.RulesDropped++
		}
	}
	total := proto.Size(ceiling)
	for total > limit {
		widest := -1
		for index, group := range ceiling.Groups {
			if len(group.Namespaces) > 0 &&
				(widest < 0 || len(group.Namespaces) >= len(ceiling.Groups[widest].Namespaces)) {
				widest = index
			}
		}
		if widest >= 0 {
			group := ceiling.Groups[widest]
			last := group.Namespaces[len(group.Namespaces)-1]
			total -= embedded(proto.Size(last))
			group.Namespaces = group.Namespaces[:len(group.Namespaces)-1]
			if !group.NamespacesTruncated {
				group.NamespacesTruncated = true
				total += 2
			}
			continue
		}
		if len(ceiling.Groups) <= 1 {
			return
		}
		total -= embedded(proto.Size(ceiling.Groups[len(ceiling.Groups)-1]))
		ceiling.Groups = ceiling.Groups[:len(ceiling.Groups)-1]
		if !ceiling.Truncated {
			ceiling.Truncated = true
			total += 2
		}
	}
}

// embedded is what a message of size bytes takes inside another: its tag,
// its length and itself. Field numbers here are under 16: a one-byte tag.
func embedded(size int) int {
	return 1 + protowire.SizeVarint(uint64(size)) + size //nolint:gosec // a size is never negative
}
