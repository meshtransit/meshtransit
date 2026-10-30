// Package rbaccheck checks what each Kubernetes group of a gateway may
// really do in its cluster, through the API server's own authorizers, and
// turns off a non-privileged group that may do what none should (K1-I7;
// K1b design §9).
package rbaccheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// parallelReviews bounds the reviews of one group in flight: a pass asks
// some two hundred rights of each group (re-review b4 M1).
const parallelReviews = 8

// ErrUnauthorized reports a token the API server refused: it is forgotten
// and the review tried once more.
var ErrUnauthorized = errors.New("rbaccheck: the API server refused the token")

// Reviewer asks the API server whether the token's subject may do what
// attributes say (a SelfSubjectAccessReview).
type Reviewer interface {
	Review(ctx context.Context, token string, attributes Attributes) (bool, error)
}

// Tokens hands out a token of a group's account, and forgets one the API
// server refused.
type Tokens interface {
	Token(ctx context.Context, group string) (string, error)
	Forget(group, token string)
}

// Group is one Kubernetes group the gateway serves.
type Group struct {
	Name                           string
	Privileged, AllowImpersonation bool
}

// Options bound a checker.
type Options struct {
	Groups   []Group
	Reviewer Reviewer
	Tokens   Tokens
	// Namespace is the gateway's; StatefulSet and Replicas name its pods;
	// ServiceAccount is its own; Secrets are its Secrets (state, join key).
	Namespace, StatefulSet, ServiceAccount string
	Replicas                               int
	Secrets                                []string
	// GuardedNamespaces are where running a pod reaches the gateway's node:
	// the VAP's allowlist; nil: kube-system (review b4 H2).
	GuardedNamespaces []string
	// Interval paces passes; a check failing twice in a row, or not run for
	// two intervals, turns a group off.
	Interval time.Duration
	// Logger, when set, hears of passes slower than half the interval.
	Logger *slog.Logger
}

// Verdict is what a group may be used for.
type Verdict struct {
	Enabled bool
	// Impersonation reports a privileged group that may keep the client's
	// Impersonate-User and Impersonate-Group headers.
	Impersonation bool
	// Reason says why a group is off, or why it lost impersonation; it may
	// be shown to the group's users. Detail adds what only the gateway's log
	// and status show (review b4 L2). Code is Reason as one of the Code
	// values, what the gateway reports to Core (mtcp-v1 §6.11).
	Reason, Detail string
	Code           Code
	// CheckedAt is the last pass that checked it whole; zero: none yet.
	CheckedAt time.Time
}

// Code says why a group is off, or enabled without impersonation, without
// the API server's own words.
type Code string

// Verdict codes; empty for an enabled group with nothing to say.
const (
	CodeNotChecked       Code = "not_checked"
	CodeCheckStale       Code = "check_stale"
	CodeAPIError         Code = "api_error"
	CodeRBACExceeds      Code = "rbac_exceeds"
	CodeImpersonationOff Code = "impersonation_off"
)

// Checker keeps each group's verdict.
type Checker struct {
	options Options
	at      gateway
	now     func() time.Time

	passing  sync.Mutex // one pass at a time (review b4 L1)
	mu       sync.Mutex
	verdicts map[string]Verdict
	lastPass time.Time       // when the last whole pass ended; zero before one
	failures map[string]int  // consecutive failed checks, by group
	stale    map[string]bool // groups announced stale
	changes  chan struct{}
}

// New makes a checker; every group is off until the first pass.
func New(options Options) (*Checker, error) {
	if len(options.Groups) == 0 || options.Reviewer == nil || options.Tokens == nil || !dnsLabel(options.Namespace) ||
		options.StatefulSet == "" || options.Replicas < 1 || len(options.Secrets) == 0 ||
		options.ServiceAccount == "" || options.Interval < time.Second {
		return nil, errors.New("rbaccheck: invalid options")
	}
	// kube-system is always guarded; every name must be one (re-review b4
	// L).
	guarded := []string{"kube-system"}
	for _, namespace := range options.GuardedNamespaces {
		if !dnsLabel(namespace) {
			return nil, fmt.Errorf("rbaccheck: invalid guarded namespace %q", namespace)
		}
		if namespace != "kube-system" {
			guarded = append(guarded, namespace)
		}
	}
	for _, secret := range options.Secrets {
		if !dnsSubdomain(secret) {
			return nil, fmt.Errorf("rbaccheck: invalid Secret name %q", secret)
		}
	}
	at := gateway{namespace: options.Namespace, statefulSet: options.StatefulSet,
		serviceAccount: options.ServiceAccount, pods: replicaNames(options.StatefulSet, options.Replicas),
		secrets: options.Secrets, guarded: guarded}
	verdicts := map[string]Verdict{}
	for _, group := range options.Groups {
		if _, twice := verdicts[group.Name]; twice || !dnsLabel(group.Name) ||
			(group.AllowImpersonation && !group.Privileged) {
			return nil, fmt.Errorf("rbaccheck: invalid group %q", group.Name)
		}
		verdicts[group.Name] = Verdict{Reason: "not checked yet", Code: CodeNotChecked}
		at.accounts = append(at.accounts, "mt-"+group.Name)
	}
	return &Checker{options: options, at: at, now: time.Now, verdicts: verdicts, failures: map[string]int{},
		stale: map[string]bool{}, changes: make(chan struct{}, 1)}, nil
}

// Verdict returns a group's verdict; a group the checker does not know is
// off, and so is one not checked whole for two intervals, whatever stalled
// (review b4 M1).
func (checker *Checker) Verdict(group string) Verdict {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	verdict, found := checker.verdicts[group]
	if !found {
		return Verdict{Reason: "not a group of this gateway", Code: CodeNotChecked}
	}
	if verdict.Enabled && checker.now().Sub(verdict.CheckedAt) > 2*checker.options.Interval {
		return Verdict{Reason: "the RBAC check has not run", Code: CodeCheckStale, CheckedAt: verdict.CheckedAt}
	}
	return verdict
}

// LastPass is when the last whole pass ended; zero before one.
func (checker *Checker) LastPass() time.Time {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	return checker.lastPass
}

// Changes is told when a verdict changed: sessions of a group turned off
// are then cut.
func (checker *Checker) Changes() <-chan struct{} { return checker.changes }

// Run checks at once, then every Interval, until ctx ends. Apart from the
// passes it announces verdicts going stale, so a stalled pass still has
// the sessions of its groups cut (re-review b4 M1).
func (checker *Checker) Run(ctx context.Context) error {
	var watching sync.WaitGroup
	watching.Add(1)
	go func() {
		defer watching.Done()
		ticker := time.NewTicker(checker.options.Interval / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checker.announceStale()
			}
		}
	}()
	defer watching.Wait()
	ticker := time.NewTicker(checker.options.Interval)
	defer ticker.Stop()
	for {
		checker.Pass(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// announceStale tells Changes of groups whose verdict went stale.
func (checker *Checker) announceStale() {
	checker.mu.Lock()
	announce := false
	for group, verdict := range checker.verdicts {
		stale := verdict.Enabled && checker.now().Sub(verdict.CheckedAt) > 2*checker.options.Interval
		if stale && !checker.stale[group] {
			announce = true
		}
		checker.stale[group] = stale
	}
	checker.mu.Unlock()
	if announce {
		select {
		case checker.changes <- struct{}{}:
		default:
		}
	}
}

// Pass checks every group once, against a namespace and names made up for
// the pass.
func (checker *Checker) Pass(ctx context.Context) {
	checker.passing.Lock()
	defer checker.passing.Unlock()
	made := make([]byte, 8)
	if _, err := rand.Read(made); err != nil {
		return
	}
	probe := probePrefix + hex.EncodeToString(made[:4])
	name := "mt-probe-" + hex.EncodeToString(made[4:])
	started := time.Now()
	defer func() {
		if took := time.Since(started); took > checker.options.Interval/2 && checker.options.Logger != nil {
			checker.options.Logger.Warn("Kubernetes RBAC check slow", "error_code", "kubernetes_rbac_check_slow",
				"took", took.Round(time.Second).String())
		}
	}()
	changed := false
	for _, group := range checker.options.Groups {
		verdict, err := checker.check(ctx, group, probe, name)
		checker.mu.Lock()
		previous := checker.verdicts[group.Name]
		now := checker.now()
		switch {
		case err == nil:
			verdict.CheckedAt = now
			checker.failures[group.Name] = 0
		default:
			checker.failures[group.Name]++
			if checker.failures[group.Name] < 2 && !previous.CheckedAt.IsZero() {
				verdict = previous // one failed check keeps the verdict
				break
			}
			verdict = Verdict{Reason: "the RBAC check fails", Detail: err.Error(), Code: CodeAPIError,
				CheckedAt: previous.CheckedAt}
		}
		if verdict.Enabled != previous.Enabled || verdict.Impersonation != previous.Impersonation {
			changed = true
		}
		checker.verdicts[group.Name] = verdict
		checker.mu.Unlock()
		checker.report(group.Name, previous, verdict)
	}
	checker.mu.Lock()
	checker.lastPass = checker.now()
	checker.mu.Unlock()
	if changed {
		select {
		case checker.changes <- struct{}{}:
		default:
		}
	}
}

// report logs a group's verdict when it changes: an ERROR, with the detail,
// for a group turned off (K1b design §9; kind demo b5b).
func (checker *Checker) report(group string, previous, verdict Verdict) {
	logger := checker.options.Logger
	if logger == nil || verdict.Enabled == previous.Enabled && verdict.Impersonation == previous.Impersonation &&
		verdict.Reason == previous.Reason && verdict.Detail == previous.Detail {
		return
	}
	if !verdict.Enabled {
		logger.Error("Kubernetes group turned off", "error_code", "kubernetes_group_disabled", "group", group,
			"reason", verdict.Reason, "detail", verdict.Detail)
		return
	}
	logger.Info("Kubernetes group enabled", "group", group, "impersonation", verdict.Impersonation,
		"note", verdict.Reason)
}

// check asks, in order, about every right a group must not hold; the first
// it holds turns it off. A privileged group may hold any of them; one that
// keeps impersonation must hold it only for named users and groups.
func (checker *Checker) check(ctx context.Context, group Group, probe, made string) (Verdict, error) {
	token, err := checker.options.Tokens.Token(ctx, group.Name)
	if err != nil {
		return Verdict{}, err
	}
	if group.Privileged {
		verdict := Verdict{Enabled: true}
		if !group.AllowImpersonation {
			return verdict, nil
		}
		held, err := checker.firstHeld(ctx, group.Name, &token, unboundImpersonation(probe, made))
		if err != nil {
			return Verdict{}, err
		}
		if held == nil {
			verdict.Impersonation = true
		} else {
			verdict.Reason = "may " + held.String() + ": impersonation is turned off"
			verdict.Code = CodeImpersonationOff
		}
		return verdict, nil
	}
	held, err := checker.firstHeld(ctx, group.Name, &token, dangerousRights(checker.at, probe))
	if err != nil {
		return Verdict{}, err
	}
	if held != nil {
		return Verdict{Reason: "may " + held.String(), Code: CodeRBACExceeds}, nil
	}
	return Verdict{Enabled: true}, nil
}

// firstHeld returns the first right, in order, the group holds, or nil,
// asking parallelReviews at a time. A token the API server refuses is
// forgotten and replaced once.
func (checker *Checker) firstHeld(ctx context.Context, group string, token *string, rights []Attributes) (
	*Attributes, error,
) {
	replaced := false
	for start := 0; start < len(rights); start += parallelReviews {
		chunk := rights[start:min(start+parallelReviews, len(rights))]
		allowed, err := checker.review(ctx, *token, chunk)
		if errors.Is(err, ErrUnauthorized) && !replaced {
			replaced = true
			checker.options.Tokens.Forget(group, *token)
			if *token, err = checker.options.Tokens.Token(ctx, group); err != nil {
				return nil, err
			}
			allowed, err = checker.review(ctx, *token, chunk)
		}
		// A right found held turns the group off, whatever else in the
		// chunk failed (review b4 final M).
		for index, held := range allowed {
			if held {
				return &chunk[index], nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// review asks about rights at once: what each answered, and any error. A
// token refused gives no answers: none of them can be trusted.
func (checker *Checker) review(ctx context.Context, token string, rights []Attributes) ([]bool, error) {
	allowed := make([]bool, len(rights))
	errs := make([]error, len(rights))
	var asking sync.WaitGroup
	for index := range rights {
		asking.Add(1)
		go func() {
			defer asking.Done()
			allowed[index], errs[index] = checker.options.Reviewer.Review(ctx, token, rights[index])
		}()
	}
	asking.Wait()
	for _, err := range errs {
		if errors.Is(err, ErrUnauthorized) {
			return nil, err
		}
	}
	return allowed, errors.Join(errs...)
}

// dnsSubdomain reports an RFC 1123 subdomain, as object names are.
func dnsSubdomain(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabel(label) {
			return false
		}
	}
	return true
}

// dnsLabel reports an RFC 1123 label.
func dnsLabel(name string) bool {
	if name == "" || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
