package rbaccheck

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeReviewer allows what allow says for a group's token, and fails while
// fail is set.
type fakeReviewer struct {
	mu      sync.Mutex
	allow   map[string]func(Attributes) bool // by group
	fail    error
	reviews int
}

func (reviewer *fakeReviewer) Review(_ context.Context, token string, attributes Attributes) (bool, error) {
	reviewer.mu.Lock()
	defer reviewer.mu.Unlock()
	reviewer.reviews++
	if reviewer.fail != nil {
		return false, reviewer.fail
	}
	group := strings.TrimPrefix(token, "token-")
	if allow := reviewer.allow[group]; allow != nil {
		return allow(attributes), nil
	}
	return false, nil
}

func (reviewer *fakeReviewer) set(change func(*fakeReviewer)) {
	reviewer.mu.Lock()
	defer reviewer.mu.Unlock()
	change(reviewer)
}

// fakeTokens hands out "token-<group>".
type fakeTokens struct{ fail error }

func (tokens fakeTokens) Token(_ context.Context, group string) (string, error) {
	if tokens.fail != nil {
		return "", tokens.fail
	}
	return "token-" + group, nil
}

func (fakeTokens) Forget(string, string) {}

func testOptions(reviewer Reviewer, tokens Tokens, groups ...Group) Options {
	return Options{Groups: groups, Reviewer: reviewer, Tokens: tokens, Namespace: "meshtransit",
		StatefulSet: "meshgw", Replicas: 2, Secrets: []string{"meshgw-state", "meshgw-join"},
		ServiceAccount: "meshgw", Interval: 10 * time.Minute}
}

func testChecker(t *testing.T, reviewer Reviewer, groups ...Group) *Checker {
	t.Helper()
	checker, err := New(testOptions(reviewer, fakeTokens{}, groups...))
	if err != nil {
		t.Fatal(err)
	}
	return checker
}

// Every group is off until the first pass; a non-privileged group with a
// dangerous right anywhere is turned off with the reason, the others on.
func TestCheckerTurnsOffDangerousGroups(t *testing.T) {
	t.Parallel()
	is := func(verb, group, resource, subresource string) func(Attributes) bool {
		return func(attributes Attributes) bool {
			return attributes.Verb == verb && attributes.Group == group && attributes.Resource == resource &&
				attributes.Subresource == subresource
		}
	}
	cases := map[string]struct {
		allow  func(Attributes) bool
		reason string
	}{
		"view": {allow: func(attributes Attributes) bool {
			return attributes.Verb == "list" && attributes.Resource == "pods"
		}},
		"admin": {allow: func(Attributes) bool { return true }, reason: "* */*"},
		"secrets": {allow: func(attributes Attributes) bool {
			return attributes.Verb == "list" && attributes.Resource == "secrets" && attributes.Namespace == ""
		}, reason: "list secrets"},
		// A ClusterRoleBinding shows in a namespace that does not exist.
		"bound-everywhere": {allow: func(attributes Attributes) bool {
			return attributes.Resource == "secrets" && strings.HasPrefix(attributes.Namespace, "mt-probe-")
		}, reason: "secrets in every namespace"},
		"escalate":  {allow: is("escalate", "rbac.authorization.k8s.io", "clusterroles", ""), reason: "escalate"},
		"nodeproxy": {allow: is("get", "", "nodes", "proxy"), reason: "nodes/proxy"},
		"webhooks": {allow: is("create", "admissionregistration.k8s.io", "mutatingwebhookconfigurations", ""),
			reason: "mutatingwebhookconfigurations"},
		// Ways to take the gateway over, named or not (re-review HIGH-B).
		"exec-gateway": {allow: func(attributes Attributes) bool {
			return attributes.Namespace == "meshtransit" && attributes.Resource == "pods" &&
				attributes.Subresource == "exec" && attributes.Verb == "get" && attributes.Name == "meshgw-1"
		}, reason: "get pods/exec meshgw-1"},
		"state-secret": {allow: func(attributes Attributes) bool {
			return attributes.Namespace == "meshtransit" && attributes.Resource == "secrets" &&
				attributes.Name == "meshgw-state"
		}, reason: "secrets meshgw-state"},
		"mint-sre": {allow: func(attributes Attributes) bool {
			return attributes.Subresource == "token" && attributes.Name == "mt-sre"
		}, reason: "serviceaccounts/token mt-sre"},
		"statefulset": {allow: is("patch", "apps", "statefulsets", ""), reason: "statefulsets"},
	}
	allow := map[string]func(Attributes) bool{}
	var groups []Group
	for name, test := range cases {
		allow[name] = test.allow
		groups = append(groups, Group{Name: name})
	}
	allow["sre"] = func(Attributes) bool { return true }
	groups = append(groups, Group{Name: "sre", Privileged: true})
	reviewer := &fakeReviewer{allow: allow}
	checker := testChecker(t, reviewer, groups...)
	for _, group := range groups {
		if verdict := checker.Verdict(group.Name); verdict.Enabled || verdict.Reason == "" {
			t.Fatalf("%s before any pass: %+v", group.Name, verdict)
		}
	}
	checker.Pass(t.Context())
	for name, test := range cases {
		verdict := checker.Verdict(name)
		if test.reason == "" {
			if !verdict.Enabled {
				t.Errorf("%s turned off: %s", name, verdict.Reason)
			}
			continue
		}
		if verdict.Enabled || !strings.Contains(verdict.Reason, test.reason) {
			t.Errorf("%s: %+v, want off for %q", name, verdict, test.reason)
		}
	}
	// A privileged group may hold anything: it stays on.
	if verdict := checker.Verdict("sre"); !verdict.Enabled {
		t.Errorf("sre: %+v", verdict)
	}
	if verdict := checker.Verdict("unknown"); verdict.Enabled {
		t.Error("an unknown group is on")
	}
}

// A privileged group keeps impersonation only while its right to
// impersonate is held to named users and groups.
func TestCheckerLimitsImpersonation(t *testing.T) {
	t.Parallel()
	named := func(attributes Attributes) bool {
		return attributes.Verb == "impersonate" && (attributes.Name == "alice" || attributes.Name == "ops")
	}
	reviewer := &fakeReviewer{allow: map[string]func(Attributes) bool{
		"named": named,
		"any":   func(attributes Attributes) bool { return attributes.Verb == "impersonate" },
	}}
	checker := testChecker(t, reviewer, Group{Name: "named", Privileged: true, AllowImpersonation: true},
		Group{Name: "any", Privileged: true, AllowImpersonation: true},
		Group{Name: "plain", Privileged: true})
	checker.Pass(t.Context())
	if verdict := checker.Verdict("named"); !verdict.Enabled || !verdict.Impersonation {
		t.Fatalf("named: %+v", verdict)
	}
	if verdict := checker.Verdict("any"); !verdict.Enabled || verdict.Impersonation ||
		!strings.Contains(verdict.Reason, "impersonate") {
		t.Fatalf("any: %+v", verdict)
	}
	if verdict := checker.Verdict("plain"); !verdict.Enabled || verdict.Impersonation {
		t.Fatalf("plain: %+v", verdict)
	}
}

// A failing check keeps the last verdict for two intervals, then turns the
// group off; changes are announced.
func TestCheckerOnFailures(t *testing.T) {
	t.Parallel()
	reviewer := &fakeReviewer{}
	checker := testChecker(t, reviewer, Group{Name: "view"})
	now := time.Now()
	checker.now = func() time.Time { return now }
	checker.Pass(t.Context())
	select {
	case <-checker.Changes():
	default:
		t.Fatal("no change announced")
	}
	if !checker.Verdict("view").Enabled {
		t.Fatal("view off")
	}
	reviewer.set(func(reviewer *fakeReviewer) { reviewer.fail = errors.New("API server down") })
	now = now.Add(10 * time.Minute)
	checker.Pass(t.Context())
	if !checker.Verdict("view").Enabled {
		t.Fatal("turned off at one failed check")
	}
	now = now.Add(10 * time.Minute)
	checker.Pass(t.Context())
	verdict := checker.Verdict("view")
	if verdict.Enabled || !strings.Contains(verdict.Detail, "API server down") ||
		strings.Contains(verdict.Reason, "API server down") {
		t.Fatalf("at the second failed check: %+v", verdict)
	}
	select {
	case <-checker.Changes():
	default:
		t.Fatal("no change announced")
	}
	// A token that cannot be minted fails the check the same way.
	failing, err := New(testOptions(&fakeReviewer{}, fakeTokens{fail: errors.New("no RBAC")}, Group{Name: "view"}))
	if err != nil {
		t.Fatal(err)
	}
	failing.Pass(t.Context())
	if verdict := failing.Verdict("view"); verdict.Enabled {
		t.Fatalf("without a token: %+v", verdict)
	}
}

// Each pass asks about a new namespace that does not exist.
func TestCheckerProbesANewNamespaceEachPass(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	seen := map[string]bool{}
	reviewer := &fakeReviewer{allow: map[string]func(Attributes) bool{"view": func(attributes Attributes) bool {
		if strings.HasPrefix(attributes.Namespace, "mt-probe-") {
			mu.Lock()
			seen[attributes.Namespace] = true
			mu.Unlock()
		}
		return false
	}}}
	checker := testChecker(t, reviewer, Group{Name: "view"})
	checker.Pass(t.Context())
	checker.Pass(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("probe namespaces %v", seen)
	}
}

func TestNewRefusesBadOptions(t *testing.T) {
	t.Parallel()
	good := testOptions(&fakeReviewer{}, fakeTokens{}, Group{Name: "view"})
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Options){
		"no groups":     func(options *Options) { options.Groups = nil },
		"bad group":     func(options *Options) { options.Groups = []Group{{Name: "View"}} },
		"twice":         func(options *Options) { options.Groups = []Group{{Name: "a"}, {Name: "a"}} },
		"no reviewer":   func(options *Options) { options.Reviewer = nil },
		"no namespace":  func(options *Options) { options.Namespace = "" },
		"no interval":   func(options *Options) { options.Interval = 0 },
		"no replicas":   func(options *Options) { options.Replicas = 0 },
		"no secrets":    func(options *Options) { options.Secrets = nil },
		"impersonation": func(options *Options) { options.Groups = []Group{{Name: "a", AllowImpersonation: true}} },
	} {
		options := good
		change(&options)
		if _, err := New(options); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// countingTokens counts forgotten tokens and hands out a new one after.
type countingTokens struct {
	mu        sync.Mutex
	forgotten int
}

func (tokens *countingTokens) Token(_ context.Context, group string) (string, error) {
	tokens.mu.Lock()
	defer tokens.mu.Unlock()
	if tokens.forgotten > 0 {
		return "fresh-" + group, nil
	}
	return "stale-" + group, nil
}

func (tokens *countingTokens) Forget(string, string) {
	tokens.mu.Lock()
	defer tokens.mu.Unlock()
	tokens.forgotten++
}

type refusingReviewer struct{}

func (refusingReviewer) Review(_ context.Context, token string, _ Attributes) (bool, error) {
	if strings.HasPrefix(token, "stale-") {
		return false, ErrUnauthorized
	}
	return false, nil
}

// A token the API server refuses is forgotten and replaced once.
func TestCheckerReplacesARefusedToken(t *testing.T) {
	t.Parallel()
	tokens := &countingTokens{}
	checker, err := New(testOptions(refusingReviewer{}, tokens, Group{Name: "view"}))
	if err != nil {
		t.Fatal(err)
	}
	checker.Pass(t.Context())
	if verdict := checker.Verdict("view"); !verdict.Enabled || tokens.forgotten != 1 {
		t.Fatalf("verdict %+v, %d forgotten", verdict, tokens.forgotten)
	}
}

// Each right a non-privileged group must not hold turns it off alone
// (review b4 test gap): a reviewer allowing exactly that one right.
func TestCheckerTurnsOffForEachRight(t *testing.T) {
	t.Parallel()
	options := testOptions(&fakeReviewer{}, fakeTokens{}, Group{Name: "view"})
	probe := probePrefix + "fixed"
	checker, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	all := dangerousRights(checker.at, probe)
	for _, right := range all {
		only := right
		allowed := func(attributes Attributes) bool {
			if strings.HasPrefix(attributes.Namespace, probePrefix) {
				attributes.Namespace = probe
			}
			return attributes == only
		}
		one, err := New(testOptions(&fakeReviewer{allow: map[string]func(Attributes) bool{"view": allowed}},
			fakeTokens{}, Group{Name: "view"}))
		if err != nil {
			t.Fatal(err)
		}
		one.Pass(t.Context())
		if verdict := one.Verdict("view"); verdict.Enabled {
			t.Errorf("%s held, the group stays on", right)
		}
	}
	// The list holds what review b4 named.
	text := make([]string, len(all))
	for index, right := range all {
		text[index] = right.String()
	}
	joined := strings.Join(text, "\n")
	for _, want := range []string{
		"create apps/deployments in meshtransit", "patch pods meshgw-0 in meshtransit", "create nodes/proxy in the cluster",
		"patch nodes in the cluster", "create pods in kube-system", "patch configmaps aws-auth in kube-system",
		"create admissionregistration.k8s.io/mutatingadmissionpolicies in the cluster",
		"update secrets meshgw-join in meshtransit", "create serviceaccounts/token mt-view in meshtransit",
		"patch flowcontrol.apiserver.k8s.io/flowschemas in the cluster", "get pods/proxy in meshtransit",
		"patch apps/daemonsets in kube-system", "update batch/cronjobs in kube-system",
		"patch apps/deployments in meshtransit",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("not asked: %s", want)
		}
	}
}

// A verdict not checked whole for two intervals is off, whatever stalled.
func TestCheckerVerdictGoesStale(t *testing.T) {
	t.Parallel()
	checker := testChecker(t, &fakeReviewer{}, Group{Name: "view"})
	now := time.Now()
	checker.now = func() time.Time { return now }
	checker.Pass(t.Context())
	now = now.Add(21 * time.Minute)
	if verdict := checker.Verdict("view"); verdict.Enabled {
		t.Fatalf("stale: %+v", verdict)
	}
}

// A privileged group losing impersonation is announced.
func TestCheckerAnnouncesImpersonationChanges(t *testing.T) {
	t.Parallel()
	reviewer := &fakeReviewer{}
	checker := testChecker(t, reviewer, Group{Name: "sre", Privileged: true, AllowImpersonation: true})
	checker.Pass(t.Context())
	<-checker.Changes()
	reviewer.set(func(reviewer *fakeReviewer) {
		reviewer.allow = map[string]func(Attributes) bool{"sre": func(attributes Attributes) bool {
			return attributes.Verb == "impersonate"
		}}
	})
	checker.Pass(t.Context())
	select {
	case <-checker.Changes():
	default:
		t.Fatal("not announced")
	}
	if verdict := checker.Verdict("sre"); !verdict.Enabled || verdict.Impersonation {
		t.Fatalf("verdict %+v", verdict)
	}
}

// A verdict going stale is announced, so its group's sessions are cut.
func TestCheckerAnnouncesStaleness(t *testing.T) {
	t.Parallel()
	checker := testChecker(t, &fakeReviewer{}, Group{Name: "view"})
	now := time.Now()
	checker.now = func() time.Time { return now }
	checker.Pass(t.Context())
	<-checker.Changes()
	checker.announceStale()
	select {
	case <-checker.Changes():
		t.Fatal("announced while fresh")
	default:
	}
	now = now.Add(21 * time.Minute)
	checker.announceStale()
	select {
	case <-checker.Changes():
	default:
		t.Fatal("staleness not announced")
	}
}

// Run passes at once and stops with its context.
func TestCheckerRunStops(t *testing.T) {
	t.Parallel()
	checker := testChecker(t, &fakeReviewer{}, Group{Name: "view"})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- checker.Run(ctx) }()
	select {
	case <-checker.Changes():
	case <-time.After(5 * time.Second):
		t.Fatal("no first pass")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// kube-system is always guarded; guarded namespaces and Secrets are names.
func TestCheckerGuardedNamespaces(t *testing.T) {
	t.Parallel()
	for _, guarded := range [][]string{nil, {}, {"cilium"}} {
		options := testOptions(&fakeReviewer{}, fakeTokens{}, Group{Name: "view"})
		options.GuardedNamespaces = guarded
		checker, err := New(options)
		if err != nil || checker.at.guarded[0] != "kube-system" {
			t.Fatalf("%v: %v %v", guarded, checker, err)
		}
	}
	for name, change := range map[string]func(*Options){
		"bad namespace": func(options *Options) { options.GuardedNamespaces = []string{"Kube-system"} },
		"bad secret":    func(options *Options) { options.Secrets = []string{"a/b"} },
	} {
		options := testOptions(&fakeReviewer{}, fakeTokens{}, Group{Name: "view"})
		change(&options)
		if _, err := New(options); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// Running code in a pod of a guarded namespace (the VAP's allowlist, whose
// pods may sit by the gateway) turns a group off; while the namespace is
// not guarded the same right does not (review b7b M2).
func TestCheckerGuardsSessionsInAllowedNamespaces(t *testing.T) {
	t.Parallel()
	for _, right := range [][2]string{
		{"create", "exec"}, {"get", "exec"}, {"create", "attach"}, {"get", "attach"},
		{"create", "portforward"}, {"get", "portforward"},
		{"patch", "ephemeralcontainers"}, {"update", "ephemeralcontainers"},
	} {
		for _, guarded := range []bool{true, false} {
			reviewer := &fakeReviewer{allow: map[string]func(Attributes) bool{
				"ops": func(attributes Attributes) bool {
					return attributes.Namespace == "local-path-storage" && attributes.Verb == right[0] &&
						attributes.Resource == "pods" && attributes.Subresource == right[1]
				},
			}}
			options := testOptions(reviewer, fakeTokens{}, Group{Name: "ops"})
			if guarded {
				options.GuardedNamespaces = []string{"local-path-storage"}
			}
			checker, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			checker.Pass(t.Context())
			verdict := checker.Verdict("ops")
			if !guarded {
				if !verdict.Enabled {
					t.Errorf("%v unguarded: turned off: %s", right, verdict.Reason)
				}
				continue
			}
			want := "may " + right[0] + " pods/" + right[1] + " in local-path-storage"
			if verdict.Enabled || verdict.Reason != want {
				t.Errorf("%v: %+v, want off for %q", right, verdict, want)
			}
		}
	}
}

// A right held is found even when another review of its chunk fails.
func TestCheckerFindsAHeldRightBesideAFailure(t *testing.T) {
	t.Parallel()
	checker := testChecker(t, &chunkReviewer{}, Group{Name: "view"})
	checker.Pass(t.Context())
	if verdict := checker.Verdict("view"); verdict.Enabled || !strings.Contains(verdict.Reason, "secrets") {
		t.Fatalf("verdict %+v", verdict)
	}
}

// chunkReviewer allows "list secrets in the cluster" and fails the right
// after it, in the same chunk.
type chunkReviewer struct{}

func (chunkReviewer) Review(_ context.Context, _ string, attributes Attributes) (bool, error) {
	switch {
	case attributes.Namespace == "" && attributes.Verb == "list" && attributes.Resource == "secrets":
		return true, nil
	case attributes.Namespace == "" && attributes.Verb == "get" && attributes.Resource == "secrets":
		return false, errors.New("webhook timed out")
	}
	return false, nil
}
