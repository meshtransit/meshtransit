package rbaccheck

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/kubeprofile"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// fakeRules answers rules reviews by "group/namespace"; the probe
// namespace is "probe". A missing key is an error.
type fakeRules struct {
	mu      sync.Mutex
	answers map[string]RulesAnswer
	errs    map[string]error
	asked   []string
	refuse  map[string]int // tokens refused once each, by token
}

func (f *fakeRules) RulesReview(_ context.Context, token, namespace string) (RulesAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	group, _, _ := strings.Cut(token, "#")
	if strings.HasPrefix(namespace, probePrefix) {
		namespace = "probe"
	}
	key := group + "/" + namespace
	f.asked = append(f.asked, key)
	if f.refuse[token] > 0 {
		f.refuse[token]--
		return RulesAnswer{}, ErrUnauthorized
	}
	if err := f.errs[key]; err != nil {
		return RulesAnswer{}, err
	}
	answer, found := f.answers[key]
	if !found {
		return RulesAnswer{}, errors.New("unknown")
	}
	return answer, nil
}

// fakeCeilingTokens hands out "group#n", a new n after Forget.
type fakeCeilingTokens struct {
	mu         sync.Mutex
	generation map[string]int
	forgotten  []string
}

func (f *fakeCeilingTokens) Token(_ context.Context, group string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("%s#%d", group, f.generation[group]), nil
}

func (f *fakeCeilingTokens) Forget(group, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.generation == nil {
		f.generation = map[string]int{}
	}
	f.generation[group]++
	f.forgotten = append(f.forgotten, token)
}

var (
	readPods = kubeprofile.Rule{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}}
	healthz  = kubeprofile.Rule{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}
)

func TestCeilingsMeasure(t *testing.T) {
	t.Parallel()
	editDeploys := kubeprofile.Rule{
		Verbs: []string{"*"}, APIGroups: []string{"apps"},
		Resources: []string{"deployments"},
	}
	rules := &fakeRules{
		answers: map[string]RulesAnswer{
			"view/probe":   {Rules: []kubeprofile.Rule{readPods, healthz, readPods}},
			"edit/probe":   {Rules: []kubeprofile.Rule{healthz}, Incomplete: true},
			"edit/default": {Rules: []kubeprofile.Rule{editDeploys, {Verbs: []string{"get"}}}},
			"edit/team-a":  {Rules: []kubeprofile.Rule{readPods}},
		},
		errs:   map[string]error{"edit/team-b": ErrRulesAnswerTooLarge},
		refuse: map[string]int{"view#0": 1},
	}
	tokens := &fakeCeilingTokens{}
	now := time.UnixMilli(1_793_000_000_000)
	ceilings, err := NewCeilings(CeilingOptions{
		Groups: []CeilingGroup{
			{Name: "view", ClusterRole: "view"},
			{Name: "edit", ClusterRole: "edit", Namespaces: []string{"team-a", "default"}},
		},
		Reviewer: rules, Tokens: tokens, Passes: time.Now, Now: func() time.Time { return now },
		RuleNamespaces: func() map[string][]string {
			return map[string][]string{"edit": {"team-b", "default", "Bad_Name"}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ceiling := ceilings.Measure(t.Context())
	if ceiling != ceilings.Latest() || ceiling.GetCheckedAtMs() != now.UnixMilli() || ceiling.GetTruncated() ||
		len(ceiling.GetGroups()) != 2 {
		t.Fatalf("ceiling %v", ceiling)
	}
	view, edit := ceiling.GetGroups()[0], ceiling.GetGroups()[1]
	// The refused token was forgotten and the review asked again.
	if !view.GetEverywhere().GetMeasured() || len(view.GetEverywhere().GetRules()) != 2 ||
		len(view.GetNamespaces()) != 0 || len(tokens.forgotten) != 1 || tokens.forgotten[0] != "view#0" {
		t.Fatalf("view %v, forgotten %v", view, tokens.forgotten)
	}
	var names []string
	for _, scope := range edit.GetNamespaces() {
		names = append(names, scope.GetNamespace())
	}
	// Declared first, sorted; then the rules' namespaces; an invalid name
	// is skipped.
	if strings.Join(names, ",") != "default,team-a,team-b" || edit.GetNamespacesTruncated() ||
		edit.GetClusterRole() != "edit" || !edit.GetEverywhere().GetIncomplete() {
		t.Fatalf("edit %v", edit)
	}
	byName := map[string]*mtcpv1.GatewayCeilingScope{}
	for _, scope := range edit.GetNamespaces() {
		byName[scope.GetNamespace()] = scope
	}
	if scope := byName["default"]; !scope.GetMeasured() || len(scope.GetRules()) != 1 || scope.GetRulesDropped() != 1 {
		t.Fatalf("default %v", scope)
	}
	if scope := byName["team-b"]; scope.GetMeasured() || len(scope.GetRules()) != 0 {
		t.Fatalf("team-b %v", scope)
	}
	if stats := ceilings.Stats(); stats.Measurements != 1 || stats.Failed["too_large"] != 1 ||
		stats.Bytes != proto.Size(ceiling) {
		t.Fatalf("stats %+v", stats)
	}
	if err := sharedmtcp.ValidateGatewayGroupCeiling(ceiling); err != nil {
		t.Fatal(err)
	}
}

func TestCeilingsMeasureFailures(t *testing.T) {
	t.Parallel()
	rules := &fakeRules{
		answers: map[string]RulesAnswer{}, errs: map[string]error{"view/probe": errors.New("boom")},
		refuse: map[string]int{"edit#0": 1, "edit#1": 1},
	}
	ceilings, err := NewCeilings(CeilingOptions{
		Groups:   []CeilingGroup{{Name: "view"}, {Name: "edit"}},
		Reviewer: rules, Tokens: &fakeCeilingTokens{}, Passes: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ceiling := ceilings.Measure(t.Context())
	for _, group := range ceiling.GetGroups() {
		if group.GetEverywhere().GetMeasured() {
			t.Fatalf("%s measured", group.GetGroup())
		}
	}
	if stats := ceilings.Stats(); stats.Failed["error"] != 1 || stats.Failed["unauthorized"] != 1 {
		t.Fatalf("stats %+v", stats)
	}
	// A measurement the gateway's stop cuts short keeps nothing.
	kept := ceilings.Latest()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if got := ceilings.Measure(cancelled); got != kept || ceilings.Latest() != kept ||
		ceilings.Stats().Measurements != 1 {
		t.Fatalf("a stopped measurement was kept: %+v", ceilings.Stats())
	}
	if _, err := NewCeilings(CeilingOptions{}); err == nil {
		t.Fatal("no reviewer taken")
	}
}

func TestCeilingNamespaces(t *testing.T) {
	t.Parallel()
	var many []string
	for index := range 20 {
		many = append(many, fmt.Sprintf("ns-%02d", index))
	}
	names, truncated := ceilingNamespaces(many[:10], append(many[5:], "UPPER", strings.Repeat("a", 64)))
	if len(names) != 16 || !truncated || names[0] != "ns-00" || names[15] != "ns-15" {
		t.Fatalf("%v %t", names, truncated)
	}
	names, truncated = ceilingNamespaces([]string{"b", "a", "b"}, []string{"a", "UPPER"})
	if strings.Join(names, ",") != "a,b" || truncated {
		t.Fatalf("%v %t", names, truncated)
	}
}

func TestCeilingRules(t *testing.T) {
	t.Parallel()
	var answer []kubeprofile.Rule
	for index := range 600 {
		answer = append(answer, kubeprofile.Rule{
			Verbs: []string{"get"}, APIGroups: []string{""},
			Resources: []string{fmt.Sprintf("r%03d", index)},
		})
	}
	answer = append(answer, answer[0], kubeprofile.Rule{
		Verbs: []string{"get"}, APIGroups: []string{""},
		Resources: []string{"bad\x01"},
	}, kubeprofile.Rule{
		Verbs: []string{"get"}, NonResourceURLs: []string{"/a"},
		Resources: []string{"pods"},
	})
	rules, dropped := ceilingRules(answer)
	// 600 distinct: 576 kept, 24 over the bound, 2 invalid.
	if len(rules) != 576 || dropped != 26 || rules[0].GetResources()[0] != "r000" {
		t.Fatalf("%d rules, %d dropped", len(rules), dropped)
	}
}

func TestFitCeiling(t *testing.T) {
	t.Parallel()
	scope := func(namespace string, rules int) *mtcpv1.GatewayCeilingScope {
		measured := &mtcpv1.GatewayCeilingScope{Namespace: namespace, Measured: true}
		for index := range rules {
			measured.Rules = append(measured.Rules, &mtcpv1.KubernetesProfileRule{
				Verbs:     []string{"get"},
				ApiGroups: []string{""}, Resources: []string{fmt.Sprintf("%s-%04d", strings.Repeat("r", 40), index)},
			})
		}
		return measured
	}
	// A group whose everywhere scope alone is too big keeps it, cut.
	ceiling := &mtcpv1.GatewayGroupCeiling{Groups: []*mtcpv1.GatewayCeilingGroup{
		{Group: "huge", Everywhere: scope("", 500)},
	}}
	fitCeiling(ceiling, 8<<10)
	if size := proto.Size(ceiling); size > 8<<10 || ceiling.GetGroups()[0].GetEverywhere().GetRulesDropped() == 0 ||
		len(ceiling.GetGroups()[0].GetEverywhere().GetRules())+
			int(ceiling.GetGroups()[0].GetEverywhere().GetRulesDropped()) != 500 {
		t.Fatalf("%d bytes, %v dropped", size, ceiling.GetGroups()[0].GetEverywhere().GetRulesDropped())
	}
	// Namespaces go first, from the widest group; then groups.
	ceiling = &mtcpv1.GatewayGroupCeiling{Groups: []*mtcpv1.GatewayCeilingGroup{
		{Group: "a", Everywhere: scope("", 10), Namespaces: []*mtcpv1.GatewayCeilingScope{scope("x", 10)}},
		{Group: "b", Everywhere: scope("", 10), Namespaces: []*mtcpv1.GatewayCeilingScope{
			scope("x", 10), scope("y", 10), scope("z", 10),
		}},
		{Group: "c", Everywhere: scope("", 10)},
	}}
	full := proto.Size(ceiling)
	fitCeiling(ceiling, full-1)
	if len(ceiling.GetGroups()[1].GetNamespaces()) != 2 || !ceiling.GetGroups()[1].GetNamespacesTruncated() ||
		len(ceiling.GetGroups()[0].GetNamespaces()) != 1 || ceiling.GetTruncated() {
		t.Fatalf("one namespace off the widest: %v", ceiling)
	}
	fitCeiling(ceiling, proto.Size(scope("", 10))*3)
	if len(ceiling.GetGroups()) == 3 && len(ceiling.GetGroups()[0].GetNamespaces())+
		len(ceiling.GetGroups()[1].GetNamespaces()) > 0 {
		t.Fatalf("groups went before namespaces: %v", ceiling)
	}
	fitCeiling(ceiling, proto.Size(scope("", 10))+100)
	if len(ceiling.GetGroups()) != 1 || !ceiling.GetTruncated() || ceiling.GetGroups()[0].GetGroup() != "a" {
		t.Fatalf("groups from the end: %v", ceiling)
	}
}

func TestCeilingsRunFollowsPasses(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var pass time.Time
	rules := &fakeRules{answers: map[string]RulesAnswer{"view/probe": {Rules: []kubeprofile.Rule{readPods}}}}
	ceilings, err := NewCeilings(CeilingOptions{
		Groups: []CeilingGroup{{Name: "view"}}, Reviewer: rules,
		Tokens: &fakeCeilingTokens{}, Passes: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return pass
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ceilings.Run(ctx)
	}()
	time.Sleep(50 * time.Millisecond)
	if ceilings.Latest() != nil {
		t.Fatal("measured before a pass")
	}
	cancel()
	<-done
	mu.Lock()
	pass = time.Now()
	mu.Unlock()
	ctx, cancel = context.WithCancel(t.Context())
	done = make(chan struct{})
	go func() {
		defer close(done)
		_ = ceilings.Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for ceilings.Latest() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if ceilings.Latest() == nil || ceilings.Stats().Measurements != 1 {
		t.Fatalf("not measured after a pass: %+v", ceilings.Stats())
	}
}

// The reviewer posts a SelfSubjectRulesReview and keeps the rules and
// incomplete, never the evaluation error; an answer over 4 MiB is refused,
// never read in part.
func TestAPIReviewerRulesReview(t *testing.T) {
	t.Parallel()
	var path, namespace, auth string
	status := http.StatusCreated
	answer := `{"status":{"resourceRules":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"]}],` +
		`"nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/api"]}],"incomplete":true,` +
		`"evaluationError":"webhook said no"}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		_, after, _ := strings.Cut(string(body), `"namespace":"`)
		namespace, _, _ = strings.Cut(after, `"`)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	reviewer, err := NewAPIReviewer(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reviewer.RulesReview(t.Context(), "token-edit", "team-a")
	if err != nil || path != "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" || namespace != "team-a" ||
		auth != "Bearer token-edit" || !got.Incomplete || len(got.Rules) != 2 ||
		got.Rules[1].NonResourceURLs[0] != "/api" {
		t.Fatalf("%+v %v %s %s", got, err, path, namespace)
	}
	status = http.StatusUnauthorized
	if _, err := reviewer.RulesReview(t.Context(), "t", "a"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("401: %v", err)
	}
	status, answer = http.StatusCreated, `{"status":{"resourceRules":[`+
		strings.Repeat(`{"verbs":["get"],"apiGroups":[""],"resources":["pods"]},`, 80_000)+`]}}`
	if _, err := reviewer.RulesReview(t.Context(), "t", "a"); !errors.Is(err, ErrRulesAnswerTooLarge) {
		t.Fatalf("a large answer: %v", err)
	}
	status = http.StatusForbidden
	if _, err := reviewer.RulesReview(t.Context(), "t", "a"); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("403: %v", err)
	}
	status = http.StatusCreated
	for _, failing := range []string{`{}`, `nope`, `{"status":null}`} {
		answer = failing
		if _, err := reviewer.RulesReview(t.Context(), "t", "a"); err == nil {
			t.Errorf("%q: no error", failing)
		}
	}
}

// heldTokens behaves as MinterTokens: Forget drops the token only while it
// is still the one held, and the next Token mints a new one.
type heldTokens struct {
	mu        sync.Mutex
	held      map[string]string
	mints     map[string]int
	forgotten int
}

func (h *heldTokens) Token(_ context.Context, group string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if token, found := h.held[group]; found {
		return token, nil
	}
	h.mints[group]++
	token := fmt.Sprintf("%s#%d", group, h.mints[group]-1)
	h.held[group] = token
	return token, nil
}

func (h *heldTokens) Forget(group, token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.held[group] == token {
		delete(h.held, group)
		h.forgotten++
	}
}

// A group whose tokens the API server refuses mints one new token per
// measurement, however many scopes it has, and its other scopes are not
// asked again (review h4b M1).
func TestCeilingsRefusedGroupMintsOnce(t *testing.T) {
	t.Parallel()
	refused := map[string]int{}
	for index := range 4 {
		refused[fmt.Sprintf("edit#%d", index)] = 100
	}
	rules := &fakeRules{
		answers: map[string]RulesAnswer{"view/probe": {Rules: []kubeprofile.Rule{readPods}}},
		refuse:  refused,
	}
	tokens := &heldTokens{held: map[string]string{}, mints: map[string]int{}}
	var namespaces []string
	for index := range 16 {
		namespaces = append(namespaces, fmt.Sprintf("ns-%02d", index))
	}
	ceilings, err := NewCeilings(CeilingOptions{
		Groups:   []CeilingGroup{{Name: "view"}, {Name: "edit", Namespaces: namespaces}},
		Reviewer: rules, Tokens: tokens, Passes: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ceiling := ceilings.Measure(t.Context())
	if tokens.mints["edit"] != 2 || tokens.forgotten != 1 || !ceiling.GetGroups()[0].GetEverywhere().GetMeasured() {
		t.Fatalf("edit minted %d, forgot %d", tokens.mints["edit"], tokens.forgotten)
	}
	asked := 0
	for _, key := range rules.asked {
		if strings.HasPrefix(key, "edit/") {
			asked++
		}
	}
	// At most one review per worker before the refusal is known, plus the
	// retry: far below the group's 17 scopes twice over.
	if asked > 2*ceilingParallel || ceilings.Stats().Failed["unauthorized"] != 17 {
		t.Fatalf("edit asked %d times, %+v", asked, ceilings.Stats())
	}
}

// slowRules answers "probe" at once and every namespace only when the
// measurement's deadline ends it.
type slowRules struct{}

func (slowRules) RulesReview(ctx context.Context, _, namespace string) (RulesAnswer, error) {
	if strings.HasPrefix(namespace, probePrefix) {
		return RulesAnswer{Rules: []kubeprofile.Rule{readPods}}, nil
	}
	<-ctx.Done()
	return RulesAnswer{}, ctx.Err()
}

// A measurement its deadline ends keeps what it measured; the rest stays
// unmeasured, counted as deadline.
func TestCeilingsDeadlinePartway(t *testing.T) {
	t.Parallel()
	ceilings, err := NewCeilings(CeilingOptions{
		Groups:   []CeilingGroup{{Name: "edit", Namespaces: []string{"a", "b", "c", "d", "e", "f"}}},
		Reviewer: slowRules{}, Tokens: &fakeCeilingTokens{}, Passes: time.Now, Deadline: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ceiling := ceilings.Measure(t.Context())
	edit := ceiling.GetGroups()[0]
	if !edit.GetEverywhere().GetMeasured() || len(edit.GetNamespaces()) != 6 ||
		ceilings.Stats().Failed["deadline"] != 6 {
		t.Fatalf("%v, %+v", edit, ceilings.Stats())
	}
	for _, scope := range edit.GetNamespaces() {
		if scope.GetMeasured() {
			t.Fatalf("%s measured", scope.GetNamespace())
		}
	}
}

// More than 64 groups: the first 64, truncated; a ceiling that cannot fit
// the limit is not kept, and the last good one stays.
func TestCeilingsTruncatedAndOversize(t *testing.T) {
	t.Parallel()
	var groups []CeilingGroup
	answers := map[string]RulesAnswer{}
	for index := range 70 {
		name := fmt.Sprintf("g%02d", index)
		groups = append(groups, CeilingGroup{Name: name})
		answers[name+"/probe"] = RulesAnswer{Rules: []kubeprofile.Rule{readPods}}
	}
	options := CeilingOptions{
		Groups: groups, Reviewer: &fakeRules{answers: answers}, Tokens: &fakeCeilingTokens{}, Passes: time.Now,
	}
	ceilings, err := NewCeilings(options)
	if err != nil {
		t.Fatal(err)
	}
	ceiling := ceilings.Measure(t.Context())
	if !ceiling.GetTruncated() || len(ceiling.GetGroups()) != 64 || ceiling.GetGroups()[63].GetGroup() != "g63" {
		t.Fatalf("%d groups, truncated %t", len(ceiling.GetGroups()), ceiling.GetTruncated())
	}
	options.Limit = 10
	tiny, err := NewCeilings(options)
	if err != nil {
		t.Fatal(err)
	}
	if got := tiny.Measure(t.Context()); got != nil || tiny.Latest() != nil || tiny.Stats().Invalid != 1 {
		t.Fatalf("an oversize ceiling was kept: %v, %+v", got, tiny.Stats())
	}
}

// Run measures once per pass, however many times it looks.
func TestCeilingsRunOncePerPass(t *testing.T) {
	t.Parallel()
	pass := time.Now()
	rules := &fakeRules{answers: map[string]RulesAnswer{"view/probe": {Rules: []kubeprofile.Rule{readPods}}}}
	ceilings, err := NewCeilings(CeilingOptions{
		Groups: []CeilingGroup{{Name: "view"}}, Reviewer: rules, Tokens: &fakeCeilingTokens{},
		Passes: func() time.Time { return pass }, Look: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_ = ceilings.Run(ctx)
	if got := ceilings.Stats().Measurements; got != 1 {
		t.Fatalf("%d measurements for one pass", got)
	}
}

// Of groups with as many namespaces, the last loses one first.
func TestFitCeilingTieBreak(t *testing.T) {
	t.Parallel()
	scope := func(namespace string) *mtcpv1.GatewayCeilingScope {
		return &mtcpv1.GatewayCeilingScope{Namespace: namespace, Measured: true, Rules: []*mtcpv1.KubernetesProfileRule{
			{Verbs: []string{"get"}, ApiGroups: []string{""}, Resources: []string{"pods"}},
		}}
	}
	ceiling := &mtcpv1.GatewayGroupCeiling{Groups: []*mtcpv1.GatewayCeilingGroup{
		{Group: "a", Everywhere: scope(""), Namespaces: []*mtcpv1.GatewayCeilingScope{scope("x"), scope("y")}},
		{Group: "b", Everywhere: scope(""), Namespaces: []*mtcpv1.GatewayCeilingScope{scope("x"), scope("y")}},
	}}
	limit := proto.Size(ceiling) - 1
	fitCeiling(ceiling, limit)
	if len(ceiling.GetGroups()[0].GetNamespaces()) != 2 || len(ceiling.GetGroups()[1].GetNamespaces()) != 1 ||
		proto.Size(ceiling) > limit {
		t.Fatalf("%v", ceiling)
	}
}

// The largest ceiling the bounds allow is cut to the message limit fast,
// and the running total never lets it end over the limit.
func TestFitCeilingLargeIsLinear(t *testing.T) {
	t.Parallel()
	scope := func(namespace string) *mtcpv1.GatewayCeilingScope {
		measured := &mtcpv1.GatewayCeilingScope{Namespace: namespace, Measured: true}
		for index := range sharedmtcp.GatewayCeilingRuleMaximum {
			measured.Rules = append(measured.Rules, &mtcpv1.KubernetesProfileRule{
				Verbs: []string{"get", "list"}, ApiGroups: []string{"apps"},
				Resources: []string{fmt.Sprintf("resource-%04d", index)},
			})
		}
		return measured
	}
	ceiling := &mtcpv1.GatewayGroupCeiling{}
	for group := range sharedmtcp.GatewayGroupReportMaximum {
		measured := &mtcpv1.GatewayCeilingGroup{Group: fmt.Sprintf("g%02d", group), Everywhere: scope("")}
		for namespace := range sharedmtcp.GatewayCeilingNamespaceMaximum {
			measured.Namespaces = append(measured.Namespaces, scope(fmt.Sprintf("ns-%02d", namespace)))
		}
		ceiling.Groups = append(ceiling.Groups, measured)
	}
	limit := sharedmtcp.MessageGatewayGroupCeiling.Limit()
	started := time.Now()
	fitCeiling(ceiling, limit)
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("took %v", took)
	}
	if size := proto.Size(ceiling); size > limit || !ceiling.GetTruncated() ||
		sharedmtcp.ValidateGatewayGroupCeiling(ceiling) != nil {
		t.Fatalf("%d bytes over %d", size, limit)
	}
}
