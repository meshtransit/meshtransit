package kubeproxy

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubereq"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/kubeprofile"
)

var (
	scopeDeveloper = [32]byte{0xd1}
	scopeReader    = [32]byte{0xd2}
	scopeImpersona = [32]byte{0xd3}
)

// fakeDiscovery knows pods, deployments and nodes; asked counts lookups.
type fakeDiscovery struct{ asked atomic.Int64 }

func (discovery *fakeDiscovery) Scope(_ context.Context, group, resource string) kubeprofile.ResourceScope {
	discovery.asked.Add(1)
	switch {
	case group == "" && (resource == "pods" || resource == "secrets"), group == "apps" && resource == "deployments":
		return kubeprofile.ScopeNamespaced
	case group == "" && (resource == "nodes" || resource == "namespaces"):
		return kubeprofile.ScopeCluster
	}
	return kubeprofile.ScopeUnknown
}

func testScope(t *testing.T, name string, namespaces []string, clusterPart bool, namespaced, cluster []kubeprofile.Rule,
) networkmap.KubernetesScope {
	t.Helper()
	profile := kubeprofile.Profile{Name: name, Namespaced: namespaced, Cluster: cluster}
	scope, err := kubeprofile.NewScope(profile, namespaces, clusterPart)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := kubeprofile.ContentHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	return networkmap.KubernetesScope{ProfileHash: hash, ProfileName: name, Scope: scope}
}

// testScopes are a developer profile (pods and deployments, any verb but
// delete, in team-a and team-b), a reader (get, list, watch everywhere) and
// one that may impersonate alice.
func testScopes(t *testing.T) map[[32]byte]networkmap.KubernetesScope {
	t.Helper()
	return map[[32]byte]networkmap.KubernetesScope{
		scopeDeveloper: testScope(t, "developer", []string{"team-a", "team-b"}, false, []kubeprofile.Rule{{
			APIGroups: []string{"", "apps"}, Resources: []string{"pods", "deployments"},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch"},
		}}, nil),
		scopeReader: testScope(t, "reader", []string{"*"}, false, []kubeprofile.Rule{{
			APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch"},
		}}, nil),
		scopeImpersona: testScope(t, "impersonator", []string{"team-a"}, true, []kubeprofile.Rule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"},
		}}, []kubeprofile.Rule{{
			APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"},
			ResourceNames: []string{"alice"},
		}}),
	}
}

func scopedPeer(t *testing.T, now time.Time, grants ...networkmap.KubernetesScopedGrant) Peer {
	t.Helper()
	return Peer{
		DeviceID: "device-a", Name: "laptop", Key: [32]byte{1}, Scopes: testScopes(t),
		AccessContact: "#platform-access", Access: &networkmap.KubernetesAccess{
			Scoped:   grants,
			OwnerRef: "person-1", OwnerChangedAt: now.Add(-30 * 24 * time.Hour),
		},
	}
}

func enforcing(group string, scope [32]byte, until time.Time) networkmap.KubernetesScopedGrant {
	return networkmap.KubernetesScopedGrant{Group: group, Scope: scope, ValidUntil: until}
}

func reporting(group string, scope [32]byte, reportUntil, until time.Time) networkmap.KubernetesScopedGrant {
	return networkmap.KubernetesScopedGrant{
		Group: group, Scope: scope, Report: true, ReportUntil: reportUntil,
		ValidUntil: until,
	}
}

func resourceCheck(verb, group, resource, namespace string, scope kubeprofile.ResourceScope) profileCheck {
	return profileCheck{request: kubeprofile.Attributes{
		ResourceRequest: true, Verb: verb, APIGroup: group,
		Resource: resource, Namespace: namespace, Scope: scope,
	}}
}

func TestDecide(t *testing.T) {
	t.Parallel()
	now := time.Now()
	later, sooner := now.Add(time.Hour), now.Add(-time.Second)
	edit, sre := Group{Name: "edit"}, Group{Name: "sre", Privileged: true}
	getPods := resourceCheck("get", "", "pods", "team-a", kubeprofile.ScopeNamespaced)
	deletePods := resourceCheck("delete", "", "pods", "team-a", kubeprofile.ScopeNamespaced)
	unknown := resourceCheck("get", "example.com", "widgets", "team-a", kubeprofile.ScopeUnknown)
	impersonating := getPods
	impersonating.impersonated = []kubeprofile.Attributes{impersonation("users", "alice")}
	impersonatingBob := getPods
	impersonatingBob.impersonated = []kubeprofile.Attributes{impersonation("users", "bob")}
	for _, test := range []struct {
		name     string
		peer     Peer
		group    Group
		check    profileCheck
		allowed  bool
		reported bool
		scope    [32]byte
		refusing int
	}{
		{name: "whole grant", peer: Peer{Access: &networkmap.KubernetesAccess{
			Grants: []networkmap.KubernetesGrant{{Group: "edit", ValidUntil: later}},
			Scoped: []networkmap.KubernetesScopedGrant{enforcing("edit", scopeDeveloper, later)},
		}, Scopes: testScopes(t)}, group: edit, check: deletePods, allowed: true},
		{
			name: "enforcing allows", peer: scopedPeer(t, now, enforcing("edit", scopeDeveloper, later)), group: edit,
			check: getPods, allowed: true, scope: scopeDeveloper,
		},
		{
			name: "enforcing refuses", peer: scopedPeer(t, now, enforcing("edit", scopeDeveloper, later)), group: edit,
			check: deletePods, scope: scopeDeveloper, refusing: 1,
		},
		{
			name: "grants join", peer: scopedPeer(t, now, enforcing("edit", scopeDeveloper, later),
				enforcing("edit", scopeReader, later)), group: edit,
			check: resourceCheck("get", "", "secrets", "kube-system", kubeprofile.ScopeNamespaced), allowed: true,
			scope: scopeReader,
		},
		{
			name: "another group's grant", peer: scopedPeer(t, now, enforcing("view", scopeReader, later)), group: edit,
			check: getPods,
		},
		{
			name: "expired grant", peer: scopedPeer(t, now, enforcing("edit", scopeDeveloper, sooner)), group: edit,
			check: getPods,
		},
		{
			name: "report lets through", peer: scopedPeer(t, now, reporting("edit", scopeDeveloper, later, later)),
			group: edit, check: deletePods, allowed: true, reported: true, scope: scopeDeveloper, refusing: 1,
		},
		{
			name: "report past its deadline enforces", peer: scopedPeer(t, now,
				reporting("edit", scopeDeveloper, sooner, later)), group: edit, check: deletePods,
			scope: scopeDeveloper, refusing: 1,
		},
		{
			name: "report allows without reporting", peer: scopedPeer(t, now,
				reporting("edit", scopeDeveloper, later, later)), group: edit, check: getPods, allowed: true,
			scope: scopeDeveloper,
		},
		{
			name: "a privileged group never reports", peer: scopedPeer(t, now,
				reporting("sre", scopeDeveloper, later, later)), group: sre, check: deletePods, scope: scopeDeveloper,
			refusing: 1,
		},
		{
			name: "unknown scope of the map", peer: scopedPeer(t, now, enforcing("edit", [32]byte{0xee}, later)),
			group: edit, check: getPods,
		},
		{
			name: "discovery does not know", peer: scopedPeer(t, now, enforcing("edit", scopeReader, later)),
			group: edit, check: unknown, scope: scopeReader, refusing: 1,
		},
		{
			name: "exempt", peer: scopedPeer(t, now, enforcing("edit", scopeDeveloper, later)), group: edit,
			check: profileCheck{exempt: true}, allowed: true, scope: scopeDeveloper,
		},
		{
			name: "impersonation allowed", peer: scopedPeer(t, now, enforcing("sre", scopeImpersona, later)), group: sre,
			check: impersonating, allowed: true, scope: scopeImpersona,
		},
		{
			name: "impersonating another name", peer: scopedPeer(t, now, enforcing("sre", scopeImpersona, later)),
			group: sre, check: impersonatingBob, scope: scopeImpersona, refusing: 1,
		},
		{name: "impersonation needs the same grant", peer: scopedPeer(t, now, enforcing("sre", scopeReader, later),
			enforcing("sre", scopeImpersona, later)), group: sre, check: func() profileCheck {
			check := resourceCheck("get", "", "secrets", "team-a", kubeprofile.ScopeNamespaced)
			check.impersonated = []kubeprofile.Attributes{impersonation("users", "alice")}
			return check
		}(), scope: scopeReader, refusing: 2},
		{name: "no access", peer: Peer{}, group: edit, check: getPods},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := decide(test.peer, test.group, test.check, now)
			if got.allowed != test.allowed || got.reported != test.reported || got.scope != test.scope ||
				len(got.refusing) != test.refusing {
				t.Fatalf("decide = allowed %v reported %v scope %x refusing %d", got.allowed, got.reported,
					got.scope[:1], len(got.refusing))
			}
		})
	}
}

func TestCheckForReadsTheRequest(t *testing.T) {
	t.Parallel()
	discovery := &fakeDiscovery{}
	server := &Server{options: Options{Discovery: discovery}}
	check := func(method, path string, header http.Header) profileCheck {
		target, _ := url.Parse(path)
		info, _ := kubereq.Parse(method, target)
		request := &http.Request{Method: method, URL: target, Header: header}
		return server.checkFor(t.Context(), request, info, header, true)
	}
	if got := check(http.MethodGet, "/apis/apps/v1", http.Header{}); !got.exempt {
		t.Fatal("discovery is not exempt")
	}
	if got := check(http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
		http.Header{}); !got.exempt {
		t.Fatal("a self review is not exempt")
	}
	asked := discovery.asked.Load()
	put := check(http.MethodPut, "/api/v1/namespaces/team-a/pods/p", http.Header{})
	if !put.request.MayCreate || put.request.Scope != kubeprofile.ScopeNamespaced || discovery.asked.Load() != asked+1 {
		t.Fatalf("PUT: %+v", put.request)
	}
	apply := check(http.MethodPatch, "/apis/apps/v1/namespaces/team-a/deployments/d",
		http.Header{"Content-Type": {"Application/Apply-Patch+YAML; charset=utf-8"}})
	merge := check(http.MethodPatch, "/apis/apps/v1/namespaces/team-a/deployments/d",
		http.Header{"Content-Type": {"application/merge-patch+json"}})
	if !apply.request.MayCreate || merge.request.MayCreate {
		t.Fatalf("apply %v, merge %v", apply.request.MayCreate, merge.request.MayCreate)
	}
	exec := check(http.MethodGet, "/api/v1/namespaces/team-a/pods/p/exec?command=sh",
		http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}})
	if !exec.request.Upgrade || exec.request.Subresource != "exec" {
		t.Fatalf("exec: %+v", exec.request)
	}
	impersonating := check(http.MethodGet, "/api/v1/nodes", http.Header{
		"Impersonate-User":  {"alice"},
		"Impersonate-Group": {"devs", "ops"},
	})
	if len(impersonating.impersonated) != 3 || impersonating.impersonated[2].Name != "ops" ||
		impersonating.request.Scope != kubeprofile.ScopeCluster {
		t.Fatalf("impersonation: %+v", impersonating)
	}
	nonResource := check(http.MethodPost, "/logs/x", http.Header{})
	if nonResource.exempt || nonResource.request.ResourceRequest || discovery.asked.Load() != asked+5 {
		t.Fatalf("a non-resource request: %+v, %d lookups", nonResource, discovery.asked.Load()-asked)
	}
	without := (&Server{}).checkFor(t.Context(), &http.Request{Method: http.MethodGet, Header: http.Header{}},
		kubereq.Info{IsResourceRequest: true, Verb: "get", Resource: "pods", Namespace: "team-a"}, http.Header{}, true)
	if without.request.Scope != kubeprofile.ScopeUnknown {
		t.Fatal("without discovery a resource is known")
	}
}

func TestProfileMessage(t *testing.T) {
	t.Parallel()
	now := time.Now()
	peer := scopedPeer(t, now)
	scopes := testScopes(t)
	message := profileMessage(peer, Group{Name: "edit"},
		resourceCheck("delete", "", "pods", "team-a", kubeprofile.ScopeNamespaced),
		[]networkmap.KubernetesScope{scopes[scopeDeveloper]})
	for _, want := range []string{
		`profile "developer" (namespaces team-a, team-b) of group edit does not allow`,
		`"delete" on "pods" in namespace "team-a"`,
	} {
		if !strings.Contains(message, want) {
			t.Errorf("missing %q in %q", want, message)
		}
	}
	if !strings.HasSuffix(message, ` (access contact set by the cluster's admins: "#platform-access")`) {
		t.Errorf("the contact is not last: %q", message)
	}
	listAll := profileMessage(Peer{}, Group{Name: "edit"},
		resourceCheck("list", "apps", "deployments", "", kubeprofile.ScopeNamespaced),
		[]networkmap.KubernetesScope{scopes[scopeDeveloper], scopes[scopeImpersona]})
	for _, want := range []string{
		`profiles "developer" (namespaces team-a, team-b), "impersonator" (namespace team-a)`,
		`do not allow "list" on "deployments" of API group "apps" across namespaces; use -n team-a`,
	} {
		if !strings.Contains(listAll, want) {
			t.Errorf("missing %q in %q", want, listAll)
		}
	}
	if strings.Contains(listAll, "access contact") {
		t.Errorf("a contact without one: %q", listAll)
	}
	unknown := profileMessage(Peer{}, Group{Name: "edit"},
		resourceCheck("get", "example.com", "widgets", "team-a", kubeprofile.ScopeUnknown),
		[]networkmap.KubernetesScope{scopes[scopeReader]})
	if !strings.Contains(unknown, `"reader" (all namespaces)`) ||
		!strings.Contains(unknown, "the cluster's discovery does not know this resource") {
		t.Errorf("unknown: %q", unknown)
	}
	path := profileMessage(Peer{AccessContact: "a \"quoted\" contact"}, Group{Name: "edit"},
		profileCheck{request: kubeprofile.Attributes{Verb: "get", Path: "/metrics"}},
		[]networkmap.KubernetesScope{scopes[scopeReader]})
	if !strings.Contains(path, `"get" on path "/metrics"`) || !strings.Contains(path, `"a \"quoted\" contact"`) {
		t.Errorf("path: %q", path)
	}
}

// profiledFixture is a proxy whose peer holds edit through scoped grants
// only, with the cluster's discovery.
func profiledFixture(t *testing.T, clock *atomic.Pointer[time.Time],
	grants ...networkmap.KubernetesScopedGrant,
) *fixture {
	t.Helper()
	f := newFixtureAt(t, "", func(options *Options) {
		options.Discovery = &fakeDiscovery{}
		if clock != nil {
			options.CoreNow = func() time.Time { return *clock.Load() }
		}
	})
	peer := scopedPeer(t, time.Now(), grants...)
	f.peer.Store(&peer)
	return f
}

func TestProxyEnforcesProfiles(t *testing.T) {
	t.Parallel()
	until := time.Now().Add(time.Hour)
	f := profiledFixture(t, nil, enforcing("edit", scopeDeveloper, until))
	if response, _ := f.do(http.MethodGet, "/api/v1/namespaces/team-a/pods", nil); response.StatusCode != http.StatusOK {
		t.Fatalf("an allowed read: %d", response.StatusCode)
	}
	f.forwarded()
	response, body := f.do(http.MethodDelete, "/api/v1/namespaces/team-a/pods/p", nil)
	if response.StatusCode != http.StatusForbidden || !strings.Contains(body, `profile \"developer\"`) ||
		!strings.Contains(body, "#platform-access") {
		t.Fatalf("a refused delete: %d %s", response.StatusCode, body)
	}
	f.nothingForwarded()
	response, _ = f.do(http.MethodPatch, "/apis/apps/v1/namespaces/team-b/deployments/d",
		http.Header{"Content-Type": {"application/merge-patch+json"}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("an allowed patch: %d", response.StatusCode)
	}
	f.forwarded()
	response, _ = f.do(http.MethodGet, "/api/v1/namespaces/team-c/pods", nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("another namespace: %d", response.StatusCode)
	}
	if response, _ = f.do(http.MethodGet, "/apis", nil); response.StatusCode != http.StatusOK {
		t.Fatalf("discovery: %d", response.StatusCode)
	}
	f.forwarded()
	f.records.mu.Lock()
	defer f.records.mu.Unlock()
	if len(f.records.intents) != 1 || !bytes.Equal(f.records.intents[0].Profile, scopeDeveloper[:]) ||
		f.records.intents[0].ReportAllowed {
		t.Fatalf("intents: %+v", f.records.intents)
	}
	if decisions := f.server.ProfileDecisions(); decisions["allowed"] != 2 || decisions["denied"] != 2 {
		t.Fatalf("decisions %v", decisions)
	}
	if strings.Join(f.records.denied, ",") != "profile_denied,profile_denied" || len(f.records.samples) != 2 ||
		f.records.samples[0] != (controlplane.KubeAuditDenialSample{
			Verb: "delete", Resource: "pods",
			Namespace: "team-a", Scope: scopeDeveloper,
		}) {
		t.Fatalf("denials %v, samples %+v", f.records.denied, f.records.samples)
	}
}

func TestProxyReportsWhatAProfileWouldDeny(t *testing.T) {
	t.Parallel()
	until := time.Now().Add(time.Hour)
	f := profiledFixture(t, nil, reporting("edit", scopeDeveloper, until, until))
	response, _ := f.do(http.MethodDelete, "/api/v1/namespaces/team-a/pods/p", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("a reported delete: %d", response.StatusCode)
	}
	f.forwarded()
	f.records.mu.Lock()
	defer f.records.mu.Unlock()
	if len(f.records.intents) != 1 || !f.records.intents[0].ReportAllowed ||
		!bytes.Equal(f.records.intents[0].Profile, scopeDeveloper[:]) {
		t.Fatalf("intents: %+v", f.records.intents)
	}
	if strings.Join(f.records.denied, ",") != "profile_would_deny" {
		t.Fatalf("denials: %v", f.records.denied)
	}
}

func TestProxyWholeGrantNamesNoProfile(t *testing.T) {
	t.Parallel()
	f := newFixtureAt(t, "", func(options *Options) { options.Discovery = &fakeDiscovery{} })
	if response, _ := f.do(http.MethodDelete, "/mt/g/edit/api/v1/namespaces/x/pods/p", nil); response.StatusCode !=
		http.StatusOK {
		t.Fatalf("a whole grant: %d", response.StatusCode)
	}
	f.forwarded()
	f.records.mu.Lock()
	defer f.records.mu.Unlock()
	if len(f.records.intents) != 1 || f.records.intents[0].Profile != nil {
		t.Fatalf("intents: %+v", f.records.intents)
	}
}

func TestSweepCutsWhenTheReportEnds(t *testing.T) {
	t.Parallel()
	var clock atomic.Pointer[time.Time]
	now := time.Now()
	clock.Store(&now)
	f := profiledFixture(t, &clock, reporting("edit", scopeReader, now.Add(time.Minute), now.Add(time.Hour)))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+clusterName+"/api/v1/namespaces/team-a/secrets?watch=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The reader profile allows watching secrets; developer does not.
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	f.forwarded()
	f.server.Sweep()
	if cut := f.server.Sessions().Cut[cutProfile]; cut != 0 {
		t.Fatalf("cut %d while the profile allows", cut)
	}
	// A narrower table: the grant now names the developer profile, which
	// does not cover secrets.
	peer := scopedPeer(t, now, reporting("edit", scopeDeveloper, now.Add(time.Minute), now.Add(time.Hour)))
	f.peer.Store(&peer)
	f.server.Sweep()
	if cut := f.server.Sessions().Cut[cutProfile]; cut != 0 {
		t.Fatalf("cut %d while the report lets it through", cut)
	}
	later := now.Add(2 * time.Minute)
	clock.Store(&later)
	f.server.Sweep()
	if cut := f.server.Sessions().Cut[cutProfile]; cut != 1 {
		t.Fatalf("not cut once the report ended: %v", f.server.Sessions().Cut)
	}
}

func TestWithheldMapRefusesAndCuts(t *testing.T) {
	t.Parallel()
	f := profiledFixture(t, nil, enforcing("edit", scopeReader, time.Now().Add(time.Hour)))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+clusterName+"/api/v1/namespaces/team-a/pods?watch=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	f.forwarded()
	withheld := Peer{DeviceID: "device-a", Name: "laptop", Key: [32]byte{1}, Withheld: true}
	f.peer.Store(&withheld)
	f.server.Sweep()
	if cut := f.server.Sessions().Cut[cutWithheld]; cut != 1 {
		t.Fatalf("not cut: %v", f.server.Sessions().Cut)
	}
	refused, body := f.do(http.MethodGet, "/api/v1/namespaces/team-a/pods", nil)
	if refused.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "unusable") {
		t.Fatalf("a request while withheld: %d %s", refused.StatusCode, body)
	}
}

// An exempt request still impersonates only what the grant allows (review
// e1–e3 H1); a whole grant never waits for discovery.
func TestExemptRequestsCheckImpersonation(t *testing.T) {
	t.Parallel()
	discovery := &fakeDiscovery{}
	server := &Server{options: Options{Discovery: discovery}}
	target, _ := url.Parse("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews")
	info, _ := kubereq.Parse(http.MethodPost, target)
	header := http.Header{"Impersonate-User": {"bob"}}
	check := server.checkFor(t.Context(), &http.Request{Method: http.MethodPost, URL: target, Header: header}, info,
		header, true)
	if !check.exempt || len(check.impersonated) != 1 {
		t.Fatalf("check %+v", check)
	}
	now := time.Now()
	sre := Group{Name: "sre", Privileged: true}
	if decide(scopedPeer(t, now, enforcing("sre", scopeReader, now.Add(time.Hour))), sre, check, now).allowed {
		t.Fatal("a self review impersonated what no grant allows")
	}
	check.impersonated[0].Name = "alice"
	if !decide(scopedPeer(t, now, enforcing("sre", scopeImpersona, now.Add(time.Hour))), sre, check, now).allowed {
		t.Fatal("a self review impersonating an allowed name was refused")
	}
	pods, _ := url.Parse("/api/v1/namespaces/team-a/pods")
	podsInfo, _ := kubereq.Parse(http.MethodGet, pods)
	whole := server.checkFor(t.Context(), &http.Request{Method: http.MethodGet, URL: pods, Header: http.Header{}},
		podsInfo, http.Header{}, false)
	if discovery.asked.Load() != 0 || whole.request.Scope != kubeprofile.ScopeUnknown {
		t.Fatal("a lookup without need")
	}
}

func TestProxyWholeGrantNeverAsksDiscovery(t *testing.T) {
	t.Parallel()
	discovery := &fakeDiscovery{}
	f := newFixtureAt(t, "", func(options *Options) { options.Discovery = discovery })
	if response, _ := f.do(http.MethodGet, "/api/v1/namespaces/x/widgets", nil); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	f.forwarded()
	if discovery.asked.Load() != 0 {
		t.Fatal("a whole grant asked discovery")
	}
}

func TestDecideEdges(t *testing.T) {
	t.Parallel()
	now := time.Now()
	edit := Group{Name: "edit"}
	deletePods := resourceCheck("delete", "", "pods", "team-a", kubeprofile.ScopeNamespaced)
	// A reporting grant without a deadline enforces.
	zero := reporting("edit", scopeDeveloper, time.Time{}, now.Add(time.Hour))
	if decide(scopedPeer(t, now, zero), edit, deletePods, now).allowed {
		t.Fatal("a report without a deadline let it through")
	}
	// S3 applies to the main resource only: an update of a status needs no
	// create.
	updates := testScope(t, "updater", []string{"team-a"}, false, []kubeprofile.Rule{{
		APIGroups: []string{""}, Resources: []string{"pods", "pods/status"}, Verbs: []string{"update"},
	}}, nil)
	peer := scopedPeer(t, now, enforcing("edit", [32]byte{0xd4}, now.Add(time.Hour)))
	peer.Scopes[[32]byte{0xd4}] = updates
	status := resourceCheck("update", "", "pods", "team-a", kubeprofile.ScopeNamespaced)
	status.request.Subresource, status.request.MayCreate = "status", true
	if !decide(peer, edit, status, now).allowed {
		t.Fatal("a PUT of a subresource needed create")
	}
	main := resourceCheck("update", "", "pods", "team-a", kubeprofile.ScopeNamespaced)
	main.request.MayCreate = true
	if decide(peer, edit, main, now).allowed {
		t.Fatal("a PUT of the main resource needed no create")
	}
}
