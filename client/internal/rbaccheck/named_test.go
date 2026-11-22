package rbaccheck

import (
	"context"
	"strings"
	"testing"

	"meshtransit.net/shared/kubeprofile"
)

// TD-CLI-84: a rule naming a static pod, a Secret or a DaemonSet in a guarded
// namespace turns a non-privileged group off; other named rules and other
// namespaces do not, and an incomplete answer only leaves a note.
func TestCheckerTurnsOffRightsByName(t *testing.T) {
	t.Parallel()
	rule := func(groups, resources, verbs, names []string) kubeprofile.Rule {
		return kubeprofile.Rule{APIGroups: groups, Resources: resources, Verbs: verbs, ResourceNames: names}
	}
	core := []string{""}
	cases := map[string]struct {
		namespace string
		answer    RulesAnswer
		reason    string // "" for enabled
		note      string
	}{
		"exec into etcd": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"pods/exec"}, []string{"create"}, []string{"etcd-node-1"})}},
			"may create pods/exec etcd-node-1 in kube-system", ""},
		"websocket exec by get": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"pods/exec"}, []string{"get"}, []string{"kube-apiserver-node-1"})}},
			"may get pods/exec kube-apiserver-node-1 in kube-system", ""},
		"any resource's exec": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"*/exec"}, []string{"create"}, []string{"etcd-node-1"})}},
			"may create pods/exec etcd-node-1 in kube-system", ""},
		"everything by name": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule([]string{"*"}, []string{"*"}, []string{"*"}, []string{"etcd-node-1", "etcd-node-2", "etcd-node-3"})}},
			"may get pods/exec etcd-node-1 and 2 more in kube-system", ""},
		"pods/* is no RBAC wildcard": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"pods/*"}, []string{"get"}, []string{"etcd-node-1"})}}, "", ""},
		"kubelet exec on a named node": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"nodes/proxy"}, []string{"create"}, []string{"cp-node-1"})}},
			"may create nodes/proxy cp-node-1 in kube-system", ""},
		"the placement policy by name": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule([]string{admission}, []string{"validatingadmissionpolicybindings"}, []string{"patch"},
				[]string{"meshgw-placement"})}},
			"may patch admissionregistration.k8s.io/validatingadmissionpolicybindings meshgw-placement in kube-system", ""},
		"its own role": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule([]string{rbac}, []string{"roles"}, []string{"escalate", "update"}, []string{"team"})}},
			"may update rbac.authorization.k8s.io/roles team in kube-system", ""},
		"system:masters": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"})}},
			"may impersonate groups system:masters in kube-system", ""},
		"the gateway's namespace": {"meshtransit", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"secrets"}, []string{"get"}, []string{"sh.helm.release.v1.gateway.v1"})}},
			"may get secrets sh.helm.release.v1.gateway.v1 in meshtransit", ""},
		"incomplete, but a rule matches": {"kube-system", RulesAnswer{Incomplete: true, Rules: []kubeprofile.Rule{
			rule(core, []string{"secrets"}, []string{"list"}, nil)}},
			"may list secrets in kube-system", ""},
		"path rules": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}}}}, "", ""},
		"an unprintable name": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"secrets"}, []string{"get"}, []string{"a\nb" + strings.Repeat("x", 100)})}},
			"may get secrets a?b" + strings.Repeat("x", 60) + "... in kube-system", ""},
		"a named Secret": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"secrets"}, []string{"get"}, []string{"bootstrap-token-abc"})}},
			"may get secrets bootstrap-token-abc in kube-system", ""},
		"kube-proxy's DaemonSet": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule([]string{"*"}, []string{"daemonsets"}, []string{"*"}, []string{"kube-proxy"})}},
			"may update apps/daemonsets kube-proxy in kube-system", ""},
		"aws-auth": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"configmaps"}, []string{"patch"}, []string{"aws-auth"})}},
			"may patch configmaps aws-auth in kube-system", ""},
		"reading a named ConfigMap": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"configmaps"}, []string{"get"}, []string{"cluster-info"})}}, "", ""},
		"pod logs": {"kube-system", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"pods/log"}, []string{"get"}, []string{"etcd-node-1"})}}, "", ""},
		"exec elsewhere": {"default", RulesAnswer{Rules: []kubeprofile.Rule{
			rule(core, []string{"pods/exec"}, []string{"create"}, []string{"etcd-node-1"})}}, "", ""},
		"incomplete": {"kube-system", RulesAnswer{Incomplete: true}, "",
			"rights by name not proven absent in kube-system"},
	}
	for name, test := range cases {
		reviewer := &fakeReviewer{rules: map[string]RulesAnswer{"view/" + test.namespace: test.answer}}
		checker := testChecker(t, reviewer, Group{Name: "view"}, Group{Name: "admin", Privileged: true})
		checker.Pass(t.Context())
		verdict := checker.Verdict("view")
		switch {
		case test.reason != "" && (verdict.Enabled || verdict.Reason != test.reason || verdict.Code != CodeRBACExceeds):
			t.Errorf("%s: verdict %+v, want off: %q", name, verdict, test.reason)
		case test.reason == "" && !verdict.Enabled:
			t.Errorf("%s: verdict %+v, want on", name, verdict)
		case test.reason == "" && !strings.HasPrefix(verdict.Reason, test.note):
			t.Errorf("%s: note %q, want %q", name, verdict.Reason, test.note)
		}
		if !checker.Verdict("admin").Enabled {
			t.Errorf("%s: the privileged group is off", name)
		}
	}
}

// A guarded namespace of the options is read too.
func TestCheckerReadsEveryGuardedNamespace(t *testing.T) {
	t.Parallel()
	reviewer := &fakeReviewer{rules: map[string]RulesAnswer{"view/ingress-nginx": {Rules: []kubeprofile.Rule{{
		APIGroups: []string{""}, Resources: []string{"pods/attach"}, Verbs: []string{"create"},
		ResourceNames: []string{"controller-0"},
	}}}}}
	options := testOptions(reviewer, fakeTokens{}, Group{Name: "view"})
	options.GuardedNamespaces = []string{"ingress-nginx"}
	checker, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	checker.Pass(t.Context())
	if verdict := checker.Verdict("view"); verdict.Enabled ||
		verdict.Reason != "may create pods/attach controller-0 in ingress-nginx" {
		t.Errorf("verdict %+v", verdict)
	}
}

// A token the API server refuses for a rules review is forgotten and
// replaced once, and the group is checked with the new one.
func TestRulesReviewReplacesARefusedToken(t *testing.T) {
	t.Parallel()
	tokens := &countingTokens{}
	checker, err := New(testOptions(rulesRefusingReviewer{}, tokens, Group{Name: "view"}))
	if err != nil {
		t.Fatal(err)
	}
	checker.Pass(t.Context())
	if verdict := checker.Verdict("view"); !verdict.Enabled {
		t.Errorf("verdict %+v, want on", verdict)
	}
	if tokens.forgotten != 1 {
		t.Errorf("forgotten %d tokens, want 1", tokens.forgotten)
	}
}

// rulesRefusingReviewer refuses a stale token in a rules review only.
type rulesRefusingReviewer struct{}

func (rulesRefusingReviewer) Review(context.Context, string, Attributes) (bool, error) {
	return false, nil
}

func (rulesRefusingReviewer) RulesReview(_ context.Context, token, _ string) (RulesAnswer, error) {
	if strings.HasPrefix(token, "stale-") {
		return RulesAnswer{}, ErrUnauthorized
	}
	return RulesAnswer{}, nil
}
