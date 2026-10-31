package mtcp

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

func ceilingRule(verbs, groups, resources []string) *mtcpv1.KubernetesProfileRule {
	return &mtcpv1.KubernetesProfileRule{Verbs: verbs, ApiGroups: groups, Resources: resources}
}

func ceilingScope(namespace string, rules ...*mtcpv1.KubernetesProfileRule) *mtcpv1.GatewayCeilingScope {
	return &mtcpv1.GatewayCeilingScope{Namespace: namespace, Measured: true, Rules: rules}
}

func validCeiling() *mtcpv1.GatewayGroupCeiling {
	return &mtcpv1.GatewayGroupCeiling{CheckedAtMs: 1_793_000_000_000, Groups: []*mtcpv1.GatewayCeilingGroup{
		{
			Group: "view", ClusterRole: "view",
			Everywhere: ceilingScope("",
				ceilingRule([]string{"get", "list", "watch"}, []string{""}, []string{"pods", "pods/log"}),
				&mtcpv1.KubernetesProfileRule{Verbs: []string{"get"}, NonResourceUrls: []string{"/api", "/api/*"}}),
		},
		{
			Group: "edit", ClusterRole: "system:aggregate-to-edit",
			Everywhere: &mtcpv1.GatewayCeilingScope{Measured: true, Incomplete: true},
			Namespaces: []*mtcpv1.GatewayCeilingScope{
				ceilingScope("default", &mtcpv1.KubernetesProfileRule{
					Verbs: []string{"*"}, ApiGroups: []string{"apps"},
					Resources: []string{"deployments"}, ResourceNames: []string{"web"},
				}),
				{Namespace: "team-a"},
			},
			NamespacesTruncated: true,
		},
	}}
}

func TestValidateGatewayGroupCeiling(t *testing.T) {
	t.Parallel()
	if err := ValidateGatewayGroupCeiling(validCeiling()); err != nil {
		t.Fatalf("a valid ceiling: %v", err)
	}
	if err := ValidateGatewayGroupCeiling(&mtcpv1.GatewayGroupCeiling{}); err != nil {
		t.Fatalf("an empty ceiling: %v", err)
	}
	for name, change := range map[string]func(*mtcpv1.GatewayGroupCeiling){
		"a negative time": func(c *mtcpv1.GatewayGroupCeiling) { c.CheckedAtMs = -1 },
		"a group twice":   func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[1].Group = "view" },
		"a bad group":     func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[0].Group = "View" },
		"65 groups": func(c *mtcpv1.GatewayGroupCeiling) {
			for index := range 63 {
				c.Groups = append(c.Groups, &mtcpv1.GatewayCeilingGroup{Group: "g" + strings.Repeat("a", index%60) +
					string(rune('a'+index/26)) + string(rune('a'+index%26)), Everywhere: &mtcpv1.GatewayCeilingScope{}})
			}
		},
		"a role with a slash": func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[0].ClusterRole = "a/b" },
		"a role of ..":        func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[0].ClusterRole = ".." },
		"no everywhere":       func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[0].Everywhere = nil },
		"a named everywhere":  func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[0].Everywhere.Namespace = "default" },
		"an unnamed namespace": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[1].Namespaces[0].Namespace = ""
		},
		"a namespace twice": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[1].Namespaces[1].Namespace = "default"
		},
		"an upper case namespace": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[1].Namespaces[0].Namespace = "Default"
		},
		"17 namespaces": func(c *mtcpv1.GatewayGroupCeiling) {
			for index := range 15 {
				c.Groups[1].Namespaces = append(c.Groups[1].Namespaces,
					&mtcpv1.GatewayCeilingScope{Namespace: "ns-" + string(rune('a'+index))})
			}
		},
		"unmeasured with rules": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[1].Namespaces[1].Rules = c.Groups[1].Namespaces[0].Rules
		},
		"unmeasured, incomplete": func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[1].Namespaces[1].Incomplete = true },
		"unmeasured, dropped":    func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[1].Namespaces[1].RulesDropped = 1 },
		"a rule without verbs": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[0].Verbs = nil
		},
		"a rule without resources": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[0].Resources = nil
		},
		"a rule without API groups": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[0].ApiGroups = nil
		},
		"a path rule naming resources": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[1].Resources = []string{"pods"}
		},
		"a control character": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[0].Resources = []string{"pods\n"}
		},
		"a non-ASCII name": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[1].Namespaces[0].Rules[0].ResourceNames = []string{"wéb"}
		},
		"a string of 254 bytes": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[0].Resources = []string{strings.Repeat("r", 254)}
		},
		"65 verbs": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[0].Verbs = make([]string, 65)
		},
		"a role with a percent sign": func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[0].ClusterRole = "a%2f" },
		"a role with a tab":          func(c *mtcpv1.GatewayGroupCeiling) { c.Groups[0].ClusterRole = "a\tb" },
		"a path rule with API groups": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[1].ApiGroups = []string{""}
		},
		"a path rule with names": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[1].ResourceNames = []string{"web"}
		},
		"names without resources": func(c *mtcpv1.GatewayGroupCeiling) {
			c.Groups[0].Everywhere.Rules[0].Resources = nil
			c.Groups[0].Everywhere.Rules[0].ResourceNames = []string{"web"}
		},
		"577 rules": func(c *mtcpv1.GatewayGroupCeiling) {
			rule := c.Groups[0].Everywhere.Rules[0]
			for range 575 {
				c.Groups[0].Everywhere.Rules = append(c.Groups[0].Everywhere.Rules, rule)
			}
		},
	} {
		ceiling := validCeiling()
		change(ceiling)
		if err := ValidateGatewayGroupCeiling(ceiling); !errors.Is(err, ErrGatewayGroupCeiling) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A scope of 576 typical rules (about 115 bytes each) fits the message
// alone. The bounds allow larger scopes: a gateway then drops rules from the
// end of the scope and counts them (§6.12).
func TestGatewayGroupCeilingTypicalFullScopeFits(t *testing.T) {
	t.Parallel()
	scope := &mtcpv1.GatewayCeilingScope{Measured: true}
	for range GatewayCeilingRuleMaximum {
		scope.Rules = append(scope.Rules, ceilingRule([]string{
			"get", "list", "watch", "create", "update", "patch",
			"delete",
		}, []string{"apps"}, []string{"deployments", "deployments/scale", "statefulsets", "replicasets"}))
	}
	ceiling := &mtcpv1.GatewayGroupCeiling{CheckedAtMs: 1_793_000_000_000, Groups: []*mtcpv1.GatewayCeilingGroup{
		{Group: strings.Repeat("g", 63), ClusterRole: strings.Repeat("r", 253), Everywhere: scope},
	}}
	if err := ValidateGatewayGroupCeiling(ceiling); err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(ceiling)
	if err != nil || len(encoded) > MessageGatewayGroupCeiling.Limit() {
		t.Fatalf("%d bytes, %v", len(encoded), err)
	}
}
