package postgres

import (
	"strings"
	"testing"
)

func TestActivePolicyDecoderRejectsDisclosureAndInvalidRules(t *testing.T) {
	t.Parallel()
	valid := `{"workspace_id":"01890f00-0000-7000-8000-000000000101","network_id":"01890f00-0000-7000-8000-000000000201","policy_revision":1,"semantic_hash":null,"rule_count":0,"device_rules_only":true,"rules":[]}`
	snapshot, err := decodeActivePolicy(valid)
	if err != nil || !snapshot.IsValid() || !snapshot.Complete() || !snapshot.DeviceRulesOnly() {
		t.Fatalf("empty active policy: %v", err)
	}
	for _, test := range []struct{ name, payload string }{
		{name: "provider field", payload: strings.Replace(valid, `"rules":[]`, `"rules":[],"provider_workspace_id":"01890f00-0000-7000-8000-000000000999"`, 1)},
		{name: "null rules", payload: strings.Replace(valid, `"rules":[]`, `"rules":null`, 1)},
		{name: "incomplete count", payload: strings.Replace(valid, `"rule_count":0`, `"rule_count":1`, 1)},
		{name: "missing active artifact", payload: strings.Replace(valid, `"policy_revision":1`, `"policy_revision":2`, 1)},
		{name: "extra value", payload: valid + `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeActivePolicy(test.payload); err == nil {
				t.Fatal("invalid projection accepted")
			}
		})
	}
	scope := postgresPolicySimulationScope(t)
	for _, ports := range [][2]int{{0, 1}, {1, 65536}, {1, -1}, {65536, 65536}, {443, 80}} {
		row := activePolicyRuleWire{ID: postgresPolicySimulationID(501), SourceID: postgresPolicySimulationID(301), DestinationID: postgresPolicySimulationID(302), SelectorKind: "device", SelectorID: postgresPolicySimulationID(302), Protocol: "tcp"}
		row.Ports = append(row.Ports, struct {
			First int `json:"first"`
			Last  int `json:"last"`
		}{First: ports[0], Last: ports[1]})
		if _, err := row.parse(scope); err == nil {
			t.Fatal("invalid ports accepted")
		}
	}
}

func FuzzDecodeActivePolicy(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"workspace_id":"01890f00-0000-7000-8000-000000000101","network_id":"01890f00-0000-7000-8000-000000000201","policy_revision":1,"semantic_hash":null,"rule_count":0,"device_rules_only":true,"rules":[]}`)
	f.Fuzz(func(t *testing.T, input string) {
		snapshot, err := decodeActivePolicy(input)
		if err == nil && !snapshot.IsValid() {
			t.Fatal("invalid snapshot without error")
		}
	})
}
