package guardrail_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

func id(t *testing.T) publicid.ID {
	t.Helper()
	value, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type fixture struct {
	ours, partner, stranger                 workspace.ID
	vendor, production, staging, partnerNet network.ID
	strangerNet                             network.ID
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	return fixture{
		ours: workspace.ID(id(t)), partner: workspace.ID(id(t)), stranger: workspace.ID(id(t)),
		vendor: network.ID(id(t)), production: network.ID(id(t)), staging: network.ID(id(t)),
		partnerNet: network.ID(id(t)), strangerNet: network.ID(id(t)),
	}
}

func scope(t *testing.T, workspaceID workspace.ID, networkID network.ID) network.Scope {
	t.Helper()
	value, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func rail(t *testing.T, spec guardrail.Spec) guardrail.Guardrail {
	t.Helper()
	if !spec.IsValid() {
		t.Fatalf("spec %+v is invalid", spec)
	}
	return guardrail.Guardrail{ID: id(t), Version: 1, Spec: spec}
}

func TestEvaluateShareEdges(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	isolation := rail(t, guardrail.Spec{Kind: guardrail.KindNetworkIsolation, Name: "Vendor never reaches Production",
		Mode: guardrail.ModeEnforce, Isolation: guardrail.NetworkIsolationParams{
			From: []network.ID{f.vendor}, To: []network.ID{f.production}}})
	lockOut := rail(t, guardrail.Spec{Kind: guardrail.KindNetworkSharing, Name: "Production shares nothing",
		Mode: guardrail.ModeAudit, Sharing: guardrail.NetworkSharingParams{
			Networks: []network.ID{f.production}, Direction: guardrail.DirectionOutgoing}})
	external := rail(t, guardrail.Spec{Kind: guardrail.KindExternalSharing, Name: "Only our MSP",
		Mode: guardrail.ModeEnforce, External: guardrail.ExternalSharingParams{
			Direction: guardrail.DirectionBoth, AllowedWorkspaces: []workspace.ID{f.partner}}})
	all := []guardrail.Guardrail{isolation, lockOut, external}

	cases := []struct {
		name     string
		provider network.Scope
		consumer network.Scope
		want     []string
	}{
		{"vendor reaches production", scope(t, f.ours, f.production), scope(t, f.ours, f.vendor),
			[]string{guardrail.ReasonIsolatedNetworks, guardrail.ReasonSharingLocked}},
		{"production reaches vendor is the other direction", scope(t, f.ours, f.vendor), scope(t, f.ours, f.production), nil},
		{"staging receives from production", scope(t, f.ours, f.production), scope(t, f.ours, f.staging),
			[]string{guardrail.ReasonSharingLocked}},
		{"partner Workspace is allowed", scope(t, f.ours, f.staging), scope(t, f.partner, f.partnerNet), nil},
		{"stranger cannot receive", scope(t, f.ours, f.staging), scope(t, f.stranger, f.strangerNet),
			[]string{guardrail.ReasonExternalSharing}},
		{"stranger cannot offer to us", scope(t, f.stranger, f.strangerNet), scope(t, f.ours, f.staging),
			[]string{guardrail.ReasonExternalSharing}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := guardrail.Evaluate(all, f.ours, guardrail.ShareEdge{Provider: test.provider, Consumer: test.consumer})
			reasons := make([]string, len(findings))
			for index, finding := range findings {
				reasons[index] = finding.Reason
			}
			if len(reasons) != len(test.want) {
				t.Fatalf("reasons = %v, want %v", reasons, test.want)
			}
			for index := range reasons {
				if reasons[index] != test.want[index] {
					t.Fatalf("reasons = %v, want %v", reasons, test.want)
				}
			}
		})
	}
}

func TestCheckBlocksOnlyEnforcedGuardrails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	audit := rail(t, guardrail.Spec{Kind: guardrail.KindNetworkSharing, Name: "Watch Production",
		Mode: guardrail.ModeAudit, Sharing: guardrail.NetworkSharingParams{
			Networks: []network.ID{f.production}, Direction: guardrail.DirectionBoth}})
	edge := guardrail.ShareEdge{Provider: scope(t, f.ours, f.production), Consumer: scope(t, f.ours, f.staging)}
	findings, err := guardrail.Check([]guardrail.Guardrail{audit}, f.ours, edge)
	if err != nil || len(findings) != 1 {
		t.Fatalf("audit mode: findings %v, err %v; want one finding and no block", findings, err)
	}
	audit.Mode = guardrail.ModeEnforce
	_, err = guardrail.Check([]guardrail.Guardrail{audit}, f.ours, edge)
	var violation *guardrail.ViolationError
	if !errors.As(err, &violation) || len(violation.Findings) != 1 || violation.Findings[0].Name != "Watch Production" {
		t.Fatalf("enforce mode error = %v, want a violation naming the guardrail", err)
	}
}

func TestOtherWorkspacesGuardrailsAreNotOurs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	theirs := rail(t, guardrail.Spec{Kind: guardrail.KindExternalSharing, Name: "No external",
		Mode: guardrail.ModeEnforce, External: guardrail.ExternalSharingParams{Direction: guardrail.DirectionBoth}})
	edge := guardrail.ShareEdge{Provider: scope(t, f.stranger, f.strangerNet), Consumer: scope(t, f.ours, f.staging)}
	// Evaluated as a third Workspace that is on neither side: nothing applies.
	if findings := guardrail.Evaluate([]guardrail.Guardrail{theirs}, f.partner, edge); len(findings) != 0 {
		t.Fatalf("findings for an uninvolved Workspace = %v", findings)
	}
}

func TestRequiredPermission(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	base := guardrail.Spec{Kind: guardrail.KindExternalSharing, Name: "External", Mode: guardrail.ModeEnforce,
		External: guardrail.ExternalSharingParams{Direction: guardrail.DirectionOutgoing,
			Networks: []network.ID{f.production}, AllowedWorkspaces: []workspace.ID{f.partner}}}
	with := func(change func(*guardrail.Spec)) *guardrail.Spec {
		next := base
		next.External.Networks = append([]network.ID(nil), base.External.Networks...)
		next.External.AllowedWorkspaces = append([]workspace.ID(nil), base.External.AllowedWorkspaces...)
		change(&next)
		return &next
	}
	manage, weaken := authorization.PermissionGuardrailManage, authorization.PermissionGuardrailWeaken
	cases := map[string]struct {
		next *guardrail.Spec
		want authorization.Permission
	}{
		"rename":                {with(func(s *guardrail.Spec) { s.Name = "Renamed" }), manage},
		"cover both directions": {with(func(s *guardrail.Spec) { s.External.Direction = guardrail.DirectionBoth }), manage},
		"cover every Network":   {with(func(s *guardrail.Spec) { s.External.Networks = nil }), manage},
		"drop the partner":      {with(func(s *guardrail.Spec) { s.External.AllowedWorkspaces = nil }), manage},
		"add a partner": {with(func(s *guardrail.Spec) {
			s.External.AllowedWorkspaces = append(s.External.AllowedWorkspaces, f.stranger)
		}), weaken},
		"switch to incoming": {with(func(s *guardrail.Spec) { s.External.Direction = guardrail.DirectionIncoming }), weaken},
		"audit only":         {with(func(s *guardrail.Spec) { s.Mode = guardrail.ModeAudit }), weaken},
		"delete":             {nil, weaken},
	}
	for name, test := range cases {
		if got := guardrail.RequiredPermission(&base, test.next); got != test.want {
			t.Errorf("%s: permission = %s, want %s", name, got, test.want)
		}
	}
	if got := guardrail.RequiredPermission(nil, &base); got != manage {
		t.Errorf("create: permission = %s, want %s", got, manage)
	}
}

func TestSpecValidationAndCanonicalParams(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	valid := guardrail.Spec{Kind: guardrail.KindNetworkIsolation, Name: "Isolate", Mode: guardrail.ModeAudit,
		Isolation: guardrail.NetworkIsolationParams{From: []network.ID{f.staging, f.vendor}, To: []network.ID{f.production}}}
	reordered := valid
	reordered.Isolation.From = []network.ID{f.vendor, f.staging}
	first, err := valid.SemanticHash()
	if err != nil {
		t.Fatal(err)
	}
	second, err := reordered.SemanticHash()
	if err != nil || first != second {
		t.Fatalf("semantic hash depends on order: %x vs %x (%v)", first, second, err)
	}
	renamed := valid
	renamed.Name = "Another name"
	if third, _ := renamed.SemanticHash(); third != first {
		t.Fatal("semantic hash must not depend on the name")
	}
	document, err := valid.ParamsDocument()
	if err != nil {
		t.Fatal(err)
	}
	var parsed guardrail.Spec
	if err := guardrail.ParseParams(guardrail.KindNetworkIsolation, document, &parsed); err != nil ||
		len(parsed.Isolation.From) != 2 || parsed.Isolation.To[0] != f.production {
		t.Fatalf("ParseParams(%s) = %+v, %v", document, parsed.Isolation, err)
	}
	invalid := map[string]func(*guardrail.Spec){
		"blank name":       func(s *guardrail.Spec) { s.Name = "  " },
		"padded name":      func(s *guardrail.Spec) { s.Name = " Isolate" },
		"unknown mode":     func(s *guardrail.Spec) { s.Mode = "warn" },
		"no target":        func(s *guardrail.Spec) { s.Isolation.To = nil },
		"same both sides":  func(s *guardrail.Spec) { s.Isolation.To = []network.ID{f.vendor} },
		"duplicate source": func(s *guardrail.Spec) { s.Isolation.From = []network.ID{f.vendor, f.vendor} },
		"unknown kind":     func(s *guardrail.Spec) { s.Kind = "posture" },
	}
	for name, mutate := range invalid {
		spec := valid
		spec.Isolation.From = append([]network.ID(nil), valid.Isolation.From...)
		mutate(&spec)
		if spec.IsValid() {
			t.Errorf("%s: spec accepted", name)
		}
	}
}
