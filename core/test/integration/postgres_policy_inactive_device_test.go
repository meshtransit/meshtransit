//go:build integration

package integration

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// assertPostgreSQLPolicyInactiveDevice qualifies schema 144: rules naming a
// suspended Device publish, rules naming a Device that is later revoked keep
// publishing, and only a new rule naming the revoked Device is refused with
// ErrDeviceUnavailable, both for Device rules and for group rules with a
// fixed Device side. It revokes one fixture Device and leaves a deny-all
// policy and no group behind.
func assertPostgreSQLPolicyInactiveDevice(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	// The Device logout test after this one uses the first active Device.
	devices := activeFixtureDevices(ctx, t, admin, 2)
	staying, leaving := devices[0], devices[1]
	groups := newIntegrationDeviceGroupService(t, runtimePool)
	created, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Inactive Device rules"},
		newCorrelationID(t))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	group := created.Group.ID

	icmp := func(source, destination node.ID, destinationGroup devicegroup.ID) compilation.RuleIntent {
		t.Helper()
		ruleID, err := policy.ParseRuleID(newCorrelationID(t).String())
		if err != nil {
			t.Fatal(err)
		}
		intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
			ID: ruleID, Scope: scope, SourceNodeID: source, DestinationNodeID: destination,
			DestinationDeviceGroupID: destinationGroup, Protocol: policy.ProtocolICMP,
			DestinationPortRanges: []policy.PortRange{},
		})
		if err != nil {
			t.Fatalf("rule intent: %v", err)
		}
		return intent
	}
	publish := func(rules ...compilation.RuleIntent) {
		t.Helper()
		if rules == nil {
			rules = []compilation.RuleIntent{}
		}
		publishIntegrationRules(ctx, t, runtimePool, owner, scope, fixturePolicyRevision(ctx, t, admin), rules)
	}

	// Suspended: new and existing rules naming it publish and compile.
	suspendIntegrationDevice(ctx, t, admin, runtimePool, owner, scope, leaving, devicelifecycle.ActionSuspend)
	deviceRule := icmp(leaving, staying, devicegroup.ID{})
	groupRule := icmp(leaving, node.ID{}, group)
	publish(deviceRule, groupRule)
	assertActiveCompiledRuleCounts(ctx, t, admin, 1, 1)
	suspendIntegrationDevice(ctx, t, admin, runtimePool, owner, scope, leaving, devicelifecycle.ActionResume)

	// Revoked: the rules the active release holds keep publishing next to an edit.
	revokeIntegrationFixtureDevice(ctx, t, admin, runtimePool, leaving)
	unrelated := icmp(staying, node.ID{}, group)
	publish(deviceRule, groupRule, unrelated)
	assertActiveCompiledRuleCounts(ctx, t, admin, 1, 2)

	// A new rule naming the revoked Device is refused, whichever function sees it.
	for name, refused := range map[string]compilation.RuleIntent{
		"Device rule": icmp(staying, leaving, devicegroup.ID{}),
		"group rule":  icmp(leaving, node.ID{}, group),
	} {
		err := publishIntegrationRulesError(ctx, t, runtimePool, owner, scope,
			fixturePolicyRevision(ctx, t, admin), deviceRule, groupRule, unrelated, refused)
		if !errors.Is(err, publication.ErrDeviceUnavailable) {
			t.Fatalf("new %s naming a revoked Device: %v, want ErrDeviceUnavailable", name, err)
		}
	}
	assertActiveCompiledRuleCounts(ctx, t, admin, 1, 2)

	// Removing the stale rules and restoring deny-all also publish.
	publish(unrelated)
	assertActiveCompiledRuleCounts(ctx, t, admin, 0, 1)
	publish()
	if _, err := groups.Delete(ctx, owner, scope, group, created.Group.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete group: %v", err)
	}
}

// publishIntegrationRulesError publishes rules over base and returns the
// publication error instead of failing the test.
func publishIntegrationRulesError(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	owner accountsession.Session, scope network.Scope, base int64, rules ...compilation.RuleIntent) error {
	t.Helper()
	request, err := compilation.NewRequest(compilation.RequestParams{Scope: scope, Revision: base + 1, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := newIntegrationPolicyCompiler(t, runtimePool).Compile(ctx, owner, request)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	reason, err := publication.NewAuditReason("integration inactive Device rules")
	if err != nil {
		t.Fatal(err)
	}
	command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: candidate, BasePolicyRevision: base, AccountSession: owner, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newIntegrationManagementPolicyPublicationService(t, runtimePool).Publish(ctx, command)
	return err
}

func suspendIntegrationDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	owner accountsession.Session, scope network.Scope, device node.ID, action devicelifecycle.Action) {
	t.Helper()
	result, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
		Scope: scope, DeviceID: device, Action: action, Reason: "Inactive Device rules",
		ExpectedVersion: readIntegrationDevice(ctx, t, admin, device).version, CorrelationID: newCorrelationID(t),
	})
	if err != nil {
		t.Fatalf("%s Device: %v", action, err)
	}
	if want := map[devicelifecycle.Action]string{
		devicelifecycle.ActionSuspend: "suspended", devicelifecycle.ActionResume: "active",
	}[action]; result.After.State != want {
		t.Fatalf("%s Device state = %q, want %q", action, result.After.State, want)
	}
}

func revokeIntegrationFixtureDevice(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, device node.ID) {
	t.Helper()
	const prefix = "01890f31-0000-7000-8000-"
	text := device.String()
	number, err := strconv.Atoi(strings.TrimPrefix(text, prefix))
	if !strings.HasPrefix(text, prefix) || err != nil {
		t.Fatalf("Device %s is not a numbered fixture Device", text)
	}
	command := deviceRevocationIntegrationCommand(t, 203, number,
		readIntegrationDevice(ctx, t, admin, device).version, 0x44, "inactive Device rules")
	if _, err := newIntegrationDeviceRevocationService(t, runtimePool).Revoke(ctx, command); err != nil {
		t.Fatalf("revoke Device: %v", err)
	}
	if state := readIntegrationDevice(ctx, t, admin, device).state; state != "revoked" {
		t.Fatalf("revoked Device state = %q", state)
	}
}

func assertActiveCompiledRuleCounts(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceRules, groupRules int) {
	t.Helper()
	var devices, groups int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM mesh.compiled_policy_rule WHERE policy_release_id = release.id),
    (SELECT count(*) FROM mesh.compiled_policy_group_rule WHERE policy_release_id = release.id)
FROM mesh.policy_release AS release
WHERE release.workspace_id = 103 AND release.network_id = 203 AND release.state = 'active'`).Scan(
		&devices, &groups); err != nil {
		t.Fatal(err)
	}
	if devices != deviceRules || groups != groupRules {
		t.Fatalf("active release compiles %d Device and %d group rules, want %d and %d",
			devices, groups, deviceRules, groupRules)
	}
}
