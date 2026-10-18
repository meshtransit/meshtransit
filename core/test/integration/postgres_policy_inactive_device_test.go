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

// assertPostgreSQLPolicyInactiveDevice qualifies schemas 144 and 165: rules
// naming a suspended Device publish, rules naming a Device that is later
// revoked keep publishing while they stay unchanged, and a new or changed
// rule naming the revoked Device is refused with ErrDeviceUnavailable. This
// holds for Device rules, group rules with a fixed Device side, and rules to
// a Resource or Resource Group on that Device. It revokes one fixture Device
// and leaves a deny-all policy and no Device Group behind.
func assertPostgreSQLPolicyInactiveDevice(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool) {
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
	var deviceGroups []devicegroup.Group
	for _, name := range []string{"Inactive Device rules", "Inactive Device rules other"} {
		created, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: name}, newCorrelationID(t))
		if err != nil {
			t.Fatalf("create group: %v", err)
		}
		deviceGroups = append(deviceGroups, created.Group)
	}
	group, otherGroup := deviceGroups[0].ID, deviceGroups[1].ID
	resourceID, resourceGroupID, otherResourceGroupID := inactiveDeviceResources(ctx, t, admin, runtimePool, owner, scope, leaving)

	rule := func(params compilation.RuleIntentParams) compilation.RuleIntent {
		t.Helper()
		params.Scope = scope
		return inactiveDeviceRule(t, params)
	}
	publish := func(rules ...compilation.RuleIntent) {
		t.Helper()
		if rules == nil {
			rules = []compilation.RuleIntent{}
		}
		publishIntegrationRules(ctx, t, runtimePool, owner, scope, fixturePolicyRevision(ctx, t, admin), rules)
	}

	// Its Resource is shared: suspension keeps the share, revocation ends it.
	leavingShare := shareLeavingDevice(ctx, t, admin, runtimePool, owner, scope, resourceID)

	// Suspended: new and existing rules naming it publish and compile.
	suspendIntegrationDevice(ctx, t, admin, runtimePool, owner, scope, leaving, devicelifecycle.ActionSuspend)
	assertNoDeviceRemovalQueued(ctx, t, admin, leavingShare)
	deviceRule := rule(compilation.RuleIntentParams{SourceNodeID: leaving, DestinationNodeID: staying})
	groupRule := rule(compilation.RuleIntentParams{SourceNodeID: leaving, DestinationDeviceGroupID: group})
	resourceRule := rule(compilation.RuleIntentParams{SourceNodeID: staying, DestinationResourceID: resourceID})
	resourceGroupRule := rule(compilation.RuleIntentParams{
		SourceNodeID: staying, DestinationGroupID: resourceGroupID,
	})
	kept := []compilation.RuleIntent{deviceRule, groupRule, resourceRule, resourceGroupRule}
	publish(kept...)
	assertActiveCompiledRuleCounts(ctx, t, admin, 3, 1)
	assertActiveResourceDestinationCounts(ctx, t, admin, 1, 1)

	// Revoked while suspended, as the Console offers: the rules the active
	// release holds keep publishing next to an edit.
	revokeIntegrationFixtureDevice(ctx, t, admin, runtimePool, leaving)
	assertRevokedDeviceLeftSuspension(ctx, t, admin, leaving)
	// Schema 185: its Resource waits while the share is still open.
	assertResourceRetirementDeferred(ctx, t, admin, workerPool, resourceID, "shared")
	assertDeviceRemovalEndsShare(ctx, t, admin, workerPool, leavingShare)
	// Schema 185: its Resource is queued but kept while rules and groups use it.
	assertResourceRetirementDeferred(ctx, t, admin, workerPool, resourceID, "named by active rules")
	unrelated := rule(compilation.RuleIntentParams{SourceNodeID: staying, DestinationDeviceGroupID: group})
	kept = append(kept, unrelated)
	publish(kept...)
	assertActiveCompiledRuleCounts(ctx, t, admin, 3, 2)
	assertActiveResourceDestinationCounts(ctx, t, admin, 1, 1)

	// A new rule naming the revoked Device, or a kept one changed in any part,
	// is refused, whichever function sees it.
	for _, refused := range []struct {
		name string
		rule compilation.RuleIntent
	}{
		{"new Device rule", rule(compilation.RuleIntentParams{SourceNodeID: staying, DestinationNodeID: leaving})},
		{"new group rule", rule(compilation.RuleIntentParams{SourceNodeID: leaving, DestinationDeviceGroupID: group})},
		{"new Resource rule", rule(compilation.RuleIntentParams{
			SourceNodeID: staying, DestinationResourceID: resourceID,
		})},
		{"new Resource Group rule", rule(compilation.RuleIntentParams{
			SourceNodeID: staying, DestinationGroupID: resourceGroupID,
		})},
		{"Device rule with another protocol", rule(compilation.RuleIntentParams{
			ID: deviceRule.ID(), SourceNodeID: leaving, DestinationNodeID: staying,
			Protocol: policy.ProtocolTCP, DestinationPortRanges: tcpPorts(t, 22, 22),
		})},
		{"group rule with another group", rule(compilation.RuleIntentParams{
			ID: groupRule.ID(), SourceNodeID: leaving, DestinationDeviceGroupID: otherGroup,
		})},
		{"group rule with another protocol", rule(compilation.RuleIntentParams{
			ID: groupRule.ID(), SourceNodeID: leaving, DestinationDeviceGroupID: group,
			Protocol: policy.ProtocolUDP, DestinationPortRanges: tcpPorts(t, 53, 53),
		})},
		{"Resource rule with another port", rule(compilation.RuleIntentParams{
			ID: resourceRule.ID(), SourceNodeID: staying, DestinationResourceID: resourceID,
			Protocol: policy.ProtocolTCP, DestinationPortRanges: tcpPorts(t, 443, 443),
		})},
	} {
		rules := make([]compilation.RuleIntent, 0, len(kept)+1)
		for _, keptRule := range kept {
			if keptRule.ID() != refused.rule.ID() {
				rules = append(rules, keptRule)
			}
		}
		err := publishIntegrationRulesError(ctx, t, runtimePool, owner, scope,
			fixturePolicyRevision(ctx, t, admin), append(rules, refused.rule)...)
		if !errors.Is(err, publication.ErrDeviceUnavailable) {
			t.Fatalf("%s naming a revoked Device: %v, want ErrDeviceUnavailable", refused.name, err)
		}
	}
	assertActiveCompiledRuleCounts(ctx, t, admin, 3, 2)
	assertActiveResourceDestinationCounts(ctx, t, admin, 1, 1)

	// A kept Resource Group rule moved to another group on the same Device
	// compiles to the same Device rule, so only the Resource Group attach
	// function can refuse it.
	movedGroupRule := rule(compilation.RuleIntentParams{
		ID: resourceGroupRule.ID(), SourceNodeID: staying, DestinationGroupID: otherResourceGroupID,
	})
	movedRules := make([]compilation.RuleIntent, 0, len(kept))
	for _, keptRule := range kept {
		if keptRule.ID() != movedGroupRule.ID() {
			movedRules = append(movedRules, keptRule)
		}
	}
	if err := publishIntegrationRulesError(ctx, t, runtimePool, owner, scope, fixturePolicyRevision(ctx, t, admin),
		append(movedRules, movedGroupRule)...); !errors.Is(err, publication.ErrDeviceUnavailable) ||
		!refusedBy(err, "attach_policy_resource_group_destinations") {
		t.Errorf("Resource Group rule moved to another group: %v (context %q), want MTP05 from the Resource Group attach",
			err, postgresWhere(err))
	}
	assertForgedDestinationHistoryRefused(ctx, t, admin, resourceRule.ID(), resourceGroupRule.ID(),
		staying, leaving, resourceID, resourceGroupID)
	assertActiveCompiledRuleCounts(ctx, t, admin, 3, 2)
	assertActiveResourceDestinationCounts(ctx, t, admin, 1, 1)

	// Removing the stale rules and restoring deny-all also publish.
	publish(unrelated)
	assertActiveCompiledRuleCounts(ctx, t, admin, 0, 1)
	assertActiveResourceDestinationCounts(ctx, t, admin, 0, 0)
	publish()
	assertResourceRetirementDeferred(ctx, t, admin, workerPool, resourceID, "member of Resource Groups")
	deleteInactiveDeviceResourceGroups(ctx, t, admin, runtimePool, owner, scope, resourceGroupID, otherResourceGroupID)
	assertResourceRetired(ctx, t, admin, workerPool, resourceID)
	for _, deviceGroup := range deviceGroups {
		if _, err := groups.Delete(ctx, owner, scope, deviceGroup.ID, deviceGroup.Version,
			newCorrelationID(t)); err != nil {
			t.Fatalf("delete group: %v", err)
		}
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

// assertRevokedDeviceLeftSuspension checks a Device revoked while suspended
// keeps no suspension reason or handover, as the schema requires of a
// Device that is not suspended.
func assertRevokedDeviceLeftSuspension(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) {
	t.Helper()
	var reason, handover *string
	if err := admin.QueryRow(ctx, `SELECT suspended_reason, handover_principal_id::TEXT FROM mesh.device
WHERE public_id = $1::UUID`, device.String()).Scan(&reason, &handover); err != nil {
		t.Fatal(err)
	}
	if reason != nil || handover != nil {
		t.Fatalf("revoked Device keeps suspension %v and handover %v", reason, handover)
	}
}
