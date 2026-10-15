//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/resource"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

// inactiveDeviceRule builds one rule intent; a zero ID gets a fresh one and
// a zero protocol means ICMP.
func inactiveDeviceRule(t *testing.T, params compilation.RuleIntentParams) compilation.RuleIntent {
	t.Helper()
	if !params.ID.IsValid() {
		id, err := policy.ParseRuleID(newCorrelationID(t).String())
		if err != nil {
			t.Fatal(err)
		}
		params.ID = id
	}
	if params.Protocol == policy.ProtocolUnknown {
		params.Protocol = policy.ProtocolICMP
	}
	if params.DestinationPortRanges == nil {
		params.DestinationPortRanges = []policy.PortRange{}
	}
	intent, err := compilation.NewRuleIntent(params)
	if err != nil {
		t.Fatalf("rule intent: %v", err)
	}
	return intent
}

// tcpPorts returns one TCP port range.
func tcpPorts(t *testing.T, first, last uint16) []policy.PortRange {
	t.Helper()
	ports, err := policy.NewPortRange(first, last)
	if err != nil {
		t.Fatal(err)
	}
	return []policy.PortRange{ports}
}

// inactiveDeviceResources returns the active Resource on device, created
// when there is none, and a new Resource Group holding only it.
func inactiveDeviceResources(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, owner accountsession.Session, scope network.Scope,
	device node.ID) (resource.ID, resource.GroupID) {
	t.Helper()
	service := newIntegrationResourceAuthorityService(t, runtimePool)
	id, version, generation, found := activeDeviceResource(ctx, t, admin, device)
	if !found {
		inventory, _ := resourceAuthorityRevisions(ctx, t, admin, 103, 203)
		command, err := authority.NewCreateDeviceCommand(
			resourceAuthorityDeviceDefinition(t, scope, owner.PrincipalID(), device, "Inactive Device Resource"),
			inventory, owner, resourceAuthorityReason(t, "Resource on a Device that leaves"),
			resourceAuthorityProof(t, 165))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Create(ctx, command); err != nil {
			t.Fatalf("create Resource on the leaving Device: %v", err)
		}
		if id, version, generation, found = activeDeviceResource(ctx, t, admin, device); !found {
			t.Fatal("created Resource is not active on the leaving Device")
		}
	}
	member, err := resource.NewReference(scope, id, version, generation)
	if err != nil {
		t.Fatal(err)
	}
	_, groupRevision := resourceAuthorityRevisions(ctx, t, admin, 103, 203)
	command, err := authority.NewCreateGroupCommand(
		resourceAuthorityGroupDefinition(t, scope, owner.PrincipalID(), "Inactive Device services",
			[]resource.Reference{member}),
		groupRevision, owner, resourceAuthorityReason(t, "Resource Group on a Device that leaves"),
		resourceAuthorityProof(t, 166))
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(ctx, command)
	if err != nil {
		t.Fatalf("create Resource Group on the leaving Device: %v", err)
	}
	return id, created.GroupID()
}

func activeDeviceResource(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) (
	resource.ID, int64, int64, bool) {
	t.Helper()
	var text string
	var version, generation int64
	err := admin.QueryRow(ctx, `SELECT resource.public_id::TEXT, resource.version, resource.target_generation
FROM mesh.resource AS resource
JOIN mesh.resource_device_target AS target
  ON target.workspace_id = resource.workspace_id AND target.network_id = resource.network_id
 AND target.resource_id = resource.id AND target.target_generation = resource.target_generation
 AND target.state = 'active'
JOIN mesh.device AS device ON device.id = target.device_id
WHERE resource.workspace_id = 103 AND resource.network_id = 203 AND resource.state = 'active'
  AND device.public_id = $1::UUID`, device.String()).Scan(&text, &version, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return resource.ID{}, 0, 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.ParseID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id, version, generation, true
}

// assertActiveResourceDestinationCounts checks the Resource and Resource
// Group destinations the active release of Network 203 holds.
func assertActiveResourceDestinationCounts(ctx context.Context, t *testing.T, admin *pgx.Conn,
	resources, groups int) {
	t.Helper()
	var gotResources, gotGroups int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM mesh.compiled_policy_resource_destination AS destination
     JOIN mesh.compiled_policy_rule AS rule ON rule.id = destination.compiled_policy_rule_id
     WHERE rule.policy_release_id = release.id),
    (SELECT count(*) FROM mesh.compiled_policy_resource_group_destination AS destination
     JOIN mesh.compiled_policy_rule AS rule ON rule.id = destination.compiled_policy_rule_id
     WHERE rule.policy_release_id = release.id)
FROM mesh.policy_release AS release
WHERE release.workspace_id = 103 AND release.network_id = 203 AND release.state = 'active'`).Scan(
		&gotResources, &gotGroups); err != nil {
		t.Fatal(err)
	}
	if gotResources != resources || gotGroups != groups {
		t.Fatalf("active release holds %d Resource and %d Resource Group destinations, want %d and %d",
			gotResources, gotGroups, resources, groups)
	}
}
