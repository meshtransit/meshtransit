//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
// when there is none, and two new Resource Groups holding only it.
func inactiveDeviceResources(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, owner accountsession.Session, scope network.Scope,
	device node.ID) (resource.ID, resource.GroupID, resource.GroupID) {
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
	var groups []resource.GroupID
	for index, name := range []string{"Inactive Device services", "Inactive Device services other"} {
		_, groupRevision := resourceAuthorityRevisions(ctx, t, admin, 103, 203)
		command, err := authority.NewCreateGroupCommand(
			resourceAuthorityGroupDefinition(t, scope, owner.PrincipalID(), name, []resource.Reference{member}),
			groupRevision, owner, resourceAuthorityReason(t, "Resource Group on a Device that leaves"),
			resourceAuthorityProof(t, byte(166+index)))
		if err != nil {
			t.Fatal(err)
		}
		created, err := service.Create(ctx, command)
		if err != nil {
			t.Fatalf("create Resource Group on the leaving Device: %v", err)
		}
		groups = append(groups, created.GroupID())
	}
	return id, groups[0], groups[1]
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

// refusedBy reports an MTP05 that the PL/pgSQL function raised itself: the
// first context line of a PostgreSQL error names the raising frame.
func refusedBy(err error, function string) bool {
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || postgresError.Code != "MTP05" {
		return false
	}
	frame, _, _ := strings.Cut(postgresError.Where, "\n")
	return strings.HasPrefix(frame, "PL/pgSQL function "+function+"(") && strings.HasSuffix(frame, " at RAISE")
}

// postgresWhere returns the context of a PostgreSQL error, for messages.
func postgresWhere(err error) string {
	if postgresError, ok := errors.AsType[*pgconn.PgError](err); ok {
		return postgresError.Where
	}
	return ""
}

// assertForgedDestinationHistoryRefused checks, in a transaction it rolls
// back, that the Resource and Resource Group attach functions compare the
// destination of a kept rule. One Device holds one Resource at a time, so a
// kept rule whose Resource changed on a revoked Device cannot be built
// through the services: the active release's row is rewritten to name
// another Resource instead. Resending the rule unchanged attaches; after the
// rewrite the attach function itself refuses it with MTP05.
func assertForgedDestinationHistoryRefused(ctx context.Context, t *testing.T, admin *pgx.Conn,
	resourceRule, groupRule policy.RuleID, source, device node.ID, resourceID resource.ID,
	groupID resource.GroupID) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationScope(ctx, t, transaction, 103, 203)
	setIntegrationChange(ctx, t, transaction, newCorrelationID(t).String())
	var resourceVersion, generation, inventory int64
	var resourceHash string
	if err := transaction.QueryRow(ctx, `SELECT version, target_generation, inventory_revision,
    pg_catalog.encode(semantic_hash, 'hex')
FROM mesh.resource WHERE workspace_id = 103 AND network_id = 203 AND public_id = $1::UUID`,
		resourceID.String()).Scan(&resourceVersion, &generation, &inventory, &resourceHash); err != nil {
		t.Fatal(err)
	}
	var groupVersion, definition, groupRevision int64
	var groupHash string
	if err := transaction.QueryRow(ctx, `SELECT version, active_definition_version, group_revision,
    pg_catalog.encode(semantic_hash, 'hex')
FROM mesh.resource_group WHERE workspace_id = 103 AND network_id = 203 AND public_id = $1::UUID`,
		groupID.String()).Scan(&groupVersion, &definition, &groupRevision, &groupHash); err != nil {
		t.Fatal(err)
	}
	member := map[string]any{
		"destination_resource_public_id":     resourceID.String(),
		"destination_resource_version":       resourceVersion,
		"destination_target_generation":      generation,
		"destination_inventory_revision":     inventory,
		"destination_resource_semantic_hash": resourceHash,
	}
	group := map[string]any{
		"destination_resource_group_public_id":            groupID.String(),
		"destination_resource_group_version":              groupVersion,
		"destination_group_definition_version":            definition,
		"destination_group_revision":                      groupRevision,
		"destination_resource_group_semantic_hash":        groupHash,
		"destination_group_member_resource_public_id":     resourceID.String(),
		"destination_group_member_resource_version":       resourceVersion,
		"destination_group_member_target_generation":      generation,
		"destination_group_member_inventory_revision":     inventory,
		"destination_group_member_resource_semantic_hash": resourceHash,
	}

	for _, destination := range []struct {
		name, table, function string
		rule                  policy.RuleID
		fields                map[string]any
	}{
		{"Resource", "mesh.compiled_policy_resource_destination", "attach_policy_resource_destinations",
			resourceRule, member},
		{"Resource Group member", "mesh.compiled_policy_resource_group_destination",
			"attach_policy_resource_group_destinations", groupRule, group},
	} {
		for _, forged := range []bool{false, true} {
			savepoint, err := transaction.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if forged {
				forgeActiveReleaseRow(ctx, t, savepoint, `UPDATE `+destination.table+` AS destination
SET destination_resource_id = (
    SELECT other.id FROM mesh.resource AS other
    WHERE other.workspace_id = 103 AND other.network_id = 203
      AND other.id <> destination.destination_resource_id
    ORDER BY other.id LIMIT 1)
FROM mesh.compiled_policy_rule AS rule
JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
WHERE rule.id = destination.compiled_policy_rule_id
  AND release.workspace_id = 103 AND release.network_id = 203 AND release.state = 'active'
  AND rule.access_rule_public_id = $1::UUID`, destination.rule.String())
			}
			err = resendKeptDestination(ctx, t, savepoint, destination.function, destination.rule, source, device,
				destination.fields)
			switch {
			case !forged && err != nil:
				t.Errorf("%s rule resent unchanged: %v", destination.name, err)
			case forged && !refusedBy(err, destination.function):
				t.Errorf("%s rule whose destination changed on a revoked Device: %v (context %q), want MTP05 from %s",
					destination.name, err, postgresWhere(err), destination.function)
			}
			if err := savepoint.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// forgeActiveReleaseRow runs one UPDATE of an immutable compiled row with
// triggers off and checks it changed exactly one row.
func forgeActiveReleaseRow(ctx context.Context, t *testing.T, transaction pgx.Tx, update string,
	arguments ...any) {
	t.Helper()
	if _, err := transaction.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	tag, err := transaction.Exec(ctx, update, arguments...)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("forge the active release: %d rows, %v", tag.RowsAffected(), err)
	}
	if _, err := transaction.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
}

// resendKeptDestination publishes rule again as an ICMP rule from source to
// device and attaches its destination fields, returning the attach error.
func resendKeptDestination(ctx context.Context, t *testing.T, transaction pgx.Tx, function string,
	rule policy.RuleID, source, device node.ID, fields map[string]any) error {
	t.Helper()
	projection, release := newCorrelationID(t).String(), newCorrelationID(t).String()
	local, err := json.Marshal([]map[string]any{{
		"projection_public_id": projection, "access_rule_public_id": rule.String(),
		"source_node_public_id": source.String(), "destination_node_public_id": device.String(),
		"protocol": "icmp", "port_range_first": []int{}, "port_range_last": []int{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	attached := map[string]any{
		"projection_public_id": projection, "access_rule_public_id": rule.String(),
		"destination_node_public_id": device.String(),
	}
	for key, value := range fields {
		attached[key] = value
	}
	payload, err := json.Marshal([]map[string]any{attached})
	if err != nil {
		t.Fatal(err)
	}
	var base int64
	if err := transaction.QueryRow(ctx, `SELECT policy_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&base); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(local)
	at := time.Now().UTC()
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.publish_compiled_policy_v2(
    $1::UUID, $2::BIGINT, $3::BYTEA, 3, $4::TIMESTAMPTZ, $5::JSONB)`, release, base, hash[:], at, local); err != nil {
		t.Fatalf("publish the kept rule: %v", err)
	}
	_, err = transaction.Exec(ctx, `SELECT * FROM mesh_ops.`+function+`($1::UUID, $2::TIMESTAMPTZ, $3::JSONB)`,
		release, at, payload)
	return err
}
