//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// A Workspace member of Network 203 only, seeded for the catalog checks.
const catalogMemberID = "01890f00-0000-7000-8000-000000009210"

func newIntegrationIdentityCatalog(t *testing.T, runtimePool *postgresadapter.Pool) (*identitygroup.Service,
	*devicetag.Service) {
	t.Helper()
	options := postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	groupStore, err := postgresadapter.NewIdentityGroupStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := identitygroup.NewService(groupStore, accountsession.SystemClock{}, identitygroup.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	tagStore, err := postgresadapter.NewDeviceTagStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	tags, err := devicetag.NewService(tagStore, accountsession.SystemClock{}, devicetag.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return groups, tags
}

func countCatalogAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, kind string, networkScoped bool) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = $1 AND (network_id IS NOT NULL) = $2`, kind, networkScoped).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countRevisionWakeups(ctx context.Context, t *testing.T, admin *pgx.Conn, key, value string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.outbox_event
WHERE event_class = 'network.revision.advanced' AND network_id = 203 AND payload->>$1 = $2`, key, value).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// secondFixtureScope is another active Network of Workspace 103.
func secondFixtureScope(ctx context.Context, t *testing.T, admin *pgx.Conn, first network.Scope) network.Scope {
	t.Helper()
	var text string
	if err := admin.QueryRow(ctx, `SELECT public_id::TEXT FROM mesh.network
WHERE workspace_id = 103 AND id <> 203 AND state = 'active' AND deleted_at IS NULL ORDER BY id LIMIT 1`).
		Scan(&text); err != nil {
		t.Fatalf("second fixture Network: %v", err)
	}
	id, err := network.ParseID(text)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(first.WorkspaceID(), id)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

// seedCatalogMember adds an active Workspace member who belongs to Network
// 203 and to no other Network.
func seedCatalogMember(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state)
OVERRIDING SYSTEM VALUE VALUES (9210, $1::UUID, 1, 'account', 'active')`, args: []any{catalogMemberID}},
		{sql: `INSERT INTO mesh.account (id, public_id, deployment_id, principal_id, display_name,
    session_generation, recovery_state) OVERRIDING SYSTEM VALUE
VALUES (9211, '01890f00-0000-7000-8000-000000009211', 1, 9210, 'Catalog Member', 1, 'verified')`},
		{sql: `INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id,
    principal_id, state, authority_generation, valid_from) OVERRIDING SYSTEM VALUE
VALUES (9212, '01890f00-0000-7000-8000-000000009212', 1, 103, 9210, 'active', 1, now() - INTERVAL '1 minute')`},
		{sql: `INSERT INTO mesh.network_membership (id, public_id, deployment_id, workspace_id, network_id,
    principal_id, workspace_membership_id, state, valid_from) OVERRIDING SYSTEM VALUE
VALUES (9213, '01890f00-0000-7000-8000-000000009213', 1, 103, 203, 9210, 9212, 'active',
    now() - INTERVAL '1 minute')`},
	})
}

// assertPostgreSQLIdentityCatalog qualifies schemas 121 and 228 through the
// production stores. User groups and tags belong to one Network:
// identity_group.* and device_tag.* are checked in that Network, so a
// Workspace-scope it_admin without a role there cannot manage them while a
// network_admin of the Network can, and only there; members must be active
// members of the group's Network; names are unique per Network; a tag's
// owner groups and the tags a Device carries come from its own Network; a
// tag owner may tag only Devices it owns unless it holds device.manage or
// device_tag.manage; a tag change rebuilds its Network with evidence and a
// wakeup on that Network's stream; deleting a tag rebuilds the Network that
// had it; a group that owns a tag cannot be deleted; removing a member from
// the Network removes them from its groups. It leaves nothing behind.
func assertPostgreSQLIdentityCatalog(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	groups, tags := newIntegrationIdentityCatalog(t, runtimePool)
	roleService := newIntegrationRoleService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	seedCatalogMember(ctx, t, admin)
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	other := secondFixtureScope(ctx, t, admin, scope)
	devices := activeFixtureDevices(ctx, t, admin, 1)
	var memberOwnsDevice bool
	if err := admin.QueryRow(ctx, `SELECT device.owner_principal_id = principal.id FROM mesh.device AS device,
mesh.principal AS principal WHERE device.public_id = $1::UUID AND principal.public_id = $2::UUID`,
		devices[0].String(), member.PrincipalID().String()).Scan(&memberOwnsDevice); err != nil || memberOwnsDevice {
		t.Fatalf("fixture Device must not belong to the member: owned=%t error=%v", memberOwnsDevice, err)
	}
	memberPrincipal := publicid.ID(member.PrincipalID())
	catalogMember := mustIntegrationPublicID(t, catalogMemberID)

	// Identity Groups.
	// Schema 184: read while a member change holds the Workspace.
	listing, err := runWhileWorkspaceChanging(ctx, t, admin, "list_identity_groups_v2", owner.ID().String(),
		func() (identitygroup.Listing, error) { return groups.List(ctx, owner, scope) })
	if err != nil || len(listing.Groups) != 0 || !listing.CanManage {
		t.Fatalf("owner groups = %+v, error = %v", listing, err)
	}
	if _, err := groups.List(ctx, member, scope); !errors.Is(err, identitygroup.ErrForbidden) {
		t.Fatalf("plain member listed groups: %v", err)
	}
	created, err := groups.Create(ctx, owner, scope,
		identitygroup.Definition{Name: "Engineering", Description: "Builds things"}, newCorrelationID(t))
	if err != nil || created.Group.Version != 1 {
		t.Fatalf("create group = %+v, error = %v", created, err)
	}
	group := created.Group.ID
	if _, err := groups.Create(ctx, owner, scope, identitygroup.Definition{Name: "engineering"},
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrNameTaken) {
		t.Fatalf("duplicate group name: %v", err)
	}
	// Names are unique per Network: the other Network may reuse it.
	elsewhere, err := groups.Create(ctx, owner, other, identitygroup.Definition{Name: "Engineering"},
		newCorrelationID(t))
	if err != nil {
		t.Fatalf("same name in another Network: %v", err)
	}
	if listed, err := groups.List(ctx, owner, other); err != nil || len(listed.Groups) != 1 ||
		listed.Groups[0].ID != elsewhere.Group.ID {
		t.Fatalf("other Network groups = %+v, error = %v", listed, err)
	}
	// A group is addressed only through its own Network.
	if _, err := groups.Members(ctx, owner, other, group, publicid.ID{}, 10); !errors.Is(err,
		identitygroup.ErrNotFound) {
		t.Fatalf("read a group through another Network: %v", err)
	}
	if _, err := groups.Update(ctx, owner, other, group, 1, identitygroup.Definition{Name: "Moved"},
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrNotFound) {
		t.Fatalf("renamed a group through another Network: %v", err)
	}

	// Members must be active members of the group's Network: a stranger and
	// a Workspace member outside Network 203 are refused.
	stranger := newCorrelationID(t)
	if _, err := groups.ChangeMembers(ctx, owner, scope, group, 1, []publicid.ID{stranger},
		nil, newCorrelationID(t)); !errors.Is(err, identitygroup.ErrIneligibleMember) {
		t.Fatalf("stranger joined a group: %v", err)
	}
	if _, err := groups.ChangeMembers(ctx, owner, scope, group, 1, []publicid.ID{memberPrincipal},
		nil, newCorrelationID(t)); !errors.Is(err, identitygroup.ErrIneligibleMember) {
		t.Fatalf("a Workspace member outside the Network joined a group: %v", err)
	}
	if _, err := groups.ChangeMembers(ctx, owner, other, elsewhere.Group.ID, 1, []publicid.ID{catalogMember},
		nil, newCorrelationID(t)); !errors.Is(err, identitygroup.ErrIneligibleMember) {
		t.Fatalf("a member of Network 203 joined a group of another Network: %v", err)
	}
	workspaceEvents := countCatalogAudit(ctx, t, admin, "identity_group", false)
	joined, err := groups.ChangeMembers(ctx, owner, scope, group, 1, []publicid.ID{catalogMember}, nil,
		newCorrelationID(t))
	if err != nil || joined.Added != 1 || joined.Group.MemberCount != 1 || len(joined.Networks) != 0 ||
		joined.AccessAffecting() {
		t.Fatalf("add member = %+v, error = %v", joined, err)
	}
	if countCatalogAudit(ctx, t, admin, "identity_group", false) != workspaceEvents+1 {
		t.Fatal("membership change must be one Workspace audit event")
	}
	if _, err := groups.ChangeMembers(ctx, owner, scope, group, 1, nil, []publicid.ID{catalogMember},
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrVersionConflict) {
		t.Fatalf("stale membership change: %v", err)
	}
	first, err := groups.Members(ctx, owner, scope, group, publicid.ID{}, 1)
	if err != nil || len(first.Members) != 1 || first.HasMore || !first.Members[0].Active {
		t.Fatalf("first member page = %+v, error = %v", first, err)
	}

	// A Workspace-scope it_admin without a role in the Network reads but
	// cannot manage its groups and tags; a network_admin of the Network
	// manages them there and nowhere else.
	itAdmin := newAssignCommand(t, owner, workspaceID, memberPrincipal, authorization.BuiltinRoleITAdmin, network.ID{})
	if _, err := roleService.Assign(ctx, itAdmin); err != nil {
		t.Fatalf("assign it_admin: %v", err)
	}
	if read, err := groups.List(ctx, member, scope); err != nil || read.CanManage {
		t.Fatalf("it_admin groups = %+v, error = %v", read, err)
	}
	if _, err := groups.Create(ctx, member, scope, identitygroup.Definition{Name: "Shadow"},
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrForbidden) {
		t.Fatalf("Workspace it_admin created a group: %v", err)
	}
	if _, err := tags.Create(ctx, member, scope, devicetag.Definition{Name: "shadow"},
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("Workspace it_admin created a tag: %v", err)
	}
	if _, err := roleService.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, itAdmin.AssignmentID, 1)); err != nil {
		t.Fatalf("revoke it_admin: %v", err)
	}
	networkAdmin := newAssignCommand(t, owner, workspaceID, memberPrincipal,
		authorization.BuiltinRoleNetworkAdmin, networkID)
	if _, err := roleService.Assign(ctx, networkAdmin); err != nil {
		t.Fatalf("assign network_admin: %v", err)
	}
	ownGroup, err := groups.Create(ctx, member, scope, identitygroup.Definition{Name: "Admins' own"},
		newCorrelationID(t))
	if err != nil {
		t.Fatalf("network_admin created a group in its Network: %v", err)
	}
	if _, err := groups.Create(ctx, member, other, identitygroup.Definition{Name: "Admins' own"},
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrForbidden) {
		t.Fatalf("network_admin created a group in another Network: %v", err)
	}
	if _, err := groups.Delete(ctx, member, scope, ownGroup.Group.ID, 1, newCorrelationID(t)); err != nil {
		t.Fatalf("network_admin deleted its group: %v", err)
	}

	// Tags.
	if _, err := tags.Create(ctx, owner, scope, devicetag.Definition{Name: "Prod"},
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrInvalid) {
		t.Fatalf("invalid tag name: %v", err)
	}
	tagCreated, err := tags.Create(ctx, owner, scope, devicetag.Definition{
		Name: "prod-db", Description: "Databases", OwnerGroups: []identitygroup.ID{group},
		OwnerRoles: []string{"auditor"},
	}, newCorrelationID(t))
	if err != nil || tagCreated.Tag.Version != 1 || len(tagCreated.Tag.OwnerGroups) != 1 {
		t.Fatalf("create tag = %+v, error = %v", tagCreated, err)
	}
	tag := tagCreated.Tag.ID
	// An owner group of another Network is refused.
	if _, err := tags.Create(ctx, owner, scope, devicetag.Definition{
		Name: "cross", OwnerGroups: []identitygroup.ID{elsewhere.Group.ID},
	}, newCorrelationID(t)); !errors.Is(err, devicetag.ErrUnknownOwner) {
		t.Fatalf("owner group from another Network: %v", err)
	}
	if _, err := tags.Create(ctx, owner, scope, devicetag.Definition{Name: "ci"},
		newCorrelationID(t)); err != nil {
		t.Fatalf("create ci: %v", err)
	}
	if listed, err := tags.List(ctx, owner, other); err != nil || len(listed.Tags) != 0 {
		t.Fatalf("another Network sees this Network's tags: %+v, error = %v", listed, err)
	}
	foreign, err := tags.Create(ctx, owner, other, devicetag.Definition{Name: "prod-db"}, newCorrelationID(t))
	if err != nil {
		t.Fatalf("same tag name in another Network: %v", err)
	}
	if _, err := tags.ChangeAssignments(ctx, owner, scope, devices[0], []devicetag.ID{foreign.Tag.ID}, nil,
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrNotFound) {
		t.Fatalf("applied another Network's tag: %v", err)
	}
	if _, err := tags.Delete(ctx, owner, other, foreign.Tag.ID, 1, newCorrelationID(t)); err != nil {
		t.Fatalf("delete foreign tag: %v", err)
	}
	if _, err := tags.Create(ctx, member, scope, devicetag.Definition{Name: "admins-tag"},
		newCorrelationID(t)); err != nil {
		t.Fatalf("network_admin created a tag in its Network: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, group, joined.Group.Version,
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrInUse) {
		t.Fatalf("deleted a group that owns a tag: %v", err)
	}
	if _, err := roleService.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, networkAdmin.AssignmentID, 1)); err != nil {
		t.Fatalf("revoke network_admin: %v", err)
	}
	cleanup, err := tags.List(ctx, owner, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, listed := range cleanup.Tags {
		if listed.ID == tag {
			continue
		}
		if _, err := tags.Delete(ctx, owner, scope, listed.ID, listed.Version, newCorrelationID(t)); err != nil {
			t.Fatalf("delete %s: %v", listed.Name, err)
		}
	}

	if _, err := tags.NetworkOptions(ctx, member, scope); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("plain member read tag options: %v", err)
	}
	// A plain member cannot read the Network's Devices, so it cannot tag.
	if _, err := tags.ChangeAssignments(ctx, member, scope, devices[0], []devicetag.ID{tag}, nil,
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("plain member tagged a Device: %v", err)
	}
	// As the Network's auditor it owns the tag through its role and reads the
	// Devices, yet the Device is not its own and it lacks device.manage.
	auditor := newAssignCommand(t, owner, workspaceID, memberPrincipal, authorization.BuiltinRoleAuditor, networkID)
	if _, err := roleService.Assign(ctx, auditor); err != nil {
		t.Fatalf("assign auditor: %v", err)
	}
	if _, err := tags.ChangeAssignments(ctx, member, scope, devices[0], []devicetag.ID{tag}, nil,
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("tag owner tagged a Device it does not own: %v", err)
	}
	if options, err := tags.NetworkOptions(ctx, member, scope); err != nil || len(options.Tags) != 1 ||
		options.Tags[0].ID != tag || options.Tags[0].Apply != devicetag.ApplyOwnDevices {
		t.Fatalf("tag owner options = %+v, error = %v", options, err)
	}
	if _, err := roleService.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, auditor.AssignmentID, 1)); err != nil {
		t.Fatalf("revoke auditor: %v", err)
	}

	networkBefore, groupBefore := fixtureNetworkRevisions(ctx, t, admin)
	wakeupsBefore := countRevisionWakeups(ctx, t, admin, "device_id", devices[0].String())
	tagged, err := tags.ChangeAssignments(ctx, owner, scope, devices[0], []devicetag.ID{tag}, nil, newCorrelationID(t))
	if err != nil || tagged.Added != 1 || len(tagged.Tags) != 1 || tagged.Tags[0] != tag {
		t.Fatalf("tag Device = %+v, error = %v", tagged, err)
	}
	networkAfter, groupAfter := fixtureNetworkRevisions(ctx, t, admin)
	if networkAfter != networkBefore+1 || groupAfter != groupBefore+1 || tagged.NetworkRevision != networkAfter {
		t.Fatalf("revisions %d/%d -> %d/%d", networkBefore, groupBefore, networkAfter, groupAfter)
	}
	if countRevisionWakeups(ctx, t, admin, "device_id", devices[0].String()) != wakeupsBefore+1 {
		t.Fatal("tagging must wake the Network's map sessions")
	}
	again, err := tags.ChangeAssignments(ctx, owner, scope, devices[0], []devicetag.ID{tag}, nil, newCorrelationID(t))
	if err != nil || again.Changed() {
		t.Fatalf("re-tagging = %+v, error = %v; want a no-op", again, err)
	}
	networkTags, err := tags.NetworkTags(ctx, owner, scope)
	if err != nil || len(networkTags) != 1 || networkTags[0].DeviceID != devices[0] {
		t.Fatalf("Network tags = %+v, error = %v", networkTags, err)
	}

	// Deleting the tag removes the assignment and rebuilds the Network.
	tagListing, err := tags.List(ctx, owner, scope)
	if err != nil || len(tagListing.Tags) != 1 || tagListing.Tags[0].DeviceCount != 1 || !tagListing.CanManage {
		t.Fatalf("tag listing = %+v, error = %v", tagListing, err)
	}
	deleted, err := tags.Delete(ctx, owner, scope, tag, 1, newCorrelationID(t))
	if err != nil || !deleted.Deleted || len(deleted.Networks) != 1 || deleted.Networks[0].NetworkID != networkID {
		t.Fatalf("delete tag = %+v, error = %v", deleted, err)
	}
	if countRevisionWakeups(ctx, t, admin, "aggregate_id", tag.String()) != 1 {
		t.Fatal("deleting a tag in use by Devices must wake the Network's map sessions")
	}
	if networkTags, err := tags.NetworkTags(ctx, owner, scope); err != nil || len(networkTags) != 0 {
		t.Fatalf("Network tags after delete = %+v, error = %v", networkTags, err)
	}

	// Removing the member from the Network removes them from its groups.
	removal := newNetworkMemberFixture(t, runtimePool)
	if _, err := removal.remove(ctx, t, owner, catalogMemberID); err != nil {
		t.Fatalf("remove the catalog member from the Network: %v", err)
	}
	after, err := groups.Members(ctx, owner, scope, group, publicid.ID{}, 10)
	if err != nil || after.Group.MemberCount != 0 || len(after.Members) != 0 ||
		after.Group.Version != joined.Group.Version+1 {
		t.Fatalf("group after Network removal = %+v, error = %v", after, err)
	}
	if _, err := groups.Delete(ctx, owner, scope, group, after.Group.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete group: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, other, elsewhere.Group.ID, 1, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the other Network's group: %v", err)
	}
}
