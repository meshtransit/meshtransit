//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/devicetag"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identitygroup"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

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

// assertPostgreSQLIdentityCatalog qualifies schema 121 through the
// production stores: identity_group.* and device_tag.* gate the Workspace
// catalogs; members must be active Workspace members; names are unique; a
// tag owner may tag only Devices it owns unless it holds device.manage or
// device_tag.manage; a tag change rebuilds its Network with evidence and a
// wakeup on that Network's stream; deleting a tag rebuilds the Networks that
// had it; a group that owns a tag cannot be deleted. It leaves nothing behind.
func assertPostgreSQLIdentityCatalog(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	groups, tags := newIntegrationIdentityCatalog(t, runtimePool)
	roleService := newIntegrationRoleService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
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
	devices := activeFixtureDevices(ctx, t, admin, 1)
	var memberOwnsDevice bool
	if err := admin.QueryRow(ctx, `SELECT device.owner_principal_id = principal.id FROM mesh.device AS device,
mesh.principal AS principal WHERE device.public_id = $1::UUID AND principal.public_id = $2::UUID`,
		devices[0].String(), member.PrincipalID().String()).Scan(&memberOwnsDevice); err != nil || memberOwnsDevice {
		t.Fatalf("fixture Device must not belong to the member: owned=%t error=%v", memberOwnsDevice, err)
	}

	// Identity Groups.
	listing, err := groups.List(ctx, owner, workspaceID)
	if err != nil || len(listing.Groups) != 0 || !listing.CanManage {
		t.Fatalf("owner groups = %+v, error = %v", listing, err)
	}
	if _, err := groups.List(ctx, member, workspaceID); !errors.Is(err, identitygroup.ErrForbidden) {
		t.Fatalf("plain member listed groups: %v", err)
	}
	created, err := groups.Create(ctx, owner, workspaceID,
		identitygroup.Definition{Name: "Engineering", Description: "Builds things"}, newCorrelationID(t))
	if err != nil || created.Group.Version != 1 {
		t.Fatalf("create group = %+v, error = %v", created, err)
	}
	group := created.Group.ID
	if _, err := groups.Create(ctx, owner, workspaceID, identitygroup.Definition{Name: "engineering"},
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrNameTaken) {
		t.Fatalf("duplicate group name: %v", err)
	}
	stranger := newCorrelationID(t)
	memberPrincipal := publicid.ID(member.PrincipalID())
	ownerPrincipal := publicid.ID(owner.PrincipalID())
	if _, err := groups.ChangeMembers(ctx, owner, workspaceID, group, 1, []publicid.ID{memberPrincipal, stranger},
		nil, newCorrelationID(t)); !errors.Is(err, identitygroup.ErrIneligibleMember) {
		t.Fatalf("non-member joined a group: %v", err)
	}
	workspaceEvents := countCatalogAudit(ctx, t, admin, "identity_group", false)
	joined, err := groups.ChangeMembers(ctx, owner, workspaceID, group, 1,
		[]publicid.ID{memberPrincipal, ownerPrincipal}, nil, newCorrelationID(t))
	if err != nil || joined.Added != 2 || joined.Group.MemberCount != 2 || len(joined.Networks) != 0 ||
		joined.AccessAffecting() {
		t.Fatalf("add members = %+v, error = %v", joined, err)
	}
	if countCatalogAudit(ctx, t, admin, "identity_group", false) != workspaceEvents+1 {
		t.Fatal("membership change must be one Workspace audit event")
	}
	if _, err := groups.ChangeMembers(ctx, owner, workspaceID, group, 1, nil, []publicid.ID{memberPrincipal},
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrVersionConflict) {
		t.Fatalf("stale membership change: %v", err)
	}
	first, err := groups.Members(ctx, owner, workspaceID, group, publicid.ID{}, 1)
	if err != nil || len(first.Members) != 1 || !first.HasMore || !first.Members[0].Active {
		t.Fatalf("first member page = %+v, error = %v", first, err)
	}

	// Tags.
	if _, err := tags.Create(ctx, owner, workspaceID, devicetag.Definition{Name: "Prod"},
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrInvalid) {
		t.Fatalf("invalid tag name: %v", err)
	}
	tagCreated, err := tags.Create(ctx, owner, workspaceID, devicetag.Definition{
		Name: "prod-db", Description: "Databases", OwnerGroups: []identitygroup.ID{group},
		OwnerRoles: []string{"network_admin"},
	}, newCorrelationID(t))
	if err != nil || tagCreated.Tag.Version != 1 || len(tagCreated.Tag.OwnerGroups) != 1 {
		t.Fatalf("create tag = %+v, error = %v", tagCreated, err)
	}
	tag := tagCreated.Tag.ID
	if _, err := tags.Create(ctx, member, workspaceID, devicetag.Definition{Name: "ci"},
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("plain member created a tag: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, workspaceID, group, joined.Group.Version,
		newCorrelationID(t)); !errors.Is(err, identitygroup.ErrInUse) {
		t.Fatalf("deleted a group that owns a tag: %v", err)
	}

	if _, err := tags.NetworkOptions(ctx, member, scope); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("plain member read tag options: %v", err)
	}
	// A plain member cannot read the Network's Devices, so it cannot tag.
	if _, err := tags.ChangeAssignments(ctx, member, scope, devices[0], []devicetag.ID{tag}, nil,
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("plain member tagged a Device: %v", err)
	}
	// As network_admin it owns the tag twice over, yet the Device is not its own.
	networkAdmin := newAssignCommand(t, owner, workspaceID, memberPrincipal,
		authorization.BuiltinRoleNetworkAdmin, networkID)
	if _, err := roleService.Assign(ctx, networkAdmin); err != nil {
		t.Fatalf("assign network_admin: %v", err)
	}
	if _, err := tags.ChangeAssignments(ctx, member, scope, devices[0], []devicetag.ID{tag}, nil,
		newCorrelationID(t)); !errors.Is(err, devicetag.ErrForbidden) {
		t.Fatalf("tag owner tagged a Device it does not own: %v", err)
	}
	// Its options name the tag it owns, for its own Devices only, and hide
	// the catalog otherwise until a Device here carries a tag.
	hidden, err := tags.Create(ctx, owner, workspaceID, devicetag.Definition{Name: "audit-only"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	options, err := tags.NetworkOptions(ctx, member, scope)
	if err != nil || len(options.Tags) != 1 || options.Tags[0].ID != tag ||
		options.Tags[0].Apply != devicetag.ApplyOwnDevices || len(options.OwnedDevices) != 0 {
		t.Fatalf("tag owner options = %+v, error = %v", options, err)
	}
	if _, err := tags.ChangeAssignments(ctx, owner, scope, devices[0], []devicetag.ID{hidden.Tag.ID}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	options, err = tags.NetworkOptions(ctx, member, scope)
	if err != nil || len(options.Tags) != 2 || options.Tags[0].ID != hidden.Tag.ID ||
		options.Tags[0].Apply != devicetag.ApplyNone {
		t.Fatalf("options with a carried, unowned tag = %+v, error = %v", options, err)
	}
	ownerOptions, err := tags.NetworkOptions(ctx, owner, scope)
	if err != nil || len(ownerOptions.Tags) != 2 || ownerOptions.Tags[1].Apply != devicetag.ApplyAnyDevice {
		t.Fatalf("owner options = %+v, error = %v", ownerOptions, err)
	}
	if _, err := tags.ChangeAssignments(ctx, owner, scope, devices[0], nil, []devicetag.ID{hidden.Tag.ID},
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := tags.Delete(ctx, owner, workspaceID, hidden.Tag.ID, 1, newCorrelationID(t)); err != nil {
		t.Fatalf("delete audit-only: %v", err)
	}
	if _, err := roleService.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, networkAdmin.AssignmentID, 1)); err != nil {
		t.Fatalf("revoke network_admin: %v", err)
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
	tagListing, err := tags.List(ctx, owner, workspaceID)
	if err != nil || len(tagListing.Tags) != 1 || tagListing.Tags[0].DeviceCount != 1 || !tagListing.CanManage {
		t.Fatalf("tag listing = %+v, error = %v", tagListing, err)
	}
	deleted, err := tags.Delete(ctx, owner, workspaceID, tag, 1, newCorrelationID(t))
	if err != nil || !deleted.Deleted || len(deleted.Networks) != 1 || deleted.Networks[0].NetworkID != networkID {
		t.Fatalf("delete tag = %+v, error = %v", deleted, err)
	}
	if countRevisionWakeups(ctx, t, admin, "aggregate_id", tag.String()) != 1 {
		t.Fatal("deleting a tag in use by Devices must wake the Network's map sessions")
	}
	if networkTags, err := tags.NetworkTags(ctx, owner, scope); err != nil || len(networkTags) != 0 {
		t.Fatalf("Network tags after delete = %+v, error = %v", networkTags, err)
	}
	if _, err := groups.Delete(ctx, owner, workspaceID, group, joined.Group.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete group: %v", err)
	}
}
