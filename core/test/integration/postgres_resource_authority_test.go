//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/resource"
	authority "meshtransit.net/core/internal/domain/resource/authority"
	"meshtransit.net/core/internal/domain/resource/catalog"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/idempotency"
)

func assertPostgreSQLResourceAuthority(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	service := newIntegrationResourceAuthorityService(t, runtimePool)
	session := managementRBACAccountSessionFixture(t)
	scope203 := resourceAuthorityScope(t, 103, 203)
	actorID := session.PrincipalID()
	device930 := resourceAuthorityNodeID(t, 930)
	inventory203, group203 := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 203)

	deviceDefinition := resourceAuthorityDeviceDefinition(
		t, scope203, actorID, device930, "Production database 01",
	)
	reason := resourceAuthorityReason(t, "create first Device Resource")
	deviceCommand, err := authority.NewCreateDeviceCommand(
		deviceDefinition, inventory203, session, reason, resourceAuthorityProof(t, 1),
	)
	if err != nil {
		t.Fatalf("construct Device Resource command: %v", err)
	}
	deviceResult, err := service.Create(ctx, deviceCommand)
	if err != nil {
		t.Fatalf("create Device Resource: %v", err)
	}
	if deviceResult.Operation() != authority.OperationCreateDevice ||
		deviceResult.SubsystemRevision() != inventory203+1 || deviceResult.Version() != 1 {
		t.Fatalf("Device Resource result = %+v", deviceResult)
	}
	replayedDeviceResult, err := service.Create(ctx, deviceCommand)
	if err != nil || replayedDeviceResult != deviceResult {
		t.Fatalf("replay Device Resource result = %+v, error = %v", replayedDeviceResult, err)
	}
	assertCommittedDeviceResource(ctx, t, adminConnection, deviceCommand, deviceResult)

	staleDefinition := resourceAuthorityDeviceDefinition(
		t, scope203, actorID, resourceAuthorityNodeID(t, 910), "Stale Resource",
	)
	staleCommand, err := authority.NewCreateDeviceCommand(
		staleDefinition, inventory203, session, reason, resourceAuthorityProof(t, 2),
	)
	if err != nil {
		t.Fatalf("construct stale Resource command: %v", err)
	}
	if _, err := service.Create(ctx, staleCommand); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("stale Resource creation error = %v, want ErrConflict", err)
	}

	reference, err := resource.NewReference(scope203, deviceResult.ResourceID(), 1, 1)
	if err != nil {
		t.Fatalf("construct Resource reference: %v", err)
	}
	groupDefinition := resourceAuthorityGroupDefinition(
		t, scope203, actorID, "Production databases", []resource.Reference{reference},
	)
	groupCommand, err := authority.NewCreateGroupCommand(
		groupDefinition, group203, session,
		resourceAuthorityReason(t, "create first destination Resource Group"),
		resourceAuthorityProof(t, 3),
	)
	if err != nil {
		t.Fatalf("construct Resource Group command: %v", err)
	}
	groupResult, err := service.Create(ctx, groupCommand)
	if err != nil {
		t.Fatalf("create Resource Group: %v", err)
	}
	if groupResult.Operation() != authority.OperationCreateGroup ||
		groupResult.SubsystemRevision() != group203+1 || groupResult.Version() != 1 {
		t.Fatalf("Resource Group result = %+v", groupResult)
	}
	assertCommittedResourceGroup(ctx, t, adminConnection, groupCommand, groupResult)

	staleReference, err := resource.NewReference(scope203, deviceResult.ResourceID(), 1, 2)
	if err != nil {
		t.Fatalf("construct stale target-generation reference: %v", err)
	}
	staleGroup := resourceAuthorityGroupDefinition(
		t, scope203, actorID, "Stale generation", []resource.Reference{staleReference},
	)
	staleGroupCommand, err := authority.NewCreateGroupCommand(
		staleGroup, group203+1, session, resourceAuthorityReason(t, "reject stale generation"),
		resourceAuthorityProof(t, 4),
	)
	if err != nil {
		t.Fatalf("construct stale Resource Group command: %v", err)
	}
	if _, err := service.Create(ctx, staleGroupCommand); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("stale target generation error = %v, want ErrConflict", err)
	}

	scope204 := resourceAuthorityScope(t, 103, 204)
	assertResourceCatalogReads(
		ctx, t, runtimePool, session, scope203, scope204,
		deviceResult.ResourceID(), groupResult.GroupID(),
	)
	_, group204 := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 204)
	crossScopeReference, err := resource.NewReference(
		scope204, deviceResult.ResourceID(), 1, 1,
	)
	if err != nil {
		t.Fatalf("construct opaque cross-scope reference: %v", err)
	}
	crossScopeGroup := resourceAuthorityGroupDefinition(
		t, scope204, actorID, "Cross scope", []resource.Reference{crossScopeReference},
	)
	crossScopeCommand, err := authority.NewCreateGroupCommand(
		crossScopeGroup, group204, session, resourceAuthorityReason(t, "reject cross-scope member"),
		resourceAuthorityProof(t, 5),
	)
	if err != nil {
		t.Fatalf("construct cross-scope group command: %v", err)
	}
	if _, err := service.Create(ctx, crossScopeCommand); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("cross-scope Resource Group error = %v, want ErrConflict", err)
	}

	scope202 := resourceAuthorityScope(t, 102, 202)
	inventory202, _ := resourceAuthorityRevisions(ctx, t, adminConnection, 102, 202)
	unauthorizedDefinition := resourceAuthorityDeviceDefinition(
		t, scope202, actorID, device930, "Unauthorized Resource",
	)
	unauthorizedCommand, err := authority.NewCreateDeviceCommand(
		unauthorizedDefinition, inventory202, session,
		resourceAuthorityReason(t, "reject missing Resource management permission"),
		resourceAuthorityProof(t, 6),
	)
	if err != nil {
		t.Fatalf("construct unauthorized Resource command: %v", err)
	}
	if _, err := service.Create(ctx, unauthorizedCommand); !errors.Is(err, authority.ErrForbidden) {
		t.Fatalf("unauthorized Resource error = %v, want ErrForbidden", err)
	}

	rebound := assertResourceTargetRebinding(
		ctx, t, adminConnection, runtimePool, service, session, scope203, scope204,
	)
	assertResourceAuthorityChange(
		ctx, t, adminConnection, runtimePool, session, scope203, rebound,
	)

	assertResourceLifecycles(
		ctx, t, adminConnection, runtimeConnection, runtimePool, session, scope203, scope204,
		deviceResult, groupResult,
	)

	assertResourceAuthorityEvidenceAtomicity(ctx, t, adminConnection, runtimeConnection)
	assertResourceAuthorityPrivilegeContract(ctx, t, adminConnection, runtimeConnection, workerConnection)
}

func assertResourceAuthorityChange(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	requester accountsession.Session,
	scope network.Scope,
	rebound authority.RebindResult,
) {
	t.Helper()
	confirmer := authorityConfirmerAccountSessionFixture(t)
	service := newIntegrationResourceAuthorityChangeService(t, runtimePool)
	nonOwnerPreview, err := authority.NewResourceAuthorityChangePreview(
		scope, rebound.ResourceID(), rebound.Version(),
		authority.AuthorityChangeTransferOwner, requester.PrincipalID(), confirmer,
	)
	if err != nil {
		t.Fatalf("construct non-owner authority-change preview: %v", err)
	}
	if _, err := service.Preview(ctx, nonOwnerPreview); !errors.Is(err, authority.ErrForbidden) {
		t.Fatalf("non-owner authority-change preview error = %v, want forbidden", err)
	}
	preview, err := authority.NewResourceAuthorityChangePreview(
		scope, rebound.ResourceID(), rebound.Version(),
		authority.AuthorityChangeTransferOwner, confirmer.PrincipalID(), requester,
	)
	if err != nil {
		t.Fatalf("construct ownership-transfer preview: %v", err)
	}
	impact, err := service.Preview(ctx, preview)
	if err != nil {
		t.Fatalf("preview ownership transfer: %v", err)
	}
	if impact.CurrentOwnerPrincipalID() != requester.PrincipalID() ||
		impact.ProposedOwnerPrincipalID() != confirmer.PrincipalID() ||
		impact.ProposedCustodianPrincipalID() != requester.PrincipalID() ||
		impact.RequiredConfirmations() != 1 ||
		impact.MaximumStepUpAge() != authority.MaximumAuthorityChangeStepUpAge {
		t.Fatalf("ownership-transfer impact = %+v", impact)
	}
	requestCommand, err := authority.NewAuthorityChangeRequestCommand(
		preview, impact.Hash(), resourceAuthorityReason(t, "propose protected owner transfer"),
		resourceAuthorityProof(t, 21),
	)
	if err != nil {
		t.Fatalf("construct ownership-transfer request: %v", err)
	}
	requested, err := service.Request(ctx, requestCommand)
	if err != nil {
		t.Fatalf("request ownership transfer: %v", err)
	}
	if requested.RequestVersion() != 1 || requested.ImpactHash() != impact.Hash() ||
		!requested.ExpiresAt().After(time.Now().UTC()) {
		t.Fatalf("ownership-transfer request result = %+v", requested)
	}
	replayedRequest, err := service.Request(ctx, requestCommand)
	if err != nil || !replayedRequest.Equal(requested) {
		t.Fatalf("replayed ownership-transfer request = %+v, error=%v", replayedRequest, err)
	}
	wrongActorCommand, err := authority.NewResourceAuthorityChangeConfirmation(
		scope, rebound.ResourceID(), requested.RequestID(), requested.RequestVersion(),
		impact.Hash(), requester,
		resourceAuthorityReason(t, "reject requester self-confirmation"),
		resourceAuthorityProof(t, 22),
	)
	if err != nil {
		t.Fatalf("construct requester self-confirmation: %v", err)
	}
	if _, err := service.Confirm(ctx, wrongActorCommand); !errors.Is(err, authority.ErrForbidden) {
		t.Fatalf("requester self-confirmation error = %v, want ErrForbidden", err)
	}
	confirmationCommand, err := authority.NewResourceAuthorityChangeConfirmation(
		scope, rebound.ResourceID(), requested.RequestID(), requested.RequestVersion(),
		impact.Hash(), confirmer,
		resourceAuthorityReason(t, "accept protected owner transfer"),
		resourceAuthorityProof(t, 23),
	)
	if err != nil {
		t.Fatalf("construct ownership-transfer confirmation: %v", err)
	}
	confirmed, err := service.Confirm(ctx, confirmationCommand)
	if err != nil {
		t.Fatalf("confirm ownership transfer: %v", err)
	}
	if confirmed.SubjectVersion() != rebound.Version()+1 || confirmed.RequestVersion() != 2 ||
		confirmed.OwnerPrincipalID() != confirmer.PrincipalID() ||
		confirmed.CustodianPrincipalID() != requester.PrincipalID() ||
		confirmed.SemanticHash() != impact.ProposedSemanticHash() {
		t.Fatalf("ownership-transfer confirmation = %+v", confirmed)
	}
	replayedConfirmation, err := service.Confirm(ctx, confirmationCommand)
	if err != nil || !replayedConfirmation.Equal(confirmed) {
		t.Fatalf(
			"replayed ownership-transfer confirmation = %+v, error=%v",
			replayedConfirmation, err,
		)
	}
	stalePreview, err := authority.NewResourceAuthorityChangePreview(
		scope, rebound.ResourceID(), rebound.Version(),
		authority.AuthorityChangeDelegateCustodian, confirmer.PrincipalID(), requester,
	)
	if err != nil {
		t.Fatalf("construct stale authority-change preview: %v", err)
	}
	if _, err := service.Preview(ctx, stalePreview); !errors.Is(
		err, authority.ErrAuthorityChangeVersionConflict,
	) {
		t.Fatalf("stale authority-change preview error = %v, want version conflict", err)
	}
	assertCommittedResourceAuthorityChange(
		ctx, t, adminConnection, requested, confirmed, requester, confirmer,
	)
}

func assertResourceTargetRebinding(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	creationService *authority.Service,
	session accountsession.Session,
	homeScope network.Scope,
	otherScope network.Scope,
) authority.RebindResult {
	t.Helper()
	inventoryRevision, groupRevision := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 203)
	definition := resourceAuthorityDeviceDefinition(
		t, homeScope, session.PrincipalID(), resourceAuthorityNodeID(t, 910),
		"Rebind qualification Resource",
	)
	createCommand, err := authority.NewCreateDeviceCommand(
		definition, inventoryRevision, session,
		resourceAuthorityReason(t, "create target-rebinding fixture"),
		resourceAuthorityProof(t, 16),
	)
	if err != nil {
		t.Fatalf("construct target-rebinding fixture: %v", err)
	}
	created, err := creationService.Create(ctx, createCommand)
	if err != nil {
		t.Fatalf("create target-rebinding fixture: %v", err)
	}
	reference, err := resource.NewReference(homeScope, created.ResourceID(), 1, 1)
	if err != nil {
		t.Fatalf("construct target-rebinding group reference: %v", err)
	}
	groupDefinition := resourceAuthorityGroupDefinition(
		t, homeScope, session.PrincipalID(), "Rebind affected group", []resource.Reference{reference},
	)
	groupCommand, err := authority.NewCreateGroupCommand(
		groupDefinition, groupRevision, session,
		resourceAuthorityReason(t, "create target-rebinding impact fixture"),
		resourceAuthorityProof(t, 17),
	)
	if err != nil {
		t.Fatalf("construct target-rebinding group: %v", err)
	}
	groupResult, err := creationService.Create(ctx, groupCommand)
	if err != nil {
		t.Fatalf("create target-rebinding group: %v", err)
	}

	service := newIntegrationResourceRebindService(t, runtimePool)
	replacementDeviceID := resourceAuthorityNodeID(t, 970)
	preview, err := authority.NewRebindPreview(
		homeScope, created.ResourceID(), 1, replacementDeviceID, session,
	)
	if err != nil {
		t.Fatalf("construct Resource rebind preview: %v", err)
	}
	impact, err := service.Preview(ctx, preview)
	if err != nil {
		t.Fatalf("preview Resource rebind: %v", err)
	}
	affectedGroups := impact.AffectedGroupIDs()
	if impact.CurrentDeviceID() != resourceAuthorityNodeID(t, 910) ||
		impact.ProposedRevision().DeviceID() != replacementDeviceID ||
		impact.ProposedRevision().TargetGeneration() != 2 || impact.ApprovalRequired() ||
		len(affectedGroups) != 1 || affectedGroups[0] != groupResult.GroupID() {
		t.Fatalf("Resource rebind impact = %+v groups=%+v", impact, affectedGroups)
	}
	command, err := authority.NewRebindCommand(
		preview, impact.Hash(), resourceAuthorityReason(t, "replace failed Device target"),
		resourceAuthorityProof(t, 18),
	)
	if err != nil {
		t.Fatalf("construct Resource rebind command: %v", err)
	}
	result, err := service.Rebind(ctx, command)
	if err != nil {
		t.Fatalf("apply Resource rebind: %v", err)
	}
	if result.DeviceID() != replacementDeviceID || result.TargetGeneration() != 2 ||
		result.Version() != 2 || result.ImpactHash() != impact.Hash() {
		t.Fatalf("Resource rebind result = %+v", result)
	}
	replayed, err := service.Rebind(ctx, command)
	if err != nil || replayed != result {
		t.Fatalf("replayed Resource rebind = %+v, error=%v", replayed, err)
	}

	stalePreview, err := authority.NewRebindPreview(
		homeScope, created.ResourceID(), 1, resourceAuthorityNodeID(t, 910), session,
	)
	if err != nil {
		t.Fatalf("construct stale Resource rebind preview: %v", err)
	}
	if _, err := service.Preview(ctx, stalePreview); !errors.Is(err, authority.ErrRebindVersionConflict) {
		t.Fatalf("stale Resource rebind preview error = %v, want ErrRebindVersionConflict", err)
	}
	crossScopePreview, err := authority.NewRebindPreview(
		otherScope, created.ResourceID(), 2, resourceAuthorityNodeID(t, 910), session,
	)
	if err != nil {
		t.Fatalf("construct cross-scope Resource rebind preview: %v", err)
	}
	if _, err := service.Preview(ctx, crossScopePreview); !errors.Is(err, authority.ErrRebindNotFound) {
		t.Fatalf("cross-scope Resource rebind preview error = %v, want ErrRebindNotFound", err)
	}
	assertCommittedResourceRebind(ctx, t, adminConnection, result, groupResult.GroupID())
	assertResourceGroupReplacement(
		ctx, t, adminConnection, runtimePool, session, homeScope, otherScope,
		groupResult.GroupID(), result,
	)
	return result
}

func assertResourceGroupReplacement(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	homeScope network.Scope,
	otherScope network.Scope,
	groupID resource.GroupID,
	rebound authority.RebindResult,
) {
	t.Helper()
	reference, err := resource.NewReference(
		homeScope, rebound.ResourceID(), rebound.Version(), rebound.TargetGeneration(),
	)
	if err != nil {
		t.Fatalf("construct replacement Resource Group reference: %v", err)
	}
	service := newIntegrationResourceGroupReplaceService(t, runtimePool)
	preview, err := authority.NewGroupReplacePreview(
		homeScope, groupID, 1, []resource.Reference{reference}, session,
	)
	if err != nil {
		t.Fatalf("construct Resource Group replacement preview: %v", err)
	}
	impact, err := service.Preview(ctx, preview)
	if err != nil {
		t.Fatalf("preview Resource Group replacement: %v", err)
	}
	if impact.CurrentRevision().DefinitionVersion() != 1 ||
		impact.ProposedRevision().DefinitionVersion() != 2 ||
		len(impact.AddedMembers()) != 1 || len(impact.RemovedMembers()) != 1 ||
		len(impact.RetainedMembers()) != 0 || impact.ApprovalRequired() {
		t.Fatalf("Resource Group replacement impact = %+v", impact)
	}
	command, err := authority.NewGroupReplaceCommand(
		preview, impact.Hash(), resourceAuthorityReason(t, "re-pin immutable group definition"),
		resourceAuthorityProof(t, 19),
	)
	if err != nil {
		t.Fatalf("construct Resource Group replacement command: %v", err)
	}
	result, err := service.Replace(ctx, command)
	if err != nil {
		t.Fatalf("replace Resource Group definition: %v", err)
	}
	if result.GroupID() != groupID || result.DefinitionVersion() != 2 ||
		result.Version() != 2 || result.ImpactHash() != impact.Hash() ||
		result.SemanticHash() != impact.ProposedRevision().SemanticHash() {
		t.Fatalf("Resource Group replacement result = %+v", result)
	}
	replayed, err := service.Replace(ctx, command)
	if err != nil || replayed != result {
		t.Fatalf("replayed Resource Group replacement = %+v, error=%v", replayed, err)
	}
	stalePreview, err := authority.NewGroupReplacePreview(
		homeScope, groupID, 1, []resource.Reference{reference}, session,
	)
	if err != nil {
		t.Fatalf("construct stale Resource Group replacement preview: %v", err)
	}
	if _, err := service.Preview(ctx, stalePreview); !errors.Is(
		err, authority.ErrGroupReplaceVersionConflict,
	) {
		t.Fatalf("stale Resource Group replacement error = %v, want version conflict", err)
	}
	crossScopePreview, err := authority.NewGroupReplacePreview(
		otherScope, groupID, 2,
		[]resource.Reference{resourceAuthorityReference(
			t, otherScope, rebound.ResourceID(), rebound.Version(), rebound.TargetGeneration(),
		)},
		session,
	)
	if err != nil {
		t.Fatalf("construct cross-scope Resource Group replacement preview: %v", err)
	}
	if _, err := service.Preview(ctx, crossScopePreview); !errors.Is(
		err, authority.ErrGroupReplaceNotFound,
	) {
		t.Fatalf("cross-scope Resource Group replacement error = %v, want not found", err)
	}
	assertCommittedResourceGroupReplacement(ctx, t, adminConnection, result, rebound)
}

func assertResourceLifecycles(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	homeScope network.Scope,
	otherScope network.Scope,
	deviceResult authority.Result,
	groupResult authority.Result,
) {
	t.Helper()
	assertResourceLifecycleEvidenceAtomicity(
		ctx, t, adminConnection, runtimeConnection, deviceResult.ResourceID(),
		session.PrincipalID(),
	)
	service := newIntegrationResourceLifecycleService(t, runtimePool)
	reason := resourceAuthorityReason(t, "qualification lifecycle transition")
	suspendResource, err := authority.NewResourceLifecycleCommand(
		authority.LifecycleSuspendResource, homeScope, deviceResult.ResourceID(), 1,
		session, reason, resourceAuthorityProof(t, 7),
	)
	if err != nil {
		t.Fatalf("construct Resource suspension: %v", err)
	}
	suspendedResource, err := service.Transition(ctx, suspendResource)
	if err != nil {
		t.Fatalf("suspend Resource: %v", err)
	}
	if suspendedResource.State() != resource.StateSuspended || suspendedResource.Version() != 2 {
		t.Fatalf("suspended Resource result = %+v", suspendedResource)
	}
	replayedResource, err := service.Transition(ctx, suspendResource)
	if err != nil || replayedResource != suspendedResource {
		t.Fatalf("replayed Resource suspension = %+v, error = %v", replayedResource, err)
	}

	staleResource, err := authority.NewResourceLifecycleCommand(
		authority.LifecycleDeleteResource, homeScope, deviceResult.ResourceID(), 1,
		session, reason, resourceAuthorityProof(t, 8),
	)
	if err != nil {
		t.Fatalf("construct stale Resource lifecycle: %v", err)
	}
	if _, err := service.Transition(ctx, staleResource); !errors.Is(
		err, authority.ErrLifecycleVersionConflict,
	) {
		t.Fatalf("stale Resource lifecycle error = %v, want ErrLifecycleVersionConflict", err)
	}

	resumeResource, err := authority.NewResourceLifecycleCommand(
		authority.LifecycleResumeResource, homeScope, deviceResult.ResourceID(), 2,
		session, reason, resourceAuthorityProof(t, 9),
	)
	if err != nil {
		t.Fatalf("construct Resource resume: %v", err)
	}
	resumedResource, err := service.Transition(ctx, resumeResource)
	if err != nil || resumedResource.State() != resource.StateActive || resumedResource.Version() != 3 {
		t.Fatalf("resumed Resource result = %+v, error = %v", resumedResource, err)
	}

	deleteResource, err := authority.NewResourceLifecycleCommand(
		authority.LifecycleDeleteResource, homeScope, deviceResult.ResourceID(), 3,
		session, reason, resourceAuthorityProof(t, 10),
	)
	if err != nil {
		t.Fatalf("construct Resource deletion: %v", err)
	}
	deletedResource, err := service.Transition(ctx, deleteResource)
	if err != nil || deletedResource.State() != resource.StateDeleted || deletedResource.Version() != 4 {
		t.Fatalf("deleted Resource result = %+v, error = %v", deletedResource, err)
	}

	resurrectResource, err := authority.NewResourceLifecycleCommand(
		authority.LifecycleResumeResource, homeScope, deviceResult.ResourceID(), 4,
		session, reason, resourceAuthorityProof(t, 11),
	)
	if err != nil {
		t.Fatalf("construct terminal Resource transition: %v", err)
	}
	if _, err := service.Transition(ctx, resurrectResource); !errors.Is(
		err, authority.ErrInvalidLifecycleTransition,
	) {
		t.Fatalf("terminal Resource lifecycle error = %v, want ErrInvalidLifecycleTransition", err)
	}

	crossScopeResource, err := authority.NewResourceLifecycleCommand(
		authority.LifecycleSuspendResource, otherScope, deviceResult.ResourceID(), 4,
		session, reason, resourceAuthorityProof(t, 12),
	)
	if err != nil {
		t.Fatalf("construct cross-scope Resource lifecycle: %v", err)
	}
	if _, err := service.Transition(ctx, crossScopeResource); !errors.Is(
		err, authority.ErrLifecycleNotFound,
	) {
		t.Fatalf("cross-scope Resource lifecycle error = %v, want ErrLifecycleNotFound", err)
	}

	suspendGroup, err := authority.NewGroupLifecycleCommand(
		authority.LifecycleSuspendGroup, homeScope, groupResult.GroupID(), 1,
		session, reason, resourceAuthorityProof(t, 13),
	)
	if err != nil {
		t.Fatalf("construct Resource Group suspension: %v", err)
	}
	suspendedGroup, err := service.Transition(ctx, suspendGroup)
	if err != nil || suspendedGroup.State() != resource.StateSuspended || suspendedGroup.Version() != 2 {
		t.Fatalf("suspended Resource Group result = %+v, error = %v", suspendedGroup, err)
	}
	resumeGroup, err := authority.NewGroupLifecycleCommand(
		authority.LifecycleResumeGroup, homeScope, groupResult.GroupID(), 2,
		session, reason, resourceAuthorityProof(t, 14),
	)
	if err != nil {
		t.Fatalf("construct Resource Group resume: %v", err)
	}
	resumedGroup, err := service.Transition(ctx, resumeGroup)
	if err != nil || resumedGroup.State() != resource.StateActive || resumedGroup.Version() != 3 {
		t.Fatalf("resumed Resource Group result = %+v, error = %v", resumedGroup, err)
	}
	deleteGroup, err := authority.NewGroupLifecycleCommand(
		authority.LifecycleDeleteGroup, homeScope, groupResult.GroupID(), 3,
		session, reason, resourceAuthorityProof(t, 15),
	)
	if err != nil {
		t.Fatalf("construct Resource Group deletion: %v", err)
	}
	deletedGroup, err := service.Transition(ctx, deleteGroup)
	if err != nil || deletedGroup.State() != resource.StateDeleted || deletedGroup.Version() != 4 {
		t.Fatalf("deleted Resource Group result = %+v, error = %v", deletedGroup, err)
	}

	assertCommittedResourceLifecycle(ctx, t, adminConnection, deletedResource, 3)
	assertCommittedGroupLifecycle(ctx, t, adminConnection, deletedGroup, 3)
}

func assertResourceLifecycleEvidenceAtomicity(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	resourceID resource.ID,
	actorID identity.PrincipalID,
) {
	t.Helper()
	transaction, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin incomplete Resource lifecycle: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
    '01890f00-0000-7000-8000-000000000103',
    '01890f00-0000-7000-8000-000000000203'
)`); err != nil {
		t.Fatalf("set incomplete Resource lifecycle scope: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config(
    'mesh.change_public_id', '01890f70-0000-7000-8000-000000000004', TRUE
)`); err != nil {
		t.Fatalf("set incomplete Resource lifecycle change: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.transition_resource_lifecycle_v1(
    $1::UUID, 1, 'suspended', $2::UUID, pg_catalog.transaction_timestamp()
)`, resourceID.String(), actorID.String()); err != nil {
		t.Fatalf("apply incomplete Resource lifecycle: %v", err)
	}
	if err := transaction.Commit(ctx); err == nil {
		t.Fatal("incomplete Resource lifecycle commit error = nil")
	}
	var state string
	var version int64
	if err := adminConnection.QueryRow(ctx, `SELECT state, version
FROM mesh.resource WHERE public_id = $1::UUID`, resourceID.String()).Scan(&state, &version); err != nil {
		t.Fatalf("query incomplete Resource lifecycle rollback: %v", err)
	}
	if state != "active" || version != 1 {
		t.Fatalf("incomplete Resource lifecycle state/version = %s/%d", state, version)
	}
}

func assertResourceCatalogReads(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	homeScope network.Scope,
	otherScope network.Scope,
	resourceID resource.ID,
	groupID resource.GroupID,
) {
	t.Helper()
	store, err := postgresadapter.NewResourceCatalogStore(
		runtimePool,
		postgresadapter.ResourceCatalogOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceCatalogStore() error = %v", err)
	}
	service, err := catalog.NewService(catalog.Dependencies{
		Transactions: store,
		Clock:        catalog.SystemClock{},
	})
	if err != nil {
		t.Fatalf("catalog.NewService() error = %v", err)
	}
	resourceValue, err := service.GetResource(ctx, session, homeScope, resourceID)
	if err != nil || resourceValue.ID() != resourceID || resourceValue.State() != resource.StateActive {
		t.Fatalf("GetResource() value = %+v, error = %v", resourceValue, err)
	}
	resourcePage, err := service.ListResources(
		ctx, session, homeScope, resource.StateActive, 100, catalog.PageCursor{},
	)
	if err != nil || len(resourcePage.Items) == 0 || resourcePage.Revision <= 1 {
		t.Fatalf("ListResources() page = %+v, error = %v", resourcePage, err)
	}
	groupValue, err := service.GetGroup(ctx, session, homeScope, groupID)
	if err != nil || groupValue.ID() != groupID || len(groupValue.Members()) != 1 {
		t.Fatalf("GetGroup() value = %+v, error = %v", groupValue, err)
	}
	if _, err := service.GetResource(ctx, session, otherScope, resourceID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("cross-scope GetResource() error = %v, want ErrNotFound", err)
	}
}

func newIntegrationResourceAuthorityService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *authority.Service {
	t.Helper()
	store, err := postgresadapter.NewResourceAuthorityStore(
		runtimePool,
		postgresadapter.ResourceAuthorityOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceAuthorityStore() error = %v", err)
	}
	retry, err := authority.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("authority.NewExponentialBackoff() error = %v", err)
	}
	service, err := authority.NewService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: 2 * time.Second,
			IdempotencyWindow: time.Hour,
		},
		authority.Dependencies{
			Transactions: store, CommittedResults: store,
			MutationIDs: authority.PublicMutationIDGenerator{},
			Clock:       authority.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("authority.NewService() error = %v", err)
	}
	return service
}

func newIntegrationResourceLifecycleService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *authority.LifecycleService {
	t.Helper()
	store, err := postgresadapter.NewResourceAuthorityStore(
		runtimePool,
		postgresadapter.ResourceAuthorityOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceAuthorityStore() error = %v", err)
	}
	retry, err := authority.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("authority.NewExponentialBackoff() error = %v", err)
	}
	service, err := authority.NewLifecycleService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: 2 * time.Second,
			IdempotencyWindow: time.Hour,
		},
		authority.LifecycleDependencies{
			Transactions: store, CommittedResults: store,
			MutationIDs: authority.PublicLifecycleMutationIDGenerator{},
			Clock:       authority.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("authority.NewLifecycleService() error = %v", err)
	}
	return service
}

func newIntegrationResourceRebindService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *authority.RebindService {
	t.Helper()
	store, err := postgresadapter.NewResourceAuthorityStore(
		runtimePool,
		postgresadapter.ResourceAuthorityOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceAuthorityStore() error = %v", err)
	}
	retry, err := authority.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("authority.NewExponentialBackoff() error = %v", err)
	}
	service, err := authority.NewRebindService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: 2 * time.Second,
			IdempotencyWindow: time.Hour,
		},
		authority.RebindDependencies{
			Impacts: store, Transactions: store, CommittedResults: store,
			MutationIDs: authority.PublicRebindMutationIDGenerator{},
			Clock:       authority.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("authority.NewRebindService() error = %v", err)
	}
	return service
}

func newIntegrationResourceGroupReplaceService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *authority.GroupReplaceService {
	t.Helper()
	store, err := postgresadapter.NewResourceAuthorityStore(
		runtimePool,
		postgresadapter.ResourceAuthorityOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceAuthorityStore() error = %v", err)
	}
	retry, err := authority.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("authority.NewExponentialBackoff() error = %v", err)
	}
	service, err := authority.NewGroupReplaceService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: 2 * time.Second,
			IdempotencyWindow: time.Hour,
		},
		authority.GroupReplaceDependencies{
			Impacts: store, Transactions: store, CommittedResults: store,
			MutationIDs: authority.PublicGroupReplaceMutationIDGenerator{},
			Clock:       authority.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("authority.NewGroupReplaceService() error = %v", err)
	}
	return service
}

func newIntegrationResourceAuthorityChangeService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *authority.ChangeService {
	t.Helper()
	store, err := postgresadapter.NewResourceAuthorityStore(
		runtimePool,
		postgresadapter.ResourceAuthorityOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceAuthorityStore() error = %v", err)
	}
	retry, err := authority.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("authority.NewExponentialBackoff() error = %v", err)
	}
	service, err := authority.NewAuthorityChangeService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: 2 * time.Second,
			IdempotencyWindow: time.Hour,
		},
		authority.ChangeDependencies{
			Impacts: store, RequestTransactions: store, CommittedRequests: store,
			ConfirmationTransactions: store, CommittedConfirmations: store,
			MutationIDs: authority.PublicAuthorityChangeMutationIDGenerator{},
			Clock:       authority.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("authority.NewAuthorityChangeService() error = %v", err)
	}
	return service
}

func resourceAuthorityReference(
	t *testing.T,
	scope network.Scope,
	resourceID resource.ID,
	version, generation int64,
) resource.Reference {
	t.Helper()
	reference, err := resource.NewReference(scope, resourceID, version, generation)
	if err != nil {
		t.Fatalf("resource.NewReference() error = %v", err)
	}
	return reference
}

func resourceAuthorityProof(t *testing.T, suffix byte) idempotency.Proof {
	t.Helper()
	digest := [32]byte{31: suffix}
	proof, err := idempotency.NewProof("phase2-integration-v1", digest)
	if err != nil {
		t.Fatalf("idempotency.NewProof() error = %v", err)
	}
	return proof
}

func assertCommittedDeviceResource(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command authority.Command,
	result authority.Result,
) {
	t.Helper()
	var resourceCount, targetCount, auditCount, outboxCount int
	hash := command.SemanticHash().Bytes()
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource
     WHERE public_id = $1::UUID AND workspace_id = 103 AND network_id = 203
       AND version = 1 AND target_generation = 1 AND state = 'active'
       AND activated_network_revision = $2 AND inventory_revision = $3
       AND semantic_hash = $4::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_device_target AS target
     JOIN mesh.resource AS resource ON resource.id = target.resource_id
     WHERE resource.public_id = $1::UUID AND target.state = 'active'
       AND target.target_generation = 1 AND target.version = 1),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource' AND target_public_id = $1::UUID
       AND action = 'resource.created' AND permission = 'resource.manage'
       AND payload ->> 'account_session_id' = $5),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource' AND aggregate_public_id = $1::UUID
       AND aggregate_version = 1 AND network_revision = $2
       AND event_class = 'network.revision.advanced')`,
		result.ResourceID().String(),
		result.NetworkRevision(),
		result.SubsystemRevision(),
		hash[:],
		integrationManagementSessionPublicID,
	).Scan(&resourceCount, &targetCount, &auditCount, &outboxCount); err != nil {
		t.Fatalf("query committed Device Resource: %v", err)
	}
	if resourceCount != 1 || targetCount != 1 || auditCount != 1 || outboxCount != 1 {
		t.Fatalf(
			"Device Resource evidence resource/target/audit/outbox = %d/%d/%d/%d",
			resourceCount, targetCount, auditCount, outboxCount,
		)
	}
}

func assertCommittedResourceGroup(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command authority.Command,
	result authority.Result,
) {
	t.Helper()
	var groupCount, versionCount, memberCount, auditCount, outboxCount int
	hash := command.SemanticHash().Bytes()
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group
     WHERE public_id = $1::UUID AND workspace_id = 103 AND network_id = 203
       AND version = 1 AND active_definition_version = 1 AND state = 'active'
       AND activated_network_revision = $2 AND group_revision = $3
       AND semantic_hash = $4::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version AS version
     JOIN mesh.resource_group AS resource_group ON resource_group.id = version.resource_group_id
     WHERE resource_group.public_id = $1::UUID AND version.definition_version = 1
       AND version.member_count = 1 AND version.semantic_hash = $4::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version_member AS member
     JOIN mesh.resource_group AS resource_group ON resource_group.id = member.resource_group_id
     WHERE resource_group.public_id = $1::UUID AND member.resource_version = 1
       AND member.target_generation = 1),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource_group' AND target_public_id = $1::UUID
       AND action = 'resource_group.created' AND permission = 'resource_group.manage'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource_group' AND aggregate_public_id = $1::UUID
       AND aggregate_version = 1 AND network_revision = $2
       AND event_class = 'network.revision.advanced')`,
		result.GroupID().String(), result.NetworkRevision(), result.SubsystemRevision(), hash[:],
	).Scan(&groupCount, &versionCount, &memberCount, &auditCount, &outboxCount); err != nil {
		t.Fatalf("query committed Resource Group: %v", err)
	}
	if groupCount != 1 || versionCount != 1 || memberCount != 1 ||
		auditCount != 1 || outboxCount != 1 {
		t.Fatalf(
			"Resource Group evidence group/version/member/audit/outbox = %d/%d/%d/%d/%d",
			groupCount, versionCount, memberCount, auditCount, outboxCount,
		)
	}
}

func assertCommittedResourceLifecycle(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	result authority.LifecycleResult,
	expectedEventCount int,
) {
	t.Helper()
	var aggregateCount, auditCount, outboxCount, idempotencyCount int
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource
     WHERE public_id = $1::UUID AND state = 'deleted' AND deleted_at = updated_at
       AND version = $2 AND activated_network_revision = $3
       AND inventory_revision = $4),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource' AND target_public_id = $1::UUID
       AND action IN ('resource.suspended', 'resource.resumed', 'resource.deleted')
       AND permission = 'resource.manage'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource' AND aggregate_public_id = $1::UUID
       AND aggregate_version BETWEEN 2 AND $2
       AND event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.idempotency_record
     WHERE result_kind = 'resource_lifecycle' AND result_public_id = $1::UUID
       AND state = 'completed')`,
		result.ResourceID().String(), result.Version(), result.NetworkRevision(),
		result.SubsystemRevision(),
	).Scan(&aggregateCount, &auditCount, &outboxCount, &idempotencyCount); err != nil {
		t.Fatalf("query committed Resource lifecycle: %v", err)
	}
	if aggregateCount != 1 || auditCount != expectedEventCount ||
		outboxCount != expectedEventCount || idempotencyCount != expectedEventCount {
		t.Fatalf(
			"Resource lifecycle evidence aggregate/audit/outbox/idempotency = %d/%d/%d/%d",
			aggregateCount, auditCount, outboxCount, idempotencyCount,
		)
	}
}

func assertCommittedResourceRebind(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	result authority.RebindResult,
	affectedGroupID resource.GroupID,
) {
	t.Helper()
	var resourceCount, supersededCount, activeCount, pinnedGroupCount int
	var auditCount, outboxCount, idempotencyCount int
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource
     WHERE public_id = $1::UUID AND version = $2 AND target_generation = $3
       AND activated_network_revision = $4 AND inventory_revision = $5
       AND state = 'active'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_device_target AS target
     JOIN mesh.resource AS resource ON resource.id = target.resource_id
     WHERE resource.public_id = $1::UUID AND target.state = 'superseded'
       AND target.target_generation = 1 AND target.version = 2),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_device_target AS target
     JOIN mesh.resource AS resource ON resource.id = target.resource_id
     JOIN mesh.device AS device ON device.id = target.device_id
     WHERE resource.public_id = $1::UUID AND target.state = 'active'
       AND target.target_generation = $3 AND target.version = 1
       AND device.public_id = $6::UUID),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version_member AS member
     JOIN mesh.resource_group AS resource_group ON resource_group.id = member.resource_group_id
     JOIN mesh.resource AS resource ON resource.id = member.resource_id
     WHERE resource_group.public_id = $7::UUID AND resource.public_id = $1::UUID
       AND member.target_generation = 1),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource' AND target_public_id = $1::UUID
       AND action = 'resource.rebound' AND permission = 'resource.manage'
       AND payload ->> 'approval_status' = 'not_required'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource' AND aggregate_public_id = $1::UUID
       AND aggregate_version = $2 AND network_revision = $4
       AND event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.idempotency_record
     WHERE result_kind = 'resource_rebind' AND result_public_id = $1::UUID
       AND result_version = $2 AND state = 'completed')`,
		result.ResourceID().String(), result.Version(), result.TargetGeneration(),
		result.NetworkRevision(), result.InventoryRevision(), result.DeviceID().String(),
		affectedGroupID.String(),
	).Scan(
		&resourceCount, &supersededCount, &activeCount, &pinnedGroupCount,
		&auditCount, &outboxCount, &idempotencyCount,
	); err != nil {
		t.Fatalf("query committed Resource rebind: %v", err)
	}
	if resourceCount != 1 || supersededCount != 1 || activeCount != 1 ||
		pinnedGroupCount != 1 || auditCount != 1 || outboxCount != 1 || idempotencyCount != 1 {
		t.Fatalf(
			"Resource rebind evidence resource/superseded/active/pinned/audit/outbox/idempotency = %d/%d/%d/%d/%d/%d/%d",
			resourceCount, supersededCount, activeCount, pinnedGroupCount,
			auditCount, outboxCount, idempotencyCount,
		)
	}
}

func assertCommittedResourceGroupReplacement(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	result authority.GroupReplaceResult,
	rebound authority.RebindResult,
) {
	t.Helper()
	var groupCount, versionCount, oldMemberCount, newMemberCount int
	var auditCount, outboxCount, idempotencyCount int
	hash := result.SemanticHash().Bytes()
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group
     WHERE public_id = $1::UUID AND version = $2 AND active_definition_version = $3
       AND activated_network_revision = $4 AND group_revision = $5
       AND semantic_hash = $6::BYTEA AND state = 'active'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version AS version
     JOIN mesh.resource_group AS resource_group ON resource_group.id = version.resource_group_id
     WHERE resource_group.public_id = $1::UUID
       AND version.definition_version IN (1, $3)),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version_member AS member
     JOIN mesh.resource_group AS resource_group ON resource_group.id = member.resource_group_id
     JOIN mesh.resource_group_version AS version ON version.id = member.resource_group_version_id
     WHERE resource_group.public_id = $1::UUID AND version.definition_version = 1
       AND member.resource_version = 1 AND member.target_generation = 1),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version_member AS member
     JOIN mesh.resource_group AS resource_group ON resource_group.id = member.resource_group_id
     JOIN mesh.resource_group_version AS version ON version.id = member.resource_group_version_id
     JOIN mesh.resource AS resource ON resource.id = member.resource_id
     WHERE resource_group.public_id = $1::UUID AND version.definition_version = $3
       AND resource.public_id = $7::UUID AND member.resource_version = $8
       AND member.target_generation = $9),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource_group' AND target_public_id = $1::UUID
       AND action = 'resource_group.definition_replaced'
       AND permission = 'resource_group.manage'
       AND payload ->> 'approval_status' = 'not_required'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource_group' AND aggregate_public_id = $1::UUID
       AND aggregate_version = $2 AND network_revision = $4
       AND event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.idempotency_record
     WHERE result_kind = 'resource_group_replace' AND result_public_id = $1::UUID
       AND result_version = $2 AND state = 'completed')`,
		result.GroupID().String(), result.Version(), result.DefinitionVersion(),
		result.NetworkRevision(), result.GroupRevision(), hash[:], rebound.ResourceID().String(),
		rebound.Version(), rebound.TargetGeneration(),
	).Scan(
		&groupCount, &versionCount, &oldMemberCount, &newMemberCount,
		&auditCount, &outboxCount, &idempotencyCount,
	); err != nil {
		t.Fatalf("query committed Resource Group replacement: %v", err)
	}
	if groupCount != 1 || versionCount != 2 || oldMemberCount != 1 || newMemberCount != 1 ||
		auditCount != 1 || outboxCount != 1 || idempotencyCount != 1 {
		t.Fatalf(
			"Resource Group replacement evidence group/versions/old/new/audit/outbox/idempotency = %d/%d/%d/%d/%d/%d/%d",
			groupCount, versionCount, oldMemberCount, newMemberCount,
			auditCount, outboxCount, idempotencyCount,
		)
	}
}

func assertCommittedResourceAuthorityChange(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	requested authority.ChangeRequestResult,
	confirmed authority.ChangeConfirmationResult,
	requester, confirmer accountsession.Session,
) {
	t.Helper()
	var resourceCount, requestCount, stepUpCount int
	var requestAuditCount, confirmationAuditCount, outboxCount, idempotencyCount int
	hash := confirmed.SemanticHash().Bytes()
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource
     WHERE public_id = $1::UUID AND version = $2
       AND owner_principal_id = 13 AND custodian_principal_id = 11
       AND semantic_hash = $3::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_authority_change_request
     WHERE public_id = $4::UUID AND state = 'applied' AND version = 2
       AND confirmation_count = 1 AND applied_at IS NOT NULL),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.resource_authority_step_up_evidence AS evidence
     JOIN mesh.resource_authority_change_request AS request
       ON request.id = evidence.request_id
     WHERE request.public_id = $4::UUID
       AND evidence.account_session_id IN (812, 813)),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource_authority_change_request'
       AND target_public_id = $4::UUID
       AND action = 'resource.authority_change_requested'
       AND permission = 'resource.transfer'
       AND payload ->> 'account_session_id' = $5),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource' AND target_public_id = $1::UUID
       AND action = 'resource.owner_transfer'
       AND permission = 'resource.transfer'
       AND payload ->> 'account_session_id' = $6),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event AS event
     WHERE event.public_id IN (
         SELECT record.outbox_public_id
         FROM mesh_ops.idempotency_record AS record
         WHERE record.operation IN (
             'resource_authority_change.request',
             'resource_authority_change.confirm'
         )
           AND record.result_public_id IN ($1::UUID, $4::UUID)
     )
       AND event.event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.idempotency_record
     WHERE state = 'completed'
       AND operation IN (
           'resource_authority_change.request',
           'resource_authority_change.confirm'
       )
       AND result_public_id IN ($1::UUID, $4::UUID))`,
		confirmed.SubjectPublicID().String(), confirmed.SubjectVersion(), hash[:],
		requested.RequestID().String(), requester.ID().String(), confirmer.ID().String(),
	).Scan(
		&resourceCount, &requestCount, &stepUpCount, &requestAuditCount,
		&confirmationAuditCount, &outboxCount, &idempotencyCount,
	); err != nil {
		t.Fatalf("query committed Resource authority change: %v", err)
	}
	if resourceCount != 1 || requestCount != 1 || stepUpCount != 2 ||
		requestAuditCount != 1 || confirmationAuditCount != 1 || outboxCount != 2 ||
		idempotencyCount != 2 {
		t.Fatalf(
			"Resource authority change evidence resource/request/step-up/request-audit/confirmation-audit/outbox/idempotency = %d/%d/%d/%d/%d/%d/%d",
			resourceCount, requestCount, stepUpCount, requestAuditCount,
			confirmationAuditCount, outboxCount, idempotencyCount,
		)
	}
}

func assertCommittedGroupLifecycle(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	result authority.LifecycleResult,
	expectedEventCount int,
) {
	t.Helper()
	var aggregateCount, auditCount, outboxCount, idempotencyCount int
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group
     WHERE public_id = $1::UUID AND state = 'deleted' AND deleted_at = updated_at
       AND version = $2 AND activated_network_revision = $3
       AND group_revision = $4),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource_group' AND target_public_id = $1::UUID
       AND action IN ('resource_group.suspended', 'resource_group.resumed', 'resource_group.deleted')
       AND permission = 'resource_group.manage'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource_group' AND aggregate_public_id = $1::UUID
       AND aggregate_version BETWEEN 2 AND $2
       AND event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.idempotency_record
     WHERE result_kind = 'resource_group_lifecycle' AND result_public_id = $1::UUID
       AND state = 'completed')`,
		result.GroupID().String(), result.Version(), result.NetworkRevision(),
		result.SubsystemRevision(),
	).Scan(&aggregateCount, &auditCount, &outboxCount, &idempotencyCount); err != nil {
		t.Fatalf("query committed Resource Group lifecycle: %v", err)
	}
	if aggregateCount != 1 || auditCount != expectedEventCount ||
		outboxCount != expectedEventCount || idempotencyCount != expectedEventCount {
		t.Fatalf(
			"Resource Group lifecycle evidence aggregate/audit/outbox/idempotency = %d/%d/%d/%d",
			aggregateCount, auditCount, outboxCount, idempotencyCount,
		)
	}
}

func assertResourceAuthorityEvidenceAtomicity(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()
	inventoryRevision, _ := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 203)
	transaction, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin incomplete Resource authority transaction: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
    '01890f00-0000-7000-8000-000000000103',
    '01890f00-0000-7000-8000-000000000203'
)`); err != nil {
		t.Fatalf("set incomplete Resource authority scope: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config(
    'mesh.change_public_id', '01890f70-0000-7000-8000-000000000003', TRUE
)`); err != nil {
		t.Fatalf("set incomplete Resource authority change: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.create_device_resource_v1(
    '01890f70-0000-7000-8000-000000000001',
    '01890f70-0000-7000-8000-000000000002',
    $1::BIGINT,
    '01890f31-0000-7000-8000-000000000910',
    '01890f00-0000-7000-8000-000000000011',
    'Incomplete evidence',
    pg_catalog.decode(pg_catalog.repeat('01', 32), 'hex'),
    pg_catalog.transaction_timestamp()
)`, inventoryRevision); err != nil {
		t.Fatalf("apply incomplete Resource authority: %v", err)
	}
	if err := transaction.Commit(ctx); err == nil {
		t.Fatal("incomplete Resource authority commit error = nil")
	}
	var count int
	if err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh.resource
WHERE public_id = '01890f70-0000-7000-8000-000000000001'`).Scan(&count); err != nil {
		t.Fatalf("query incomplete Resource rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("incomplete Resource count = %d, want 0", count)
	}
}

func assertResourceAuthorityPrivilegeContract(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	var runtimeCreate, workerCreate, runtimeReads, workerReads bool
	var runtimeLifecycle, workerLifecycle, runtimeTableAccess bool
	var runtimeRebindReaders, workerRebindReaders, runtimeRebind, workerRebind bool
	var runtimeGroupReplaceReaders, workerGroupReplaceReaders bool
	var runtimeGroupReplace, workerGroupReplace bool
	if err := adminConnection.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.create_device_resource_v1(uuid,uuid,bigint,uuid,uuid,text,bytea,timestamptz)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.create_device_resource_v1(uuid,uuid,bigint,uuid,uuid,text,bytea,timestamptz)',
        'EXECUTE'
    ),
	(SELECT pg_catalog.bool_and(pg_catalog.has_function_privilege(
		'mesh_runtime', reader.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.read_network_revision_v1()'::pg_catalog.regprocedure,
		'mesh_ops.read_resource_v2(uuid)'::pg_catalog.regprocedure,
		'mesh_ops.list_resources_v1(uuid,text,integer)'::pg_catalog.regprocedure,
		'mesh_ops.read_resource_group_v2(uuid)'::pg_catalog.regprocedure,
		'mesh_ops.list_resource_groups_v1(uuid,text,integer)'::pg_catalog.regprocedure
	]) AS reader(function_oid)),
	(SELECT pg_catalog.bool_or(pg_catalog.has_function_privilege(
		'mesh_worker', reader.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.read_network_revision_v1()'::pg_catalog.regprocedure,
		'mesh_ops.read_resource_v2(uuid)'::pg_catalog.regprocedure,
		'mesh_ops.list_resources_v1(uuid,text,integer)'::pg_catalog.regprocedure,
		'mesh_ops.read_resource_group_v2(uuid)'::pg_catalog.regprocedure,
		'mesh_ops.list_resource_groups_v1(uuid,text,integer)'::pg_catalog.regprocedure
	]) AS reader(function_oid)),
	(SELECT pg_catalog.bool_and(pg_catalog.has_function_privilege(
		'mesh_runtime', lifecycle.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.transition_resource_lifecycle_v1(uuid,bigint,text,uuid,timestamptz)'::pg_catalog.regprocedure,
		'mesh_ops.transition_resource_group_lifecycle_v1(uuid,bigint,text,uuid,timestamptz)'::pg_catalog.regprocedure
	]) AS lifecycle(function_oid)),
	(SELECT pg_catalog.bool_or(pg_catalog.has_function_privilege(
		'mesh_worker', lifecycle.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.transition_resource_lifecycle_v1(uuid,bigint,text,uuid,timestamptz)'::pg_catalog.regprocedure,
		'mesh_ops.transition_resource_group_lifecycle_v1(uuid,bigint,text,uuid,timestamptz)'::pg_catalog.regprocedure
	]) AS lifecycle(function_oid)),
	(SELECT pg_catalog.bool_and(pg_catalog.has_function_privilege(
		'mesh_runtime', impact_reader.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.preview_device_resource_rebind_v1(uuid,uuid)'::pg_catalog.regprocedure,
		'mesh_ops.lock_device_resource_rebind_v1(uuid,uuid)'::pg_catalog.regprocedure
	]) AS impact_reader(function_oid)),
	(SELECT pg_catalog.bool_or(pg_catalog.has_function_privilege(
		'mesh_worker', impact_reader.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.preview_device_resource_rebind_v1(uuid,uuid)'::pg_catalog.regprocedure,
		'mesh_ops.lock_device_resource_rebind_v1(uuid,uuid)'::pg_catalog.regprocedure
	]) AS impact_reader(function_oid)),
	pg_catalog.has_function_privilege(
		'mesh_runtime',
		'mesh_ops.rebind_device_resource_v1(uuid,bigint,uuid,uuid,uuid,bytea,timestamptz)',
		'EXECUTE'
	),
	pg_catalog.has_function_privilege(
		'mesh_worker',
		'mesh_ops.rebind_device_resource_v1(uuid,bigint,uuid,uuid,uuid,bytea,timestamptz)',
		'EXECUTE'
	),
	(SELECT pg_catalog.bool_and(pg_catalog.has_function_privilege(
		'mesh_runtime', impact_reader.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.preview_resource_group_replace_v1(uuid,jsonb)'::pg_catalog.regprocedure,
		'mesh_ops.lock_resource_group_replace_v1(uuid,jsonb)'::pg_catalog.regprocedure
	]) AS impact_reader(function_oid)),
	(SELECT pg_catalog.bool_or(pg_catalog.has_function_privilege(
		'mesh_worker', impact_reader.function_oid, 'EXECUTE'
	)) FROM pg_catalog.unnest(ARRAY[
		'mesh_ops.preview_resource_group_replace_v1(uuid,jsonb)'::pg_catalog.regprocedure,
		'mesh_ops.lock_resource_group_replace_v1(uuid,jsonb)'::pg_catalog.regprocedure
	]) AS impact_reader(function_oid)),
	pg_catalog.has_function_privilege(
		'mesh_runtime',
		'mesh_ops.replace_resource_group_definition_v1(uuid,bigint,uuid,uuid,bytea,timestamptz,jsonb)',
		'EXECUTE'
	),
	pg_catalog.has_function_privilege(
		'mesh_worker',
		'mesh_ops.replace_resource_group_definition_v1(uuid,bigint,uuid,uuid,bytea,timestamptz,jsonb)',
		'EXECUTE'
	),
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'DELETE')
    ), FALSE)
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN (
      'resource', 'resource_device_target', 'resource_group',
      'resource_group_version', 'resource_group_version_member'
	)`).Scan(
		&runtimeCreate, &workerCreate, &runtimeReads, &workerReads,
		&runtimeLifecycle, &workerLifecycle, &runtimeRebindReaders, &workerRebindReaders,
		&runtimeRebind, &workerRebind,
		&runtimeGroupReplaceReaders, &workerGroupReplaceReaders,
		&runtimeGroupReplace, &workerGroupReplace,
		&runtimeTableAccess,
	); err != nil {
		t.Fatalf("query Resource authority privileges: %v", err)
	}
	if !runtimeCreate || workerCreate || !runtimeReads || workerReads ||
		!runtimeLifecycle || workerLifecycle || !runtimeRebindReaders || workerRebindReaders ||
		!runtimeRebind || workerRebind ||
		!runtimeGroupReplaceReaders || workerGroupReplaceReaders ||
		!runtimeGroupReplace || workerGroupReplace ||
		runtimeTableAccess {
		t.Fatalf(
			"Resource privileges runtime-create=%t worker-create=%t runtime-reads=%t worker-reads=%t runtime-lifecycle=%t worker-lifecycle=%t runtime-rebind-readers=%t worker-rebind-readers=%t runtime-rebind=%t worker-rebind=%t runtime-group-replace-readers=%t worker-group-replace-readers=%t runtime-group-replace=%t worker-group-replace=%t runtime-table=%t",
			runtimeCreate, workerCreate, runtimeReads, workerReads,
			runtimeLifecycle, workerLifecycle, runtimeRebindReaders, workerRebindReaders,
			runtimeRebind, workerRebind,
			runtimeGroupReplaceReaders, workerGroupReplaceReaders,
			runtimeGroupReplace, workerGroupReplace,
			runtimeTableAccess,
		)
	}
	if err := runtimeConnection.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.resource`).Scan(new(int64)); err == nil {
		t.Fatal("runtime direct Resource table read unexpectedly succeeded")
	}
	if err := workerConnection.QueryRow(ctx, `SELECT * FROM mesh_ops.resolve_resource_v1(
    '01890f70-0000-7000-8000-000000000001'
)`).Scan(new(string)); err == nil {
		t.Fatal("worker Resource resolver execution unexpectedly succeeded")
	}
	if err := workerConnection.QueryRow(ctx, `SELECT * FROM mesh_ops.transition_resource_lifecycle_v1(
    '01890f70-0000-7000-8000-000000000001', 1, 'suspended',
    '01890f00-0000-7000-8000-000000000011', pg_catalog.transaction_timestamp()
)`).Scan(new(int64)); err == nil {
		t.Fatal("worker Resource lifecycle execution unexpectedly succeeded")
	}
	if err := workerConnection.QueryRow(ctx, `SELECT * FROM mesh_ops.rebind_device_resource_v1(
    '01890f70-0000-7000-8000-000000000001', 1,
    '01890f70-0000-7000-8000-000000000002',
    '01890f31-0000-7000-8000-000000000910',
    '01890f00-0000-7000-8000-000000000011',
    pg_catalog.decode(pg_catalog.repeat('01', 32), 'hex'),
    pg_catalog.transaction_timestamp()
)`).Scan(new(int64)); err == nil {
		t.Fatal("worker Resource rebind execution unexpectedly succeeded")
	}
}

func resourceAuthorityRevisions(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	workspaceID, networkID int64,
) (int64, int64) {
	t.Helper()
	var inventoryRevision, groupRevision int64
	if err := connection.QueryRow(ctx, `SELECT inventory_revision, group_revision
FROM mesh_ops.network_revision
WHERE workspace_id = $1 AND network_id = $2`, workspaceID, networkID).Scan(
		&inventoryRevision, &groupRevision,
	); err != nil {
		t.Fatalf("query Resource authority revisions: %v", err)
	}
	return inventoryRevision, groupRevision
}

func resourceAuthorityScope(t *testing.T, workspaceSuffix, networkSuffix int) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID(integrationPublicID("01890f00-0000-7000-8000-", int64(workspaceSuffix)))
	if err != nil {
		t.Fatalf("parse Resource authority Workspace: %v", err)
	}
	networkID, err := network.ParseID(integrationPublicID("01890f00-0000-7000-8000-", int64(networkSuffix)))
	if err != nil {
		t.Fatalf("parse Resource authority Network: %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("construct Resource authority scope: %v", err)
	}
	return scope
}

func resourceAuthorityNodeID(t *testing.T, suffix int) node.ID {
	t.Helper()
	id, err := node.ParseID(integrationPublicID("01890f31-0000-7000-8000-", int64(suffix)))
	if err != nil {
		t.Fatalf("parse Resource authority Device: %v", err)
	}
	return id
}

func resourceAuthorityDeviceDefinition(
	t *testing.T,
	scope network.Scope,
	actorID identity.PrincipalID,
	deviceID node.ID,
	displayName string,
) resource.DeviceDefinition {
	t.Helper()
	name, err := resource.ParseDisplayName(displayName)
	if err != nil {
		t.Fatalf("parse Resource display name: %v", err)
	}
	definition, err := resource.NewDeviceDefinition(resource.DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: actorID,
		CustodianPrincipalID: actorID, DeviceID: deviceID,
	})
	if err != nil {
		t.Fatalf("construct Device Resource definition: %v", err)
	}
	return definition
}

func resourceAuthorityGroupDefinition(
	t *testing.T,
	scope network.Scope,
	actorID identity.PrincipalID,
	displayName string,
	members []resource.Reference,
) resource.GroupDefinition {
	t.Helper()
	name, err := resource.ParseDisplayName(displayName)
	if err != nil {
		t.Fatalf("parse Resource Group display name: %v", err)
	}
	definition, err := resource.NewGroupDefinition(resource.GroupDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: actorID,
		CustodianPrincipalID: actorID, Members: members,
	})
	if err != nil {
		t.Fatalf("construct Resource Group definition: %v", err)
	}
	return definition
}

func resourceAuthorityReason(t *testing.T, value string) authority.AuditReason {
	t.Helper()
	reason, err := authority.NewAuditReason(value)
	if err != nil {
		t.Fatalf("construct Resource authority reason: %v", err)
	}
	return reason
}
