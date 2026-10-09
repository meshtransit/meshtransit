package authority

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/resource"
)

func TestRebindServicePreviewsDeterministicImpact(t *testing.T) {
	t.Parallel()
	preview := rebindPreviewFixture(t)
	impact := rebindImpactFixture(t, preview, 302, 502)
	dependencies := &fakeRebindDependencies{impact: impact}
	service := rebindServiceFixture(t, dependencies, rebindMutationIDsFixture(t))

	result, err := service.Preview(t.Context(), preview)
	if err != nil {
		t.Fatalf("Preview() error = %v", err)
	}
	if !result.Equal(impact) || len(result.AffectedGroupIDs()) != 1 || result.ApprovalRequired() {
		t.Fatalf("Preview() = %+v", result)
	}
}

func TestRebindServiceCommitsAcknowledgedTarget(t *testing.T) {
	t.Parallel()
	preview := rebindPreviewFixture(t)
	impact := rebindImpactFixture(t, preview, 302, 502)
	command := rebindCommandFixture(t, preview, impact.Hash())
	ids := rebindMutationIDsFixture(t)
	resolution := rebindResolutionFixture(t, command, ids, impact)
	transaction := &fakeRebindTransaction{resolution: resolution}
	dependencies := &fakeRebindDependencies{
		impact: impact, transactions: []*fakeRebindTransaction{transaction},
	}
	service := rebindServiceFixture(t, dependencies, ids)

	result, err := service.Rebind(t.Context(), command)
	if err != nil {
		t.Fatalf("Rebind() error = %v", err)
	}
	if result.ResourceID() != preview.ResourceID() || result.DeviceID() != preview.DeviceID() ||
		result.TargetGeneration() != 2 || result.Version() != 2 ||
		result.NetworkRevision() != 8 || result.InventoryRevision() != 4 ||
		transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("Rebind() result=%+v transaction=%+v", result, transaction)
	}
}

func TestRebindServiceRejectsChangedImpactBeforeApply(t *testing.T) {
	t.Parallel()
	preview := rebindPreviewFixture(t)
	acknowledged := rebindImpactFixture(t, preview, 302, 502)
	changed := rebindImpactFixture(t, preview, 302, 503)
	command := rebindCommandFixture(t, preview, acknowledged.Hash())
	ids := rebindMutationIDsFixture(t)
	transaction := &fakeRebindTransaction{
		resolution: rebindResolutionFixture(t, command, ids, changed),
	}
	service := rebindServiceFixture(t, &fakeRebindDependencies{
		impact: acknowledged, transactions: []*fakeRebindTransaction{transaction},
	}, ids)

	_, err := service.Rebind(t.Context(), command)
	if !errors.Is(err, ErrRebindImpactChanged) || transaction.applies != 0 ||
		transaction.rollbacks != 1 {
		t.Fatalf("Rebind() error=%v transaction=%+v", err, transaction)
	}
}

func TestRebindCommandHashBindsImpactAndTarget(t *testing.T) {
	t.Parallel()
	preview := rebindPreviewFixture(t)
	impact := rebindImpactFixture(t, preview, 302, 502)
	command := rebindCommandFixture(t, preview, impact.Hash())
	otherImpact := rebindImpactFixture(t, preview, 302, 503)
	otherImpactCommand := rebindCommandFixture(t, preview, otherImpact.Hash())
	otherDeviceID, err := node.ParseID(authorityPublicID(303))
	if err != nil {
		t.Fatal(err)
	}
	otherPreview, err := NewRebindPreview(
		preview.Scope(), preview.ResourceID(), preview.ExpectedVersion(),
		otherDeviceID, preview.AccountSession(),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherTargetCommand := rebindCommandFixture(t, otherPreview, impact.Hash())
	commandHash, _ := command.RequestHash()
	otherImpactHash, _ := otherImpactCommand.RequestHash()
	otherTargetHash, _ := otherTargetCommand.RequestHash()
	if commandHash == otherImpactHash || commandHash == otherTargetHash {
		t.Fatal("Resource rebind request hash did not bind impact and target")
	}
}

func TestRebindImpactRequiresSequentialTargetGeneration(t *testing.T) {
	t.Parallel()
	preview := rebindPreviewFixture(t)
	current := authorityDeviceDefinitionFixture(t)
	name, err := resource.ParseDisplayName("Database 01")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: name,
		OwnerPrincipalID:     authorityPrincipalID(t, 11),
		CustodianPrincipalID: authorityPrincipalID(t, 11),
		DeviceID:             preview.DeviceID(), TargetGeneration: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewRebindImpact(RebindImpactParams{
		ResourceID: preview.ResourceID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentDeviceID: current.DeviceID(), CurrentTargetGeneration: 1,
		CurrentSemanticHash: current.SemanticHash(), ProposedRevision: revision,
	})
	if !errors.Is(err, ErrInvalidRebindImpact) {
		t.Fatalf("NewRebindImpact() error = %v, want ErrInvalidRebindImpact", err)
	}
	sameTargetRevision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: name,
		OwnerPrincipalID:     authorityPrincipalID(t, 11),
		CustodianPrincipalID: authorityPrincipalID(t, 11),
		DeviceID:             current.DeviceID(), TargetGeneration: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewRebindImpact(RebindImpactParams{
		ResourceID: preview.ResourceID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentDeviceID: current.DeviceID(), CurrentTargetGeneration: 1,
		CurrentSemanticHash: current.SemanticHash(), ProposedRevision: sameTargetRevision,
	})
	if !errors.Is(err, ErrInvalidRebindImpact) {
		t.Fatalf("same-target NewRebindImpact() error = %v, want ErrInvalidRebindImpact", err)
	}
}

func TestRebindResolutionFailsClosedWhenApprovalIsRequired(t *testing.T) {
	t.Parallel()
	preview := rebindPreviewFixture(t)
	base := rebindImpactFixture(t, preview, 302, 502)
	approvalImpact, err := NewRebindImpact(RebindImpactParams{
		ResourceID: base.ResourceID(), ExpectedVersion: base.ExpectedVersion(),
		CurrentDeviceID:         base.CurrentDeviceID(),
		CurrentTargetGeneration: base.CurrentTargetGeneration(),
		CurrentSemanticHash:     base.CurrentSemanticHash(),
		ProposedRevision:        base.ProposedRevision(), AffectedGroupIDs: base.AffectedGroupIDs(),
		ApprovalRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	command := rebindCommandFixture(t, preview, approvalImpact.Hash())
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	ids := rebindMutationIDsFixture(t)
	_, err = NewRebindResolution(
		preview.Scope(), 7, 3, 2, ids.IdempotencyRecordID(), requestHash, approvalImpact,
	)
	if !errors.Is(err, ErrInvalidRebindResolution) {
		t.Fatalf("NewRebindResolution() error = %v, want ErrInvalidRebindResolution", err)
	}
}

type fakeRebindDependencies struct {
	impact       RebindImpact
	previewErr   error
	transactions []*fakeRebindTransaction
	begins       int
	committed    RebindResult
	found        bool
	resolveErr   error
}

func (dependencies *fakeRebindDependencies) PreviewRebind(
	context.Context,
	RebindPreview,
	time.Time,
) (RebindImpact, error) {
	return dependencies.impact, dependencies.previewErr
}

func (dependencies *fakeRebindDependencies) BeginRebind(
	context.Context,
	network.Scope,
) (RebindTransaction, error) {
	if dependencies.begins >= len(dependencies.transactions) {
		return nil, errors.New("unexpected begin")
	}
	transaction := dependencies.transactions[dependencies.begins]
	dependencies.begins++
	return transaction, nil
}

func (dependencies *fakeRebindDependencies) ResolveCommittedRebind(
	context.Context,
	RebindCommand,
	RebindMutationIDs,
) (RebindResult, bool, error) {
	return dependencies.committed, dependencies.found, dependencies.resolveErr
}

type fakeRebindTransaction struct {
	resolution RebindResolution
	applyErr   error
	commitErr  error
	applies    int
	commits    int
	rollbacks  int
}

func (transaction *fakeRebindTransaction) Resolve(
	context.Context,
	RebindCommand,
	RebindMutationIDs,
	time.Time,
	time.Time,
) (RebindResolution, error) {
	return transaction.resolution, nil
}

func (transaction *fakeRebindTransaction) Apply(
	_ context.Context,
	change RebindChange,
) (RebindResult, error) {
	transaction.applies++
	if transaction.applyErr != nil {
		return RebindResult{}, transaction.applyErr
	}
	command := change.Command()
	proposed := change.Resolution().Impact().ProposedRevision()
	return NewRebindResult(
		command.ResourceID(), command.Scope(), command.DeviceID(), proposed.TargetGeneration(),
		command.ExpectedVersion()+1, change.Resolution().NetworkRevision()+1,
		change.Resolution().InventoryRevision()+1, proposed.SemanticHash(), command.ImpactHash(),
	)
}

func (transaction *fakeRebindTransaction) Commit(context.Context) error {
	transaction.commits++
	return transaction.commitErr
}

func (transaction *fakeRebindTransaction) Rollback(context.Context) error {
	transaction.rollbacks++
	return nil
}

type fixedRebindMutationIDs struct{ ids RebindMutationIDs }

func (generator fixedRebindMutationIDs) NewRebindMutationIDs(
	RebindCommand,
) (RebindMutationIDs, error) {
	return generator.ids, nil
}

func rebindServiceFixture(
	t *testing.T,
	dependencies *fakeRebindDependencies,
	ids RebindMutationIDs,
) *RebindService {
	t.Helper()
	service, err := NewRebindService(
		Options{MaxAttempts: 3, RollbackTimeout: time.Second, IdempotencyWindow: time.Hour},
		RebindDependencies{
			Impacts: dependencies, Transactions: dependencies, CommittedResults: dependencies,
			MutationIDs: fixedRebindMutationIDs{ids: ids},
			Clock:       fixedAuthorityClock{now: time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)},
			Retry:       noAuthorityRetryDelay{},
		},
	)
	if err != nil {
		t.Fatalf("NewRebindService() error = %v", err)
	}
	return service
}

func rebindPreviewFixture(t *testing.T) RebindPreview {
	t.Helper()
	resourceID, err := resource.ParseID(authorityPublicID(501))
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := node.ParseID(authorityPublicID(302))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := NewRebindPreview(
		authorityScopeFixture(t), resourceID, 1, deviceID,
		authoritySessionFixture(t, authorityPrincipalID(t, 11)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

func rebindImpactFixture(
	t *testing.T,
	preview RebindPreview,
	deviceSuffix, groupSuffix int,
) RebindImpact {
	t.Helper()
	current := authorityDeviceDefinitionFixture(t)
	deviceID, err := node.ParseID(authorityPublicID(deviceSuffix))
	if err != nil {
		t.Fatal(err)
	}
	name, err := resource.ParseDisplayName("Database 01")
	if err != nil {
		t.Fatal(err)
	}
	principalID := authorityPrincipalID(t, 11)
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: name, OwnerPrincipalID: principalID,
		CustodianPrincipalID: principalID, DeviceID: deviceID, TargetGeneration: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := resource.ParseGroupID(authorityPublicID(groupSuffix))
	if err != nil {
		t.Fatal(err)
	}
	impact, err := NewRebindImpact(RebindImpactParams{
		ResourceID: preview.ResourceID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentDeviceID: current.DeviceID(), CurrentTargetGeneration: 1,
		CurrentSemanticHash: current.SemanticHash(),
		ProposedRevision:    revision, AffectedGroupIDs: []resource.GroupID{groupID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return impact
}

func rebindCommandFixture(
	t *testing.T,
	preview RebindPreview,
	impactHash RebindImpactHash,
) RebindCommand {
	t.Helper()
	reason, err := NewAuditReason("replace failed Device target")
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewRebindCommand(
		preview, impactHash, reason, authorityIdempotencyProofFixture(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func rebindMutationIDsFixture(t *testing.T) RebindMutationIDs {
	t.Helper()
	ids, err := NewRebindMutationIDs(
		authorityPublicIDValue(t, 931), authorityPublicIDValue(t, 932),
		authorityPublicIDValue(t, 933), authorityPublicIDValue(t, 934),
		authorityPublicIDValue(t, 935),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func rebindResolutionFixture(
	t *testing.T,
	command RebindCommand,
	ids RebindMutationIDs,
	impact RebindImpact,
) RebindResolution {
	t.Helper()
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := NewRebindResolution(
		command.Scope(), 7, 3, 2, ids.IdempotencyRecordID(), hash, impact,
	)
	if err != nil {
		t.Fatal(err)
	}
	return resolution
}
