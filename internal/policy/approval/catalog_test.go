package approval_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	approval "github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
)

func TestApprovalCatalogSnapshotLifecycle(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 9, 29, 2, 0, 0, 0, time.UTC)
	approvedAt := createdAt.Add(time.Minute)
	consumedAt := approvedAt.Add(time.Minute)
	requestID, _ := approval.ParseRequestID("01890f00-0000-7000-8000-000000000901")
	evidenceID, _ := approval.ParseEvidenceID("01890f00-0000-7000-8000-000000000902")
	proposer, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	approver, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000402")
	releaseID, _ := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000903")
	proposalReason, _ := approval.NewAuditReason("reviewed simulation")
	decisionReason, _ := approval.NewAuditReason("independent review")
	decision, err := approval.NewDecisionSnapshot(evidenceID, approver, decisionReason, 1, approvedAt)
	if err != nil {
		t.Fatal(err)
	}
	consumption, err := approval.NewConsumptionSnapshot(releaseID, 7, consumedAt)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		state       approval.State
		version     int64
		updatedAt   time.Time
		decision    approval.DecisionSnapshot
		consumption approval.ConsumptionSnapshot
	}{
		{name: "pending", state: approval.StatePending, version: 1, updatedAt: createdAt},
		{name: "approved", state: approval.StateApproved, version: 2, updatedAt: approvedAt, decision: decision},
		{name: "consumed", state: approval.StateConsumed, version: 3, updatedAt: consumedAt, decision: decision, consumption: consumption},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value, err := approval.NewSnapshot(approval.SnapshotParams{
				RequestID: requestID, Binding: approvalBindingFixture(t),
				ProposerPrincipalID: proposer, ProposalReason: proposalReason,
				State: test.state, RequestVersion: test.version,
				CreatedAt: createdAt, ExpiresAt: createdAt.Add(approval.RequestLifetime),
				UpdatedAt: test.updatedAt, Decision: test.decision, Consumption: test.consumption,
			})
			if err != nil || !value.IsValid() || value.State() != test.state {
				t.Fatalf("NewSnapshot() = (%+v, %v)", value, err)
			}
		})
	}
}

func TestApprovalCatalogServiceValidatesScopeAndPagination(t *testing.T) {
	t.Parallel()

	snapshot := approvalCatalogSnapshotFixture(t, "01890f00-0000-7000-8000-000000000901")
	next := approvalCatalogSnapshotFixture(t, "01890f00-0000-7000-8000-000000000905")
	reader := &approvalCatalogReaderFixture{values: []approval.Snapshot{snapshot, snapshot, next}}
	clock := &approvalClockFixture{now: time.Date(2026, 9, 29, 2, 0, 0, 0, time.UTC)}
	service, err := approval.NewCatalogService(reader, clock)
	if err != nil {
		t.Fatal(err)
	}
	session := approvalSessionFixture(t, 402, 602)
	value, err := service.Get(t.Context(), session, snapshot.Scope(), snapshot.RequestID())
	if err != nil || value.RequestID() != snapshot.RequestID() {
		t.Fatalf("Get() = (%+v, %v)", value, err)
	}
	page, err := service.List(
		t.Context(), session, snapshot.Scope(), approval.StatePending, 1, approval.RequestID{},
	)
	if err != nil || len(page.Items) != 1 || page.Next != snapshot.RequestID() {
		t.Fatalf("List() = (%+v, %v)", page, err)
	}
	if reader.getCalls != 1 || reader.listCalls != 1 || reader.permissionTime != clock.now {
		t.Fatalf("reader calls/time = %d/%d/%v", reader.getCalls, reader.listCalls, reader.permissionTime)
	}
}

func TestApprovalCatalogServiceRejectsInvalidResults(t *testing.T) {
	t.Parallel()

	wrong := approvalCatalogSnapshotFixture(t, "01890f00-0000-7000-8000-000000000904")
	reader := &approvalCatalogReaderFixture{values: []approval.Snapshot{wrong}}
	service, err := approval.NewCatalogService(reader, &approvalClockFixture{now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	requested, _ := approval.ParseRequestID("01890f00-0000-7000-8000-000000000901")
	_, err = service.Get(t.Context(), approvalSessionFixture(t, 402, 602), wrong.Scope(), requested)
	if !errors.Is(err, approval.ErrInvalidCatalogResult) {
		t.Fatalf("Get() error = %v, want ErrInvalidCatalogResult", err)
	}
}

func TestApprovalCatalogSnapshotRejectsSelfApproval(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 9, 29, 2, 0, 0, 0, time.UTC)
	proposer, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	evidenceID, _ := approval.ParseEvidenceID("01890f00-0000-7000-8000-000000000902")
	reason, _ := approval.NewAuditReason("independent review")
	decision, err := approval.NewDecisionSnapshot(
		evidenceID, proposer, reason, 1, createdAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	requestID, _ := approval.ParseRequestID("01890f00-0000-7000-8000-000000000901")
	_, err = approval.NewSnapshot(approval.SnapshotParams{
		RequestID: requestID, Binding: approvalBindingFixture(t),
		ProposerPrincipalID: proposer, ProposalReason: reason,
		State: approval.StateApproved, RequestVersion: 2,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(approval.RequestLifetime),
		UpdatedAt: decision.ApprovedAt(), Decision: decision,
	})
	if !errors.Is(err, approval.ErrInvalidCatalogResult) {
		t.Fatalf("NewSnapshot() error = %v, want ErrInvalidCatalogResult", err)
	}
}

type approvalCatalogReaderFixture struct {
	values         []approval.Snapshot
	getCalls       int
	listCalls      int
	permissionTime time.Time
}

func (fixture *approvalCatalogReaderFixture) ReadApprovalRequest(
	_ context.Context,
	_ accountsession.Session,
	_ network.Scope,
	_ approval.RequestID,
	evaluatedAt time.Time,
) (approval.Snapshot, error) {
	fixture.getCalls++
	fixture.permissionTime = evaluatedAt
	if len(fixture.values) == 0 {
		return approval.Snapshot{}, approval.ErrRequestNotFound
	}
	value := fixture.values[0]
	fixture.values = fixture.values[1:]
	return value, nil
}

func (fixture *approvalCatalogReaderFixture) ListApprovalRequests(
	_ context.Context,
	_ accountsession.Session,
	_ network.Scope,
	_ approval.State,
	_ approval.RequestID,
	_ int,
	evaluatedAt time.Time,
) ([]approval.Snapshot, error) {
	fixture.listCalls++
	fixture.permissionTime = evaluatedAt
	return append([]approval.Snapshot(nil), fixture.values...), nil
}

func approvalCatalogSnapshotFixture(t *testing.T, requestValue string) approval.Snapshot {
	t.Helper()
	requestID, _ := approval.ParseRequestID(requestValue)
	proposer, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	reason, _ := approval.NewAuditReason("reviewed simulation")
	createdAt := time.Date(2026, 9, 29, 2, 0, 0, 0, time.UTC)
	value, err := approval.NewSnapshot(approval.SnapshotParams{
		RequestID: requestID, Binding: approvalBindingFixture(t),
		ProposerPrincipalID: proposer, ProposalReason: reason,
		State: approval.StatePending, RequestVersion: 1,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(approval.RequestLifetime), UpdatedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
