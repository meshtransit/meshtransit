package memberlifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type recordingNetworkStore struct {
	queries   []memberlifecycle.NetworkMemberQuery
	additions []memberlifecycle.NetworkAddition
	removals  []memberlifecycle.NetworkRemoval
}

func (store *recordingNetworkStore) ListNetworkMembers(_ context.Context, query memberlifecycle.NetworkMemberQuery) (
	memberlifecycle.NetworkMemberPage, error) {
	store.queries = append(store.queries, query)
	return memberlifecycle.NetworkMemberPage{}, nil
}

func (store *recordingNetworkStore) AddNetworkMembers(_ context.Context, addition memberlifecycle.NetworkAddition) (
	memberlifecycle.NetworkAdditionResult, error) {
	store.additions = append(store.additions, addition)
	return memberlifecycle.NetworkAdditionResult{}, nil
}

func (store *recordingNetworkStore) RemoveNetworkMember(_ context.Context, removal memberlifecycle.NetworkRemoval) (
	memberlifecycle.NetworkRemovalResult, error) {
	store.removals = append(store.removals, removal)
	return memberlifecycle.NetworkRemovalResult{}, nil
}

func testScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func memberIDs(t *testing.T, count int) []publicid.ID {
	t.Helper()
	ids := make([]publicid.ID, count)
	for index := range ids {
		id, err := publicid.Parse(fmt.Sprintf("01890f00-0000-7000-8000-%012d", 500+index))
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = id
	}
	return ids
}

func TestNetworkServiceBoundsListing(t *testing.T) {
	t.Parallel()
	session := testSession(t)
	for _, test := range []struct {
		name  string
		limit int
		want  error
	}{
		{name: "one", limit: 1},
		{name: "maximum", limit: memberlifecycle.MaximumNetworkMemberPage},
		{name: "zero", limit: 0, want: memberlifecycle.ErrInvalid},
		{name: "over the maximum", limit: memberlifecycle.MaximumNetworkMemberPage + 1, want: memberlifecycle.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingNetworkStore{}
			service, err := memberlifecycle.NewNetworkService(store, fixedClock{now: testNow})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.List(context.Background(), session, testScope(t), publicid.ID{}, test.limit)
			if !errors.Is(err, test.want) {
				t.Fatalf("List = %v, want %v", err, test.want)
			}
			if test.want == nil && len(store.queries) != 1 {
				t.Fatalf("store saw %+v", store.queries)
			}
		})
	}
}

func TestNetworkServiceValidatesAdditions(t *testing.T) {
	t.Parallel()
	session := testSession(t)
	correlation, _ := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	duplicate := memberIDs(t, 2)
	duplicate[1] = duplicate[0]
	for _, test := range []struct {
		name    string
		members []publicid.ID
		want    error
	}{
		{name: "one", members: memberIDs(t, 1)},
		{name: "maximum", members: memberIDs(t, memberlifecycle.MaximumNetworkAdditions)},
		{name: "none", members: nil, want: memberlifecycle.ErrInvalid},
		{name: "too many", members: memberIDs(t, memberlifecycle.MaximumNetworkAdditions+1),
			want: memberlifecycle.ErrInvalid},
		{name: "duplicate", members: duplicate, want: memberlifecycle.ErrInvalid},
		{name: "zero ID", members: []publicid.ID{{}}, want: memberlifecycle.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingNetworkStore{}
			service, _ := memberlifecycle.NewNetworkService(store, fixedClock{now: testNow})
			members := append([]publicid.ID(nil), test.members...)
			_, err := service.Add(context.Background(), session, testScope(t), members, correlation)
			if !errors.Is(err, test.want) {
				t.Fatalf("Add = %v, want %v", err, test.want)
			}
			if test.want != nil {
				if len(store.additions) != 0 {
					t.Fatal("an invalid addition reached the store")
				}
				return
			}
			if len(store.additions) != 1 {
				t.Fatalf("store saw %+v", store.additions)
			}
			// The service owns its copy of the members.
			members[0] = publicid.ID{}
			if !store.additions[0].MemberIDs[0].IsValid() {
				t.Fatal("the addition shares the caller's slice")
			}
		})
	}
}

func TestNetworkServiceValidatesRemovals(t *testing.T) {
	t.Parallel()
	session := testSession(t)
	member, _ := publicid.Parse("01890f00-0000-7000-8000-000000000402")
	correlation, _ := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000701")
	for _, test := range []struct {
		name   string
		reason string
		plan   []memberlifecycle.DevicePlan
		want   error
	}{
		{name: "no Devices", reason: "Moved team"},
		{name: "planned Device", reason: "Moved team",
			plan: []memberlifecycle.DevicePlan{{DeviceID: device, Action: memberlifecycle.DeviceTransferWorkspace}}},
		{name: "no reason", want: memberlifecycle.ErrInvalid},
		{name: "Device to the member themselves", reason: "Moved team", want: memberlifecycle.ErrInvalid,
			plan: []memberlifecycle.DevicePlan{{DeviceID: device, Action: memberlifecycle.DeviceTransferMember,
				NewOwnerID: member}}},
		{name: "Device named twice", reason: "Moved team", want: memberlifecycle.ErrInvalid,
			plan: []memberlifecycle.DevicePlan{{DeviceID: device, Action: memberlifecycle.DeviceRevoke},
				{DeviceID: device, Action: memberlifecycle.DeviceTransferWorkspace}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingNetworkStore{}
			service, _ := memberlifecycle.NewNetworkService(store, fixedClock{now: testNow})
			_, err := service.Remove(context.Background(), session, memberlifecycle.NetworkRemovalRequest{
				Scope: testScope(t), MemberID: member, Reason: test.reason, Devices: test.plan,
				CorrelationID: correlation,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Remove = %v, want %v", err, test.want)
			}
			if (test.want == nil) != (len(store.removals) == 1) {
				t.Fatalf("store saw %+v", store.removals)
			}
		})
	}
}

func TestNetworkServiceRefusesExpiredSessions(t *testing.T) {
	t.Parallel()
	store := &recordingNetworkStore{}
	service, _ := memberlifecycle.NewNetworkService(store, fixedClock{now: testNow.Add(3 * 60 * 60 * 1e9)})
	_, err := service.List(context.Background(), testSession(t), testScope(t), publicid.ID{}, 10)
	if !errors.Is(err, memberlifecycle.ErrForbidden) || len(store.queries) != 0 {
		t.Fatalf("expired session listed members: %v", err)
	}
	if _, err := memberlifecycle.NewNetworkService(nil, fixedClock{}); !errors.Is(err, memberlifecycle.ErrInvalid) {
		t.Fatalf("NewNetworkService(nil) = %v", err)
	}
}
