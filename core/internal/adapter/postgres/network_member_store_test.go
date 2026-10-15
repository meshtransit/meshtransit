package postgres

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	testNetworkMemberNetwork = "01890f00-0000-7000-8000-000000000201"
	testNetworkMemberA       = "01890f00-0000-7000-8000-000000000501"
	testNetworkMemberB       = "01890f00-0000-7000-8000-000000000502"
	testNetworkMembershipA   = "01890f00-0000-7000-8000-000000000601"
	testNetworkMemberDevice  = "01890f00-0000-7000-8000-000000000701"
	testNetworkMemberDevice2 = "01890f00-0000-7000-8000-000000000702"
)

func testNetworkMemberScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID(testNetworkMemberNetwork)
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func mustPublicID(t *testing.T, text string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func decodeNetworkMemberFixture(t *testing.T, text string, target any) {
	t.Helper()
	if err := decodeIdentityCatalogJSON([]byte(text), target); err != nil {
		t.Fatalf("decode %s: %v", text, err)
	}
}

func membershipJSON(principal, state string, version int) string {
	encoded, _ := json.Marshal(map[string]any{
		"membership_id": testNetworkMembershipA, "principal_id": principal, "state": state, "version": version,
		"added_at": time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
	})
	return string(encoded)
}

func TestNetworkMemberEnvelopeDecode(t *testing.T) {
	t.Parallel()
	query := memberlifecycle.NetworkMemberQuery{Scope: testNetworkMemberScope(t), Limit: 2}
	member := func(principal, membership string) string {
		return `{"principal_id":"` + principal + `","display_name":"Person","workspace_membership_state":"active",` +
			`"owner":false,"network_membership":` + membership + `}`
	}
	for _, test := range []struct {
		name    string
		body    string
		after   string
		members int
		wantErr bool
	}{
		{name: "member and non-member", members: 2, body: `{"network_id":"` + testNetworkMemberNetwork +
			`","can_manage":true,"has_more":false,"members":[` + member(testNetworkMemberA,
			membershipJSON(testNetworkMemberA, "active", 1)) + `,` + member(testNetworkMemberB, "null") + `]}`},
		{name: "another Network", wantErr: true, body: `{"network_id":"` + testNetworkMemberA +
			`","can_manage":false,"has_more":false,"members":[]}`},
		{name: "out of order", wantErr: true, body: `{"network_id":"` + testNetworkMemberNetwork +
			`","can_manage":false,"has_more":false,"members":[` + member(testNetworkMemberB, "null") + `,` +
			member(testNetworkMemberA, "null") + `]}`},
		{name: "not after the cursor", after: testNetworkMemberA, wantErr: true, body: `{"network_id":"` +
			testNetworkMemberNetwork + `","can_manage":false,"has_more":false,"members":[` +
			member(testNetworkMemberA, "null") + `]}`},
		{name: "someone else's membership", wantErr: true, body: `{"network_id":"` + testNetworkMemberNetwork +
			`","can_manage":false,"has_more":false,"members":[` + member(testNetworkMemberA,
			membershipJSON(testNetworkMemberB, "active", 1)) + `]}`},
		{name: "revoked membership", wantErr: true, body: `{"network_id":"` + testNetworkMemberNetwork +
			`","can_manage":false,"has_more":false,"members":[` + member(testNetworkMemberA,
			membershipJSON(testNetworkMemberA, "revoked", 2)) + `]}`},
		{name: "more without members", wantErr: true, body: `{"network_id":"` + testNetworkMemberNetwork +
			`","can_manage":false,"has_more":true,"members":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			query := query
			if test.after != "" {
				query.After = mustPublicID(t, test.after)
			}
			var envelope networkMemberEnvelope
			decodeNetworkMemberFixture(t, test.body, &envelope)
			page, err := envelope.decode(query)
			if (err != nil) != test.wantErr || len(page.Members) != test.members {
				t.Fatalf("decode = %+v, %v", page, err)
			}
			if test.members == 2 && (page.Members[0].Membership == nil || page.Members[1].Membership != nil ||
				!page.CanManage) {
				t.Fatalf("page = %+v", page)
			}
		})
	}
	// Unknown fields are refused before decoding.
	if err := decodeIdentityCatalogJSON([]byte(`{"network_id":"x","extra":1}`), &networkMemberEnvelope{}); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestNetworkAdditionRecordDecode(t *testing.T) {
	t.Parallel()
	addition := memberlifecycle.NetworkAddition{
		Scope:     testNetworkMemberScope(t),
		MemberIDs: []publicid.ID{mustPublicID(t, testNetworkMemberA), mustPublicID(t, testNetworkMemberB)},
	}
	record := func(added, unchanged string, revision int) string {
		return `{"network_id":"` + testNetworkMemberNetwork + `","network_revision":` +
			strconv.Itoa(revision) + `,"added":` + added +
			`,"unchanged":` + unchanged + `,"authority":{"binding_generation":0,"membership_generation":1,` +
			`"owner_generation":1}}`
	}
	for _, test := range []struct {
		name    string
		body    string
		added   int
		wantErr bool
	}{
		{name: "one added one unchanged", added: 1, body: record(`[`+membershipJSON(testNetworkMemberA, "active", 1)+`]`,
			`["`+testNetworkMemberB+`"]`, 7)},
		{name: "both unchanged", body: record(`[]`, `["`+testNetworkMemberA+`","`+testNetworkMemberB+`"]`, 7)},
		{name: "member missing", wantErr: true, body: record(`[]`, `["`+testNetworkMemberA+`"]`, 7)},
		{name: "member twice", wantErr: true, body: record(`[`+membershipJSON(testNetworkMemberA, "active", 1)+`]`,
			`["`+testNetworkMemberA+`"]`, 7)},
		{name: "someone not asked for", wantErr: true, body: record(`[]`,
			`["`+testNetworkMemberA+`","`+testNetworkMembershipA+`"]`, 7)},
		{name: "not a new membership", wantErr: true, body: record(`[`+membershipJSON(testNetworkMemberA, "active", 2)+`]`,
			`["`+testNetworkMemberB+`"]`, 7)},
		{name: "no revision", wantErr: true, body: record(`[]`, `["`+testNetworkMemberA+`","`+testNetworkMemberB+`"]`, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var decoded networkAdditionRecord
			decodeNetworkMemberFixture(t, test.body, &decoded)
			result, err := decoded.decode(addition)
			if (err != nil) != test.wantErr || len(result.Added) != test.added {
				t.Fatalf("decode = %+v, %v", result, err)
			}
			if !test.wantErr && len(result.Added)+len(result.Unchanged) != 2 {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestNetworkRemovalRecordDecode(t *testing.T) {
	t.Parallel()
	member := mustPublicID(t, testNetworkMemberA)
	planned, _ := node.ParseID(testNetworkMemberDevice)
	removal := memberlifecycle.NetworkRemoval{
		Scope: testNetworkMemberScope(t), MemberID: member,
		Devices: []memberlifecycle.DevicePlan{{DeviceID: planned, Action: memberlifecycle.DeviceTransferWorkspace}},
	}
	device := func(id, action, state string) string {
		return `{"device_id":"` + id + `","hostname":"laptop","action":"` + action + `","state":"` + state + `"}`
	}
	network := func(id string) string {
		return `[{"network_id":"` + id + `","network_revision":9,"group_revision":4}]`
	}
	record := func(after, devices, networks string) string {
		return `{"before":` + membershipJSON(testNetworkMemberA, "active", 1) + `,"after":` + after +
			`,"devices":` + devices + `,"handovers_cancelled":1,"keys_revoked":0,"roles_revoked":1,"networks":` +
			networks + `,"authority":{"binding_generation":0,"membership_generation":1,"owner_generation":1}}`
	}
	revoked := membershipJSON(testNetworkMemberA, "revoked", 2)
	both := `[` + device(testNetworkMemberDevice, "transfer_workspace", "active") + `,` +
		device(testNetworkMemberDevice2, "revoke", "revoked") + `]`
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "planned and unnamed Devices", body: record(revoked, both, network(testNetworkMemberNetwork))},
		{name: "membership not revoked", wantErr: true,
			body: record(membershipJSON(testNetworkMemberA, "active", 2), both, network(testNetworkMemberNetwork))},
		{name: "unnamed Device kept", wantErr: true, body: record(revoked, `[`+
			device(testNetworkMemberDevice, "transfer_workspace", "active")+`,`+
			device(testNetworkMemberDevice2, "transfer_workspace", "active")+`]`, network(testNetworkMemberNetwork))},
		{name: "planned Device missing", wantErr: true, body: record(revoked, `[`+
			device(testNetworkMemberDevice2, "revoke", "revoked")+`]`, network(testNetworkMemberNetwork))},
		{name: "revoked Device still active", wantErr: true, body: record(revoked, `[`+
			device(testNetworkMemberDevice, "transfer_workspace", "active")+`,`+
			device(testNetworkMemberDevice2, "revoke", "active")+`]`, network(testNetworkMemberNetwork))},
		{name: "another Network advanced", wantErr: true, body: record(revoked, both, network(testNetworkMemberB))},
		{name: "no Network advanced", wantErr: true, body: record(revoked, both, `[]`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var decoded networkRemovalRecord
			decodeNetworkMemberFixture(t, test.body, &decoded)
			result, err := decoded.decode(removal)
			if (err != nil) != test.wantErr {
				t.Fatalf("decode = %+v, %v", result, err)
			}
			if err != nil && !errors.Is(err, memberlifecycle.ErrInvalid) {
				t.Fatalf("decode error = %v, want ErrInvalid", err)
			}
			if !test.wantErr && (len(result.Devices) != 2 || result.Network.NetworkRevision != 9 ||
				result.Devices[1].NetworkID != removal.Scope.NetworkID() || result.RolesRevoked != 1) {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestNetworkMemberStoreRefusesInvalidInput(t *testing.T) {
	t.Parallel()
	if _, err := NewNetworkMemberStore(nil, AccountSessionOptions{}); !errors.Is(err, memberlifecycle.ErrInvalid) {
		t.Fatalf("NewNetworkMemberStore(nil) = %v", err)
	}
	store := &NetworkMemberStore{}
	if _, err := store.ListNetworkMembers(t.Context(), memberlifecycle.NetworkMemberQuery{}); !errors.Is(err,
		memberlifecycle.ErrInvalid) {
		t.Fatalf("empty query = %v", err)
	}
	if _, err := store.AddNetworkMembers(t.Context(), memberlifecycle.NetworkAddition{}); !errors.Is(err,
		memberlifecycle.ErrInvalid) {
		t.Fatalf("empty addition = %v", err)
	}
	if _, err := store.RemoveNetworkMember(t.Context(), memberlifecycle.NetworkRemoval{}); !errors.Is(err,
		memberlifecycle.ErrInvalid) {
		t.Fatalf("empty removal = %v", err)
	}
}
