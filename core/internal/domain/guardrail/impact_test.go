package guardrail_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// impactFixture: our Workspace shares production out to staging (same
// Workspace), production out to a stranger, and receives from a partner.
type impactFixture struct {
	fixture
	internal, outgoing, incoming guardrail.ShareContract
	contracts                    []guardrail.ShareContract
}

func newImpactFixture(t *testing.T) impactFixture {
	t.Helper()
	f := impactFixture{fixture: newFixture(t)}
	f.internal = guardrail.ShareContract{ID: id(t), Side: guardrail.SideBoth, NetworkID: f.production, Label: "internal",
		Edge: guardrail.ShareEdge{Provider: scope(t, f.ours, f.production), Consumer: scope(t, f.ours, f.staging)}}
	f.outgoing = guardrail.ShareContract{ID: id(t), Side: guardrail.SideProvider, NetworkID: f.production, Label: "out",
		Edge: guardrail.ShareEdge{Provider: scope(t, f.ours, f.production), Consumer: scope(t, f.stranger, f.strangerNet)}}
	f.incoming = guardrail.ShareContract{ID: id(t), Side: guardrail.SideConsumer, NetworkID: f.staging, Label: "in",
		Edge: guardrail.ShareEdge{Provider: scope(t, f.partner, f.partnerNet), Consumer: scope(t, f.ours, f.staging)}}
	f.contracts = []guardrail.ShareContract{f.internal, f.outgoing, f.incoming}
	return f
}

func sharingLock(networks []network.ID, direction guardrail.Direction, mode guardrail.Mode) guardrail.Spec {
	return guardrail.Spec{Kind: guardrail.KindNetworkSharing, Name: "Lock", Mode: mode,
		Sharing: guardrail.NetworkSharingParams{Networks: networks, Direction: direction}}
}

func affectedIDs(impact guardrail.Impact) map[publicid.ID]bool {
	ids := map[publicid.ID]bool{}
	for _, contract := range impact.Affected {
		ids[contract.ID] = true
	}
	return ids
}

func TestComputeImpact(t *testing.T) {
	t.Parallel()
	f := newImpactFixture(t)
	outOfProduction := sharingLock([]network.ID{f.production}, guardrail.DirectionOutgoing, guardrail.ModeEnforce)
	external := guardrail.Spec{Kind: guardrail.KindExternalSharing, Name: "No external", Mode: guardrail.ModeEnforce,
		External: guardrail.ExternalSharingParams{Direction: guardrail.DirectionOutgoing}}
	alreadyCut := rail(t, external)
	auditOnly := rail(t, sharingLock([]network.ID{f.staging}, guardrail.DirectionIncoming, guardrail.ModeAudit))

	cases := []struct {
		name      string
		before    []guardrail.Guardrail
		candidate guardrail.Candidate
		want      []guardrail.ShareContract
	}{
		{name: "enforce cuts both shares out of production",
			candidate: guardrail.Candidate{Spec: outOfProduction}, want: []guardrail.ShareContract{f.internal, f.outgoing}},
		{name: "a share already cut is not cut again", before: []guardrail.Guardrail{alreadyCut},
			candidate: guardrail.Candidate{Spec: outOfProduction}, want: []guardrail.ShareContract{f.internal}},
		{name: "an audit guardrail cuts nothing, so its shares count", before: []guardrail.Guardrail{auditOnly},
			candidate: guardrail.Candidate{Spec: sharingLock([]network.ID{f.staging}, guardrail.DirectionIncoming,
				guardrail.ModeEnforce)}, want: []guardrail.ShareContract{f.internal, f.incoming}},
		{name: "consumer side: incoming lock cuts the received share",
			candidate: guardrail.Candidate{Spec: guardrail.Spec{Kind: guardrail.KindExternalSharing, Name: "In",
				Mode: guardrail.ModeEnforce, External: guardrail.ExternalSharingParams{Direction: guardrail.DirectionIncoming}}},
			want: []guardrail.ShareContract{f.incoming}},
		{name: "replacing the guardrail that cuts a share keeps it cut", before: []guardrail.Guardrail{alreadyCut},
			candidate: guardrail.Candidate{GuardrailID: alreadyCut.ID, ExpectedVersion: 1, Spec: guardrail.Spec{
				Kind: guardrail.KindExternalSharing, Name: "Renamed", Mode: guardrail.ModeEnforce,
				External: guardrail.ExternalSharingParams{Direction: guardrail.DirectionOutgoing}}}},
		{name: "audit mode lists violations, cut or not", before: []guardrail.Guardrail{alreadyCut},
			candidate: guardrail.Candidate{Spec: sharingLock([]network.ID{f.production}, guardrail.DirectionOutgoing,
				guardrail.ModeAudit)}, want: []guardrail.ShareContract{f.internal, f.outgoing}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			impact, err := guardrail.ComputeImpact(f.ours, test.before, test.candidate, f.contracts)
			if err != nil {
				t.Fatal(err)
			}
			got := affectedIDs(impact)
			if len(got) != len(test.want) || impact.Mode != test.candidate.Spec.Mode || impact.Hash.IsZero() {
				t.Fatalf("impact = %+v, want %d shares", impact, len(test.want))
			}
			for _, contract := range test.want {
				if !got[contract.ID] {
					t.Fatalf("impact misses %s (%s)", contract.Label, contract.ID)
				}
			}
			for index := 1; index < len(impact.Affected); index++ {
				if impact.Affected[index-1].ID.String() >= impact.Affected[index].ID.String() {
					t.Fatal("affected shares are not ordered by ID")
				}
			}
		})
	}
}

func TestImpactHashIsStable(t *testing.T) {
	t.Parallel()
	f := newImpactFixture(t)
	spec := sharingLock([]network.ID{f.production}, guardrail.DirectionOutgoing, guardrail.ModeEnforce)
	first, err := guardrail.ComputeImpact(f.ours, nil, guardrail.Candidate{Spec: spec}, f.contracts)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []guardrail.ShareContract{f.incoming, f.outgoing, f.internal}
	renamed := spec
	renamed.Name, renamed.Description = "Another name", "described"
	second, err := guardrail.ComputeImpact(f.ours, nil, guardrail.Candidate{Spec: renamed}, reversed)
	if err != nil || second.Hash != first.Hash {
		t.Fatalf("hash depends on order or name: %s vs %s (%v)", first.Hash, second.Hash, err)
	}
	parsed, err := guardrail.ParseImpactHash(first.Hash.String())
	if err != nil || parsed != first.Hash {
		t.Fatalf("ParseImpactHash round trip = %s, %v", parsed, err)
	}
	// One share fewer, or a different meaning, gives another hash.
	fewer, _ := guardrail.ComputeImpact(f.ours, nil, guardrail.Candidate{Spec: spec}, f.contracts[1:])
	both := spec
	both.Sharing.Direction = guardrail.DirectionBoth
	wider, _ := guardrail.ComputeImpact(f.ours, nil, guardrail.Candidate{Spec: both}, f.contracts)
	if fewer.Hash == first.Hash || wider.Hash == first.Hash {
		t.Fatal("hash does not commit to the shares and the semantic hash")
	}
	for _, text := range []string{"", "00", first.Hash.String() + "00", "G" + first.Hash.String()[1:],
		"AB" + first.Hash.String()[2:]} {
		if _, err := guardrail.ParseImpactHash(text); !errors.Is(err, guardrail.ErrInvalid) {
			t.Errorf("ParseImpactHash(%q) accepted", text)
		}
	}
}

func TestComputeImpactRejectsForeignContracts(t *testing.T) {
	t.Parallel()
	f := newImpactFixture(t)
	spec := sharingLock([]network.ID{f.production}, guardrail.DirectionOutgoing, guardrail.ModeEnforce)
	wrongSide := f.outgoing
	wrongSide.Side = guardrail.SideConsumer
	foreign := f.incoming
	foreign.Edge.Consumer = scope(t, f.stranger, f.strangerNet)
	for name, contract := range map[string]guardrail.ShareContract{"wrong side": wrongSide, "not ours": foreign} {
		if _, err := guardrail.ComputeImpact(f.ours, nil, guardrail.Candidate{Spec: spec},
			[]guardrail.ShareContract{contract}); !errors.Is(err, guardrail.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestChangedShares(t *testing.T) {
	t.Parallel()
	f := newImpactFixture(t)
	enforce := rail(t, sharingLock([]network.ID{f.production}, guardrail.DirectionOutgoing, guardrail.ModeEnforce))
	audit := enforce
	audit.Mode = guardrail.ModeAudit
	cut := guardrail.ChangedShares(f.ours, nil, []guardrail.Guardrail{enforce}, f.contracts)
	restored := guardrail.ChangedShares(f.ours, []guardrail.Guardrail{enforce}, []guardrail.Guardrail{audit}, f.contracts)
	unchanged := guardrail.ChangedShares(f.ours, nil, []guardrail.Guardrail{audit}, f.contracts)
	if len(cut) != 2 || len(restored) != 2 || len(unchanged) != 0 {
		t.Fatalf("cut %d, restored %d, unchanged %d; want 2, 2, 0", len(cut), len(restored), len(unchanged))
	}
}

func TestParseEnforced(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	spec := sharingLock([]network.ID{f.production}, guardrail.DirectionOutgoing, guardrail.ModeAudit)
	params, err := spec.ParamsDocument()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := guardrail.ParseEnforced(guardrail.KindNetworkSharing, params)
	if err != nil || parsed.Mode != guardrail.ModeEnforce || !guardrail.Blocks([]guardrail.Guardrail{parsed}, f.ours,
		guardrail.ShareEdge{Provider: scope(t, f.ours, f.production), Consumer: scope(t, f.ours, f.staging)}) {
		t.Fatalf("ParseEnforced = %+v, %v", parsed, err)
	}
	for name, raw := range map[string]string{
		"no networks":   `{"networks":[],"direction":"outgoing"}`,
		"bad network":   `{"networks":["x"],"direction":"outgoing"}`,
		"bad direction": `{"networks":["` + f.production.String() + `"],"direction":"sideways"}`,
	} {
		if _, err := guardrail.ParseEnforced(guardrail.KindNetworkSharing, []byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := guardrail.ParseEnforced("posture", params); err == nil {
		t.Error("unknown kind accepted")
	}
}

type impactStore struct {
	inventory guardrail.ShareInventory
	changes   []guardrail.Change
}

func (store *impactStore) List(context.Context, accountsession.Session, workspace.ID) (guardrail.Listing, error) {
	return guardrail.Listing{Guardrails: store.inventory.Guardrails}, nil
}

func (store *impactStore) Change(_ context.Context, change guardrail.Change) (guardrail.Result, error) {
	store.changes = append(store.changes, change)
	return guardrail.Result{}, nil
}

func (store *impactStore) ShareInventory(context.Context, accountsession.Session, workspace.ID) (guardrail.ShareInventory, error) {
	return store.inventory, nil
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func activeSession(t *testing.T, workspaceID workspace.ID, now time.Time) accountsession.Session {
	t.Helper()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: accountsession.ID(id(t)), DeploymentID: deployment.ID(id(t)), PrincipalID: identity.PrincipalID(id(t)),
		IdentitySubjectID: accountsession.IdentitySubjectID(id(t)), LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Minute), ACR: "urn:meshtransit:assurance:mfa", AMR: []string{"pwd", "mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1, ProviderGeneration: 1,
		DeploymentRecoveryEpoch: 1, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestServicePreviewAndImpactRequirement(t *testing.T) {
	t.Parallel()
	f := newImpactFixture(t)
	now := time.Now().UTC()
	existing := rail(t, sharingLock([]network.ID{f.production}, guardrail.DirectionOutgoing, guardrail.ModeAudit))
	store := &impactStore{inventory: guardrail.ShareInventory{Guardrails: []guardrail.Guardrail{existing},
		Contracts: f.contracts}}
	service, err := guardrail.NewService(store, fixedClock{now}, guardrail.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, f.ours, now)
	enforced := existing.Spec
	enforced.Mode = guardrail.ModeEnforce
	impact, err := service.Preview(t.Context(), session, f.ours,
		guardrail.Candidate{GuardrailID: existing.ID, ExpectedVersion: 1, Spec: enforced})
	if err != nil || len(impact.Affected) != 2 {
		t.Fatalf("preview = %+v, %v", impact, err)
	}
	for name, candidate := range map[string]struct {
		candidate guardrail.Candidate
		want      error
	}{
		"stale version": {guardrail.Candidate{GuardrailID: existing.ID, ExpectedVersion: 2, Spec: enforced},
			guardrail.ErrVersionConflict},
		"unknown":        {guardrail.Candidate{GuardrailID: id(t), ExpectedVersion: 1, Spec: enforced}, guardrail.ErrNotFound},
		"version alone":  {guardrail.Candidate{ExpectedVersion: 1, Spec: enforced}, guardrail.ErrInvalid},
		"id without one": {guardrail.Candidate{GuardrailID: existing.ID, Spec: enforced}, guardrail.ErrInvalid},
	} {
		if _, err := service.Preview(t.Context(), session, f.ours, candidate.candidate); !errors.Is(err, candidate.want) {
			t.Errorf("%s: %v, want %v", name, err, candidate.want)
		}
	}
	// The store checks the hash after it authorizes the change, so a caller
	// without permission learns nothing about shares: the service passes
	// the hash, given or not, to the store.
	if _, err := service.Update(t.Context(), session, f.ours, existing.ID, 1, enforced, impact.Hash, id(t)); err != nil ||
		len(store.changes) != 1 || store.changes[0].ImpactHash != impact.Hash {
		t.Fatalf("enforce update with the hash: %v, %+v", err, store.changes)
	}
	if _, err := service.Create(t.Context(), session, f.ours, enforced, guardrail.ImpactHash{}, id(t)); err != nil ||
		len(store.changes) != 2 || !store.changes[1].ImpactHash.IsZero() {
		t.Fatalf("create without a hash: %v, %+v", err, store.changes)
	}
}
