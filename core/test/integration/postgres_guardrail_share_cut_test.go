//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// TestPostgreSQLGuardrailShareCut qualifies schema 164 end to end on the
// database TestPostgreSQLMigrations prepared: one Device share from Network
// 203 into Network 204 (Workspace 103) is built through the production
// writers, as the share scale test does; then an enforce-mode guardrail that
// isolates 204 from 203 is previewed and saved. The save must echo the
// preview's hash, advance both Networks' revisions with Network-stream
// evidence and wakeups, and cut the share from the consumer's and the
// provider's maps; switching to audit mode or deleting restores it.
func TestPostgreSQLGuardrailShareCut(t *testing.T) {
	if os.Getenv("MESHTRANSIT_GUARDRAIL_SHARE_CUT") != "1" {
		t.Skip("set MESHTRANSIT_GUARDRAIL_SHARE_CUT=1 on a database TestPostgreSQLMigrations prepared")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	adminConfig := loadIntegrationAdminConfig(t)
	admin := openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database, adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile, adminConfig.ConnectTimeout)
	runtimePool := openShareScaleRuntimePool(ctx, t)
	workerPool := openIntegrationWorkerPool(ctx, t, adminConfig)

	providers, consumer, dualStack := seedShareScaleDevices(ctx, t, admin, 1)
	seedShareScaleAliasPools(ctx, t, admin, dualStack)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	session := shareScaleSession(ctx, t, admin)
	resources := createShareScaleResources(ctx, t, admin, runtimePool, session, providers)
	contracts := createShareScaleShares(ctx, t, runtimePool, session, resources)
	seedShareScaleRelease(ctx, t, admin, consumer, true)
	readyShareScaleAliases(ctx, t, admin, workerPool, consumer, contracts)
	share := contracts[0].ID()
	assertShareInMaps(ctx, t, runtimePool, providers[0], consumer, true)

	service := newIntegrationGuardrailService(t, runtimePool)
	workspaceID, _ := session.LoginWorkspaceID()
	isolation := guardrailShareCutIsolation(t, guardrail.ModeEnforce)
	impact, err := service.Preview(ctx, session, workspaceID, guardrail.Candidate{Spec: isolation})
	if err != nil {
		t.Fatalf("preview the isolation: %v", err)
	}
	// Earlier fixtures leave other active shares from 203 into 204; the
	// preview lists every one of them, the new share included.
	var active int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.trust_contract
WHERE provider_workspace_id = $1 AND provider_network_id = $2 AND consumer_network_id = $3
  AND state IN ('activating', 'active')`, shareScaleWorkspace, shareScaleProvider, shareScaleConsumer).Scan(
		&active); err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(impact.Affected, func(contract guardrail.ShareContract) bool {
		return contract.ID == publicid.ID(share)
	})
	if len(impact.Affected) != active || index < 0 || impact.Affected[index].Side != guardrail.SideBoth ||
		impact.Affected[index].Label != "Scale share 0" {
		t.Fatalf("preview = %+v, want the %d active shares from 203 into 204", impact, active)
	}

	// A save without the preview's hash, or with another impact's, is refused
	// and changes nothing.
	audit := guardrailShareCutIsolation(t, guardrail.ModeAudit)
	auditImpact, err := service.Preview(ctx, session, workspaceID, guardrail.Candidate{Spec: audit})
	if err != nil || len(auditImpact.Affected) != active || auditImpact.Hash == impact.Hash {
		t.Fatalf("audit preview = %+v, %v", auditImpact, err)
	}
	before := guardrailShareCutRevisions(ctx, t, admin)
	for name, hash := range map[string]guardrail.ImpactHash{"no hash": {}, "stale hash": auditImpact.Hash} {
		if _, err := service.Create(ctx, session, workspaceID, isolation, hash, newCorrelationID(t)); !errors.Is(err,
			guardrail.ErrImpactChanged) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if after := guardrailShareCutRevisions(ctx, t, admin); after != before {
		t.Fatalf("a refused save moved revisions %v -> %v", before, after)
	}

	created, err := service.Create(ctx, session, workspaceID, isolation, impact.Hash, newCorrelationID(t))
	if err != nil {
		t.Fatalf("enforce the isolation: %v", err)
	}
	cut := guardrailShareCutRevisions(ctx, t, admin)
	assertRevisionsAdvanced(t, before, cut)
	assertGuardrailShareEvidence(ctx, t, admin, created.Guardrail, cut, 1)
	assertShareInMaps(ctx, t, runtimePool, providers[0], consumer, false)
	assertBumpRechecksShares(ctx, t, admin, created.Guardrail.ID)

	// Audit mode only reports: the share comes back.
	audited, err := service.Update(ctx, session, workspaceID, created.Guardrail.ID, created.Guardrail.Version, audit,
		guardrail.ImpactHash{}, newCorrelationID(t))
	if err != nil {
		t.Fatalf("switch the isolation to audit: %v", err)
	}
	restored := guardrailShareCutRevisions(ctx, t, admin)
	assertRevisionsAdvanced(t, cut, restored)
	assertShareInMaps(ctx, t, runtimePool, providers[0], consumer, true)

	// Enforcing again needs a fresh preview of that update; deleting needs none.
	reEnforce := guardrail.Candidate{GuardrailID: audited.Guardrail.ID, ExpectedVersion: audited.Guardrail.Version,
		Spec: isolation}
	again, err := service.Update(ctx, session, workspaceID, audited.Guardrail.ID, audited.Guardrail.Version, isolation,
		previewImpact(ctx, t, service, session, workspaceID, reEnforce), newCorrelationID(t))
	if err != nil {
		t.Fatalf("enforce the isolation again: %v", err)
	}
	assertShareInMaps(ctx, t, runtimePool, providers[0], consumer, false)
	if _, err := service.Delete(ctx, session, workspaceID, again.Guardrail.ID, again.Guardrail.Version,
		newCorrelationID(t)); err != nil {
		t.Fatalf("delete the isolation: %v", err)
	}
	assertShareInMaps(ctx, t, runtimePool, providers[0], consumer, true)
	assertGuardrailShareEvidence(ctx, t, admin, again.Guardrail, guardrailShareCutRevisions(ctx, t, admin), 4)
	var contractState string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.trust_contract WHERE public_id = $1::UUID`,
		share.String()).Scan(&contractState); err != nil || contractState != "active" {
		t.Fatalf("the share's contract is %q (%v); a guardrail never changes it", contractState, err)
	}
	assertLooseningPastImpactLimit(ctx, t, runtimePool, session, workspaceID, isolation, audit,
		providers[0], consumer)
}

// assertBumpRechecksShares proves, as the runtime role inside a guardrail
// change of Workspace 103, that the bump compares the shares MeshCore
// evaluated with the active shares once it holds the revision locks: an
// evaluated set missing a share (one made after the read) or naming one no
// longer active fails with 40001; the exact set passes. The transaction
// rolls back.
func assertBumpRechecksShares(ctx context.Context, t *testing.T, admin *pgx.Conn, guardrailID publicid.ID) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, tx)
	change := newCorrelationID(t).String()
	for _, statement := range []string{
		`SELECT pg_catalog.set_config('mesh.change_public_id', '` + change + `', TRUE)`,
		`SELECT pg_catalog.set_config('mesh.workspace_id', '103', TRUE)`,
		`UPDATE mesh.guardrail SET version = version + 1, updated_at = clock_timestamp()
         WHERE public_id = '` + guardrailID.String() + `'`,
		`SET LOCAL ROLE mesh_runtime`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	var encoded string
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.guardrail_change_share_contracts_v2($1::UUID, 200000)::TEXT`,
		change).Scan(&encoded); err != nil {
		t.Fatalf("read the shares: %v", err)
	}
	var inventory struct {
		Contracts []struct {
			ID string `json:"trust_contract_id"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal([]byte(encoded), &inventory); err != nil || len(inventory.Contracts) < 2 {
		t.Fatalf("shares = %s (%v), want at least two", encoded, err)
	}
	ids := make([]string, len(inventory.Contracts))
	for index, contract := range inventory.Contracts {
		ids[index] = contract.ID
	}
	bump := func(changed, evaluated []string) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT bump`); err != nil {
			t.Fatal(err)
		}
		var heads string
		err := tx.QueryRow(ctx, `SELECT mesh_ops.bump_guardrail_share_networks_v2($1::UUID[], $2::UUID[], $3::UUID)::TEXT`,
			changed, evaluated, change).Scan(&heads)
		if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT bump`); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		return err
	}
	ended := append(slices.Clone(ids), newCorrelationID(t).String())
	for _, test := range []struct {
		name               string
		changed, evaluated []string
	}{
		{name: "a share made after the read", changed: ids[1:2], evaluated: ids[1:]},
		{name: "nothing changed, a share made", changed: []string{}, evaluated: ids[1:]},
		{name: "a share no longer active", changed: ids[:1], evaluated: ended},
		{name: "nothing changed, a share ended", changed: []string{}, evaluated: ended},
	} {
		t.Logf("bump recheck: %s", test.name)
		assertPostgreSQLCode(t, bump(test.changed, test.evaluated), "40001")
	}
	if err := bump(ids[:1], ids); err != nil {
		t.Fatalf("the exact shares were refused: %v", err)
	}
	if err := bump([]string{}, ids); err != nil {
		t.Fatalf("the exact shares with nothing changed were refused: %v", err)
	}
}

// assertLooseningPastImpactLimit uses a store whose preview bound (1) is
// below the active shares from 203 into 204: previewing or saving an
// enforce-mode guardrail is refused as too large, while switching one to
// audit and deleting it still work and restore the share.
func assertLooseningPastImpactLimit(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	session accountsession.Session, workspaceID workspace.ID, isolation, audit guardrail.Spec,
	provider, consumer shareScaleDevice) {
	t.Helper()
	store, err := postgresadapter.NewGuardrailStoreWithImpactLimit(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}, 1)
	if err != nil {
		t.Fatal(err)
	}
	limited, err := guardrail.NewService(store, accountsession.SystemClock{}, guardrail.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Preview(ctx, session, workspaceID, guardrail.Candidate{Spec: isolation}); !errors.Is(err,
		guardrail.ErrImpactTooLarge) {
		t.Fatalf("preview past the bound: %v", err)
	}
	service := newIntegrationGuardrailService(t, runtimePool)
	hash := previewImpact(ctx, t, service, session, workspaceID, guardrail.Candidate{Spec: isolation})
	if _, err := limited.Create(ctx, session, workspaceID, isolation, hash, newCorrelationID(t)); !errors.Is(err,
		guardrail.ErrImpactTooLarge) {
		t.Fatalf("enforce-mode save past the bound: %v", err)
	}
	created, err := service.Create(ctx, session, workspaceID, isolation, hash, newCorrelationID(t))
	if err != nil {
		t.Fatalf("enforce the isolation: %v", err)
	}
	assertShareInMaps(ctx, t, runtimePool, provider, consumer, false)
	audited, err := limited.Update(ctx, session, workspaceID, created.Guardrail.ID, created.Guardrail.Version, audit,
		guardrail.ImpactHash{}, newCorrelationID(t))
	if err != nil {
		t.Fatalf("switch to audit past the bound: %v", err)
	}
	assertShareInMaps(ctx, t, runtimePool, provider, consumer, true)
	if _, err := limited.Delete(ctx, session, workspaceID, audited.Guardrail.ID, audited.Guardrail.Version,
		newCorrelationID(t)); err != nil {
		t.Fatalf("delete past the bound: %v", err)
	}
}

// guardrailShareCutIsolation keeps Devices of Network 204 from reaching
// Devices of Network 203.
func guardrailShareCutIsolation(t *testing.T, mode guardrail.Mode) guardrail.Spec {
	t.Helper()
	provider, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := network.ParseID("01890f00-0000-7000-8000-000000000204")
	if err != nil {
		t.Fatal(err)
	}
	return guardrail.Spec{Kind: guardrail.KindNetworkIsolation, Name: "Staging never reaches production", Mode: mode,
		Isolation: guardrail.NetworkIsolationParams{From: []network.ID{consumer}, To: []network.ID{provider}}}
}

type guardrailShareCutRevision struct{ network, sharing int64 }

// guardrailShareCutRevisions reads the Network and sharing revisions of
// Networks 203 and 204.
func guardrailShareCutRevisions(ctx context.Context, t *testing.T, admin *pgx.Conn) [2]guardrailShareCutRevision {
	t.Helper()
	var revisions [2]guardrailShareCutRevision
	for index, networkID := range []int64{shareScaleProvider, shareScaleConsumer} {
		if err := admin.QueryRow(ctx, `SELECT network_revision, sharing_revision FROM mesh_ops.network_revision
WHERE workspace_id = $1 AND network_id = $2`, shareScaleWorkspace, networkID).Scan(
			&revisions[index].network, &revisions[index].sharing); err != nil {
			t.Fatal(err)
		}
	}
	return revisions
}

func assertRevisionsAdvanced(t *testing.T, before, after [2]guardrailShareCutRevision) {
	t.Helper()
	for index := range before {
		if after[index].network != before[index].network+1 || after[index].sharing != before[index].sharing+1 {
			t.Fatalf("revisions %v -> %v, want each advanced once", before, after)
		}
	}
}

// assertGuardrailShareEvidence checks each Network's stream recorded the
// change with the revision it advanced, and the wakeup for it, want times
// in all for this guardrail.
func assertGuardrailShareEvidence(ctx context.Context, t *testing.T, admin *pgx.Conn, rail guardrail.Guardrail,
	revisions [2]guardrailShareCutRevision, want int64) {
	t.Helper()
	for index, networkID := range []int64{shareScaleProvider, shareScaleConsumer} {
		var events, wakeups, latest int64
		if err := admin.QueryRow(ctx, `SELECT count(*), COALESCE(max((outbox.payload->>'network_revision')::BIGINT), 0),
    count(outbox.id)
FROM mesh_audit.audit_event AS event
JOIN mesh_audit.audit_event_identity AS identity
  ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
LEFT JOIN mesh_ops.outbox_event AS outbox
  ON outbox.change_public_id = identity.change_public_id AND outbox.network_id = event.network_id
 AND outbox.event_class = 'network.revision.advanced' AND outbox.aggregate_kind = 'guardrail'
WHERE event.workspace_id = $1 AND event.network_id = $2 AND event.target_kind = 'guardrail'
  AND event.target_public_id = $3::UUID AND event.action = 'guardrail.share_access_changed'`,
			shareScaleWorkspace, networkID, rail.ID.String()).Scan(&events, &latest, &wakeups); err != nil {
			t.Fatal(err)
		}
		if events != want || wakeups != want || latest != revisions[index].network {
			t.Fatalf("Network %d: %d events, %d wakeups, latest revision %d; want %d, %d, %d", networkID, events,
				wakeups, latest, want, want, revisions[index].network)
		}
	}
}

// assertShareInMaps loads the consumer's and the provider's maps and checks
// whether the share and its peer are in both.
func assertShareInMaps(ctx context.Context, t *testing.T, pool *postgresadapter.Pool, provider, consumer shareScaleDevice,
	present bool) {
	t.Helper()
	want := 0
	if present {
		want = 1
	}
	for name, device := range map[string]shareScaleDevice{"consumer": consumer, "provider": provider} {
		read := measureShareScaleMap(ctx, t, pool, device)
		if read.Projections != want {
			t.Fatalf("%s map has %d shares, want %d", name, read.Projections, want)
		}
	}
}
