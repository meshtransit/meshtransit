//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const privateFactoryRecoveryEvidence = "fixture://provider-recovery/unproven-v2"

func privateFactoryRouteGeneration(t *testing.T, route oidcauth.Route, generation int64) oidcauth.Route {
	t.Helper()
	updated, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: route.DeploymentID(), ProviderID: route.ProviderID(),
		ClientID: route.ClientID(), ProviderGeneration: generation,
		RecoveryEpoch: route.RecoveryEpoch(), Issuer: route.Issuer(), DiscoveryURI: route.DiscoveryURI(),
		AuthorizationEndpoint: route.AuthorizationEndpoint(), TokenEndpoint: route.TokenEndpoint(),
		JWKSURI: route.JWKSURI(), OIDCClientID: route.OIDCClientID(), ConnectorID: route.ConnectorID(), ClientKind: "confidential",
		ClientAuthMethod: route.ClientAuthMethod(), Scopes: route.Scopes(),
		AllowedAlgorithms: route.AllowedAlgorithms(), RedirectID: route.RedirectID(),
		RedirectURI: route.RedirectURI(), ReturnRouteID: route.ReturnRouteID(),
	})
	if err != nil {
		t.Fatal("construct recovery-generation route")
	}
	return updated
}

// quarantineFixtureProviderRecovery models the authority fence only. It is not
// a restore controller, continuity witness, or production recovery approval.
func (storage *privateFactoryIntegrationStorage) quarantineFixtureProviderRecovery(
	t *testing.T,
	route oidcauth.Route,
) {
	t.Helper()
	generationID, err := publicid.New()
	if err != nil {
		t.Fatal("generate recovery-generation identity")
	}
	payload := []byte(`{"generation":2,"recovery_mode":"unproven","recovery_state":"quarantined"}`)
	storage.commitFixtureProviderRecovery(t, route, 2, "identity_provider.recovery_quarantined",
		"meshtransit/fixture/provider-recovery/verified-generation-1", payload,
		func(ctx context.Context, tx pgx.Tx) {
			privateFactoryExec(ctx, t, tx, `UPDATE mesh.identity_provider_generation AS generation
SET state='revoked',valid_until=pg_catalog.transaction_timestamp(),version=2,
updated_at=GREATEST(generation.updated_at,pg_catalog.transaction_timestamp())
FROM mesh.identity_provider AS provider
WHERE provider.public_id=$1::UUID AND generation.identity_provider_id=provider.id
AND generation.generation=1 AND generation.state='current' AND generation.version=1`, route.ProviderID().String())
			privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.identity_provider_generation
(public_id,deployment_id,identity_provider_id,generation,trust_configuration_semantic_hash,
recovery_mode,recovery_evidence_reference,valid_from,state)
SELECT $1::UUID,provider.deployment_id,provider.id,2,generation.trust_configuration_semantic_hash,
'unproven',$2,pg_catalog.transaction_timestamp(),'current'
FROM mesh.identity_provider AS provider
JOIN mesh.identity_provider_generation AS generation ON generation.identity_provider_id=provider.id
WHERE provider.public_id=$3::UUID AND generation.generation=1 AND generation.state='revoked'`,
				generationID.String(), privateFactoryRecoveryEvidence, route.ProviderID().String())
			privateFactoryExec(ctx, t, tx, `UPDATE mesh.identity_provider
SET current_generation=2,recovery_state='quarantined',version=2,
updated_at=GREATEST(updated_at,pg_catalog.transaction_timestamp())
WHERE public_id=$1::UUID AND current_generation=1 AND recovery_state='verified' AND version=1`,
				route.ProviderID().String())
		})
}

// approveFixtureProviderRecovery models a separately authorized transition out
// of quarantine. The fixture does not manufacture continuity evidence.
func (storage *privateFactoryIntegrationStorage) approveFixtureProviderRecovery(
	t *testing.T,
	route oidcauth.Route,
) {
	t.Helper()
	payload := []byte(`{"generation":2,"recovery_mode":"unproven","recovery_state":"verified"}`)
	storage.commitFixtureProviderRecovery(t, route, 3, "identity_provider.recovery_verified",
		"meshtransit/fixture/provider-recovery/quarantined-generation-2", payload,
		func(ctx context.Context, tx pgx.Tx) {
			privateFactoryExec(ctx, t, tx, `UPDATE mesh.identity_provider
SET recovery_state='verified',version=3,
updated_at=GREATEST(updated_at,pg_catalog.transaction_timestamp())
WHERE public_id=$1::UUID AND current_generation=2 AND recovery_state='quarantined' AND version=2`,
				route.ProviderID().String())
		})
}

func (storage *privateFactoryIntegrationStorage) commitFixtureProviderRecovery(
	t *testing.T,
	route oidcauth.Route,
	version int64,
	action string,
	beforeMaterial string,
	payload []byte,
	mutate func(context.Context, pgx.Tx),
) {
	t.Helper()
	_, ids, err := (oidcauth.SystemStartIDs{}).NewStartIDs()
	if err != nil {
		t.Fatal("generate provider recovery evidence identities")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tx, err := storage.admin.Begin(ctx)
	if err != nil {
		t.Fatal("begin audited provider recovery fixture mutation")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("rollback provider recovery fixture mutation")
		}
	}()
	if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('mesh.change_public_id',$1,TRUE)", ids.ChangeID().String()); err != nil {
		t.Fatal("bind provider recovery fixture mutation identity")
	}
	mutate(ctx, tx)
	var sequence, appended int64
	var previous []byte
	if tx.QueryRow(ctx, `SELECT next_sequence,latest_event_hash FROM mesh_audit.audit_stream
WHERE id=1 AND deployment_id=1 AND scope_kind='deployment' FOR UPDATE`).Scan(&sequence, &previous) != nil ||
		len(previous) != sha256.Size {
		t.Fatal("lock provider recovery fixture audit head")
	}
	before, after := sha256.Sum256([]byte(beforeMaterial)), sha256.Sum256(payload)
	var previousHash [sha256.Size]byte
	copy(previousHash[:], previous)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: ids.AuditEventID(), ChangeID: ids.ChangeID(),
		AggregateKind: "identity_provider", AggregateID: publicid.ID(route.ProviderID()),
		AggregateVersion: version, ActorPrincipalID: privateIdentityID(t, 2), Action: action,
		Permission: "identity_provider.manage", BeforeSemanticHash: before, AfterSemanticHash: after,
		AuditPayloadHash: sha256.Sum256(payload), OutboxEventClass: action,
		OutboxPayloadHash: sha256.Sum256(payload),
	})
	if err != nil {
		t.Fatal("prepare canonical provider recovery fixture evidence")
	}
	scanErr := tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
1,$1::UUID,$2::UUID,$3::BIGINT,$4::BYTEA,$5::BYTEA,'identity_provider',$6::UUID,$7::BIGINT,
NULL::BIGINT,$8::UUID,$9::TEXT,'identity_provider.manage',NULL::UUID,$10::BYTEA,$11::BYTEA,$12::JSONB,
$9::TEXT,$12::JSONB)`, ids.AuditEventID().String(), ids.OutboxEventID().String(), sequence, previous,
		eventHash[:], route.ProviderID().String(), version, privateIdentityID(t, 2).String(), action,
		before[:], after[:], payload).Scan(&appended)
	if scanErr != nil || appended != sequence {
		t.Fatal("append exact provider recovery fixture evidence")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit audited provider recovery fixture mutation")
	}
}

func (storage *privateFactoryIntegrationStorage) assertFixtureProviderRecovery(
	t *testing.T,
	route oidcauth.Route,
	recoveryState string,
	providerVersion int64,
	oldSessionID string,
	pendingTransactionID string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var exact bool
	err := storage.admin.QueryRow(ctx, `SELECT
provider.current_generation=2 AND provider.recovery_state=$2 AND provider.version=$3
AND old_generation.state='revoked' AND old_generation.version=2 AND old_generation.valid_until IS NOT NULL
AND old_generation.recovery_mode='initial' AND old_generation.recovery_evidence_reference IS NULL
AND new_generation.state='current' AND new_generation.version=1 AND new_generation.valid_until IS NULL
AND new_generation.recovery_mode='unproven' AND new_generation.recovery_evidence_reference=$4
AND session.state='active' AND session.version=1 AND session.provider_generation=1
AND auth.state='pending' AND auth.version=1 AND auth.provider_generation=1
AND auth.consumed_at IS NULL AND auth.failure_class IS NULL
AND auth.pkce_verifier_encryption_algorithm IS NOT NULL
AND auth.pkce_verifier_encryption_key_id IS NOT NULL AND auth.pkce_verifier_ciphertext IS NOT NULL
FROM mesh.identity_provider AS provider
JOIN mesh.identity_provider_generation AS old_generation
  ON old_generation.identity_provider_id=provider.id AND old_generation.generation=1
JOIN mesh.identity_provider_generation AS new_generation
  ON new_generation.identity_provider_id=provider.id AND new_generation.generation=2
JOIN mesh.account_session AS session ON session.identity_provider_id=provider.id
JOIN mesh.auth_transaction AS auth ON auth.identity_provider_id=provider.id
WHERE provider.public_id=$1::UUID AND session.public_id=$5::UUID AND auth.public_id=$6::UUID`,
		route.ProviderID().String(), recoveryState, providerVersion, privateFactoryRecoveryEvidence,
		oldSessionID, pendingTransactionID).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("provider recovery fence lost exact generation or retained-authority evidence")
	}
}
