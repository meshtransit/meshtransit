//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func (storage *privateFactoryIntegrationStorage) seedAccount(t *testing.T) {
	t.Helper()
	storage.seed(t, "account", privateIdentityID(t, 3).String(), func(ctx context.Context, tx pgx.Tx) {
		privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.account
(public_id,deployment_id,principal_id,display_name,session_generation,recovery_state)
VALUES ($1::UUID,1,11,'Private callback fixture',1,'verified')`, privateIdentityID(t, 3).String())
	})
}

func (storage *privateFactoryIntegrationStorage) seedLoginSubject(
	t *testing.T,
	fixture *privateIdentityFixture,
	suffix byte,
	subject string,
	membership bool,
) {
	t.Helper()
	// Independently encode canonical doc 26 using the actual loaded synthetic
	// subject material. No ExternalIdentity constructor or provider-port override.
	files, _, _ := privateIdentityCompositionFixture(t, true)
	keys, err := composePrivateIdentityKeys(t.Context(), files)
	if err != nil {
		t.Fatal("compose fixture resident owners")
	}
	fixture.keys = keys
	material, err := files.Load(t.Context())
	if err != nil {
		t.Fatal("load independent fixture seed material")
	}
	defer material.Clear()
	route := fixture.options.Route
	input, err := privateFactorySubjectInput(route, material.SubjectActive.ID, subject)
	if err != nil {
		t.Fatal("invalid canonical fixture subject input")
	}
	mac := hmac.New(sha256.New, material.SubjectActive.Bytes[:])
	_, _ = mac.Write(input)
	clear(input)
	storage.seed(t, "identity_subject", privateIdentityID(t, suffix+3).String(), func(ctx context.Context, tx pgx.Tx) {
		privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.identity_subject
(public_id,deployment_id,identity_provider_id,principal_id,subject_digest_algorithm,subject_digest_key_id,
subject_digest,claims_revision,last_seen_at,state)
SELECT $1::UUID,1,id,11,'hmac-sha256-v1',$2,$3,1,pg_catalog.transaction_timestamp(),'active'
FROM mesh.identity_provider WHERE public_id=$4::UUID`,
			privateIdentityID(t, suffix+3).String(), material.SubjectActive.ID, mac.Sum(nil), route.ProviderID().String())
	})
	if membership {
		storage.seed(t, "workspace_membership", privateIdentityID(t, suffix+4).String(), func(ctx context.Context, tx pgx.Tx) {
			privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.workspace_membership
(public_id,deployment_id,workspace_id,principal_id,state,authority_generation,valid_from)
SELECT $1::UUID,1,id,11,'active',1,pg_catalog.transaction_timestamp()-INTERVAL '1 minute'
FROM mesh.workspace WHERE public_id=$2::UUID`, privateIdentityID(t, suffix+4).String(), route.WorkspaceID().String())
		})
	}
}

func privateFactorySubjectInput(route oidcauth.Route, keyID, subject string) ([]byte, error) {
	input := []byte("meshtransit/oidc-auth/identity-subject/v1\x00")
	deploymentBytes, providerBytes := route.DeploymentID().Bytes(), route.ProviderID().Bytes()
	input = append(input, deploymentBytes[:]...)
	input = append(input, providerBytes[:]...)
	for _, value := range []string{keyID, route.Issuer(), subject} {
		length := len(value)
		if length <= 0 || length > 65535 {
			clear(input)
			return nil, errInvalidPrivateIdentityComposition
		}
		input = binary.BigEndian.AppendUint16(input, uint16(length))
		input = append(input, value...)
	}
	return input, nil
}

func (storage *privateFactoryIntegrationStorage) subjectLastSeen(t *testing.T, suffix byte) time.Time {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var seen time.Time
	if err := storage.admin.QueryRow(ctx, `SELECT last_seen_at FROM mesh.identity_subject WHERE public_id=$1::UUID`,
		privateIdentityID(t, suffix+3).String()).Scan(&seen); err != nil {
		t.Fatal("read exact subject last-seen")
	}
	return seen
}

func (storage *privateFactoryIntegrationStorage) assertCallbackTerminal(
	t *testing.T,
	transactionID string,
	session accountsession.Session,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	state, failure, resultKind, resultID := "failed", "authentication_failed", "", ""
	if session.IsValid() {
		state, failure, resultKind, resultID = "succeeded", "", "account_session", session.ID().String()
	}
	var exact bool
	if err := storage.admin.QueryRow(ctx, `SELECT operation_kind='login' AND principal_id IS NULL
AND state=$2 AND version=3 AND COALESCE(failure_class,'')=$3 AND consumed_at IS NOT NULL
AND pkce_verifier_encryption_algorithm IS NULL AND pkce_verifier_encryption_key_id IS NULL
AND pkce_verifier_ciphertext IS NULL AND COALESCE(consumed_result_kind,'')=$4
AND COALESCE(consumed_result_public_id::TEXT,'')=$5
FROM mesh.auth_transaction WHERE public_id=$1::UUID`,
		transactionID, state, failure, resultKind, resultID).Scan(&exact); err != nil || !exact {
		t.Fatal("terminal anonymous login lost exact version/proof/result binding")
	}
	storage.assertCallbackEvidence(t, transactionID, resultID)
}

func (storage *privateFactoryIntegrationStorage) assertCallbackEvidence(t *testing.T, transactionID, sessionID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rows, err := storage.admin.Query(ctx, `SELECT i.stream_sequence,i.change_public_id::TEXT,
i.previous_event_hash,i.event_hash,e.target_public_id::TEXT,e.action,o.aggregate_version,
o.event_class,o.network_revision IS NULL,e.actor_principal_public_id IS NULL,e.permission
FROM mesh_audit.audit_event_identity i
JOIN mesh_audit.audit_event e ON e.event_identity_id=i.id AND e.occurred_at=i.occurred_at
JOIN mesh_ops.outbox_event o ON o.change_public_id=i.change_public_id
AND o.aggregate_public_id=e.target_public_id AND o.aggregate_kind=e.target_kind
WHERE e.target_public_id::TEXT IN ($1,$2) AND e.action<>'auth_transaction.created'
ORDER BY i.stream_sequence`, transactionID, sessionID)
	if err != nil {
		t.Fatal("read exact callback lifecycle evidence")
	}
	defer rows.Close()
	wanted := []string{"auth_transaction.claimed", "auth_transaction.terminated"}
	versions := []int64{2, 3}
	if sessionID != "" {
		wanted = []string{"auth_transaction.claimed", "account_session.created", "auth_transaction.succeeded"}
		versions = []int64{2, 1, 3}
	}
	var lastSequence int64
	var lastHash []byte
	var lastChange string
	index := 0
	for rows.Next() {
		var sequence, version int64
		var change, target, action, class, permission string
		var previous, hash []byte
		var noRevision, anonymous bool
		if err := rows.Scan(&sequence, &change, &previous, &hash, &target, &action, &version,
			&class, &noRevision, &anonymous, &permission); err != nil {
			t.Fatal("decode callback evidence")
		}
		if index >= len(wanted) {
			t.Fatal("duplicate callback evidence")
		}
		expectedTarget := transactionID
		if action == "account_session.created" {
			expectedTarget = sessionID
		}
		wrongEvent := action != wanted[index] || version != versions[index] || target != expectedTarget
		wrongMetadata := class != "identity."+action || !noRevision || permission != "identity.authenticate"
		invalidHashes := len(hash) != sha256.Size || len(previous) != sha256.Size
		if wrongEvent || wrongMetadata || invalidHashes || index == 0 && !anonymous {
			t.Fatal("callback evidence changed target/action/version/authority")
		}
		if index > 0 && (sequence != lastSequence+1 || !bytes.Equal(previous, lastHash)) {
			t.Fatal("callback audit chain is not consecutive")
		}
		if sessionID != "" && index == 2 && change != lastChange {
			t.Fatal("Session and auth success did not commit under one change")
		}
		if index == 1 && change == lastChange {
			t.Fatal("claim change reused by completion")
		}
		lastSequence, lastHash, lastChange = sequence, bytes.Clone(hash), change
		index++
	}
	if rows.Err() != nil || index != len(wanted) {
		t.Fatal("incomplete callback audit/outbox evidence")
	}
}

func (storage *privateFactoryIntegrationStorage) assertPersistedSession(
	t *testing.T,
	fixture *privateIdentityFixture,
	session accountsession.Session,
	token accountsession.Token,
) {
	t.Helper()
	digest, err := fixture.keys.sessions.ActiveDigest(token)
	if err != nil {
		t.Fatal("derive same-ring Session digest")
	}
	value := digest.Bytes()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var exact bool
	route := fixture.options.Route
	if err := storage.admin.QueryRow(ctx, `SELECT s.state='active' AND s.version=1
AND s.principal_id=11 AND subject.public_id=$2::UUID AND provider.public_id=$3::UUID
AND client.public_id=$4::UUID AND workspace.public_id=$5::UUID
AND s.token_digest_algorithm=$6 AND s.token_digest_key_id=$7 AND s.token_digest=$8
AND s.provider_generation=$11 AND s.deployment_recovery_epoch=$12
AND s.principal_authority_generation=1 AND s.account_session_generation=1
AND s.provider_sid_digest_algorithm IS NULL AND s.provider_sid_digest_key_id IS NULL
AND s.provider_sid_digest IS NULL AND s.authentication_time=$9 AND s.acr=$10
AND s.idle_expires_at>pg_catalog.clock_timestamp() AND s.absolute_expires_at>=s.idle_expires_at
FROM mesh.account_session s
JOIN mesh.identity_subject subject ON subject.id=s.identity_subject_id
JOIN mesh.identity_provider provider ON provider.id=s.identity_provider_id
JOIN mesh.identity_provider_client client ON client.id=s.identity_provider_client_id
JOIN mesh.workspace workspace ON workspace.id=s.login_workspace_id
WHERE s.public_id=$1::UUID`,
		session.ID().String(), session.IdentitySubjectID().String(), route.ProviderID().String(),
		route.ClientID().String(), route.WorkspaceID().String(), digest.Algorithm(), digest.KeyID().String(),
		value[:], session.AuthenticationTime(), "urn:meshtransit:assurance:mfa",
		route.ProviderGeneration(), route.RecoveryEpoch()).Scan(&exact); err != nil || !exact {
		t.Fatal("persisted Session lost exact identity/client/scope/digest/fences")
	}
}

func assertPrivateFactorySession(t *testing.T, session accountsession.Session, route oidcauth.Route, suffix byte) {
	t.Helper()
	workspaceID, hasWorkspace := session.LoginWorkspaceID()
	exactIdentity := session.PrincipalID().String() == privateIdentityID(t, 2).String() &&
		session.IdentitySubjectID().String() == privateIdentityID(t, suffix+3).String()
	exactScope := session.DeploymentID() == route.DeploymentID() && hasWorkspace && workspaceID == route.WorkspaceID()
	freshVersion := session.Version() == 1 && session.PrincipalAuthorityGeneration() == 1 &&
		session.AccountSessionGeneration() == 1
	exactFences := session.ProviderGeneration() == route.ProviderGeneration() &&
		session.DeploymentRecoveryEpoch() == route.RecoveryEpoch()
	exactAuthority := exactIdentity && exactScope && freshVersion && exactFences
	if !session.IsValid() || !exactAuthority {
		t.Fatal("same resident Session ring resolved wrong authority")
	}
}
