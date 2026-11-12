//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/workspace"
)

func assertPostgreSQLBrowserWorkspaceSelection(ctx context.Context, t *testing.T,
	admin *pgx.Conn, runtime *postgresadapter.Pool,
) {
	t.Helper()
	const deploymentPublicID = "01890f00-0000-7000-8000-000000000001"
	const workspacePublicID = "01890f00-0000-7000-8000-000000000102"
	const networkPublicID = "01890f00-0000-7000-8000-000000000202"
	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		t.Fatal(err)
	}
	chosenWorkspace, err := workspace.ParseID(workspacePublicID)
	if err != nil {
		t.Fatal(err)
	}
	chosenNetwork, err := network.ParseID(networkPublicID)
	if err != nil {
		t.Fatal(err)
	}
	var epoch, revision int64
	var sessionKeyID string
	var sessionBytes []byte
	if err := admin.QueryRow(ctx, `SELECT deployment.recovery_epoch, session.token_digest_key_id,
    session.token_digest FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id=session.deployment_id
WHERE session.public_id=$1::UUID`, integrationManagementSessionPublicID).Scan(&epoch, &sessionKeyID, &sessionBytes); err != nil {
		t.Fatal(err)
	}
	keyID, err := accountsession.NewDigestKeyID(sessionKeyID)
	if err != nil {
		t.Fatal(err)
	}
	var material [32]byte
	copy(material[:], sessionBytes)
	digest, err := accountsession.NewDigest(keyID, material)
	if err != nil {
		t.Fatal(err)
	}
	options := postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	choices, err := postgresadapter.NewAccountSessionStore(runtime, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := choices.ReadBrowserEnrollmentNetworksInWorkspace(ctx, deploymentID, epoch,
		digest, chosenWorkspace, network.ID{}, 100); err != nil || found {
		t.Fatalf("Workspace without membership exposed Networks: %v/%v", found, err)
	}
	if err := admin.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_revision
WHERE workspace_id=102 AND network_id=202`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000001904",
		eventPublicID:  "01890f02-0000-7000-8000-000000001904",
		outboxPublicID: "01890f03-0000-7000-8000-000000001904",
		streamID:       202, aggregateKind: "network_membership",
		aggregatePublicID: "01890f00-0000-7000-8000-000000001904",
		aggregateVersion:  1, networkRevision: revision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "browser.workspace.fixture.created", permission: "system.bootstrap",
		outboxEventClass: "browser.workspace.fixture.created",
	}, func(tx pgx.Tx) {
		statements := []string{
			`INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id,
    principal_id, state, valid_from) OVERRIDING SYSTEM VALUE VALUES
    (1901, '01890f00-0000-7000-8000-000000001901', 1, 102, 11, 'active',
     pg_catalog.transaction_timestamp()-INTERVAL '1 minute')`,
			`INSERT INTO mesh.workspace_identity_provider (id, public_id, deployment_id, workspace_id,
    identity_provider_id, identity_provider_client_id, admission_mode, minimum_assurance,
    routing_priority, state) OVERRIDING SYSTEM VALUE VALUES
    (1902, '01890f00-0000-7000-8000-000000001902', 1, 102, 601, 621, 'invitation_only',
     'urn:meshtransit:assurance:mfa', 10, 'active')`,
			`INSERT INTO mesh.enrollment_profile (id, public_id, workspace_id, network_id,
    created_by_principal_id, display_name, name_key, node_lifetime_seconds, ephemeral_mode,
    credential_use_policy, state, interactive_authorization_enabled) OVERRIDING SYSTEM VALUE VALUES
    (1903, '01890f00-0000-7000-8000-000000001903', 102, 202, 11, 'Workspace browser profile',
     'workspace-browser-profile', 3600, 'persistent', 'unlimited', 'active', TRUE)`,
			`INSERT INTO mesh.network_membership (id, public_id, deployment_id, workspace_id,
    network_id, principal_id, workspace_membership_id, state, valid_from) OVERRIDING SYSTEM VALUE VALUES
    (1904, '01890f00-0000-7000-8000-000000001904', 1, 102, 202, 11, 1901, 'active',
     pg_catalog.transaction_timestamp()-INTERVAL '1 minute')`,
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement); err != nil {
				t.Fatalf("seed cross-Workspace membership: %v", err)
			}
		}
	})
	workspaces, found, err := choices.ReadBrowserEnrollmentWorkspaces(ctx, deploymentID, epoch, digest, workspace.ID{}, 101)
	if err != nil || !found || len(workspaces.Workspaces) != 2 || workspaces.Workspaces[0].WorkspaceID != chosenWorkspace {
		t.Fatalf("multiple Workspace memberships = (%+v, %v, %v)", workspaces, found, err)
	}
	next, found, err := choices.ReadBrowserEnrollmentWorkspaces(ctx, deploymentID, epoch, digest, chosenWorkspace, 1)
	if err != nil || !found || len(next.Workspaces) != 1 || next.Workspaces[0].WorkspaceID == chosenWorkspace {
		t.Fatalf("Workspace cursor = (%+v, %v, %v)", next, found, err)
	}
	networks, found, err := choices.ReadBrowserEnrollmentNetworksInWorkspace(ctx, deploymentID, epoch,
		digest, chosenWorkspace, network.ID{}, 101)
	if err != nil || !found || len(networks.Networks) != 1 || networks.Networks[0].NetworkID != chosenNetwork {
		t.Fatalf("chosen Workspace's Networks = (%+v, %v, %v)", networks, found, err)
	}
	intentKeyID, err := enrollment.NewBrowserIntentKeyID("workspace-integration-v1")
	if err != nil {
		t.Fatal(err)
	}
	intentKey, err := enrollment.NewBrowserIntentKey(intentKeyID, bytes.Repeat([]byte{0xd1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.NewBrowserIntentKeyring(intentKey)
	if err != nil {
		t.Fatal(err)
	}
	intents, err := postgresadapter.NewBrowserIntentStore(runtime, options, keys)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := postgresadapter.NewBrowserApprovalStore(runtime, options, deploymentID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := node.NewMachineKey([32]byte{0xe1})
	if err != nil {
		t.Fatal(err)
	}
	requestedNode, err := node.NewKey([32]byte{0xe2})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := node.NewRegistrationIdentity(machine, requestedNode)
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := node.ParseHostname("workspace-browser-device")
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := enrollment.ParseBrowserIntentID("01890f00-0000-7000-8000-000000001905")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := enrollment.NewBrowserIntentNonce()
	if err != nil {
		t.Fatal(err)
	}
	token, err := intents.Issue(ctx, deploymentID, epoch, identity, hostname, intentID, nonce, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loginWorkspace, err := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	if err != nil {
		t.Fatal(err)
	}
	if approved, err := approval.ApproveInWorkspace(ctx, digest, token.Encoded(), loginWorkspace, chosenNetwork); err != nil || approved {
		t.Fatalf("Network substituted across Workspace = %v/%v", approved, err)
	}
	if approved, err := approval.ApproveInWorkspace(ctx, digest, token.Encoded(), chosenWorkspace, chosenNetwork); err != nil || !approved {
		t.Fatalf("approve explicitly chosen Workspace = %v/%v", approved, err)
	}
	intentDigest, err := enrollment.DigestPresentedBrowserIntentToken(token.Encoded())
	if err != nil {
		t.Fatal(err)
	}
	intentMaterial := intentDigest.Bytes()
	machineMaterial := machine.Bytes()
	fingerprint := machine.Fingerprint()
	nodeMaterial := requestedNode.Bytes()
	for _, test := range []struct{ name, statement string }{
		{name: "Workspace membership suspended", statement: `UPDATE mesh.workspace_membership SET state='suspended', authority_generation=authority_generation+1, version=version+1, updated_at=pg_catalog.clock_timestamp() WHERE id=1901`},
		{name: "provider route suspended", statement: `UPDATE mesh.workspace_identity_provider SET state='suspended', version=version+1, updated_at=pg_catalog.clock_timestamp() WHERE id=1902`},
		{name: "target assurance increased", statement: `UPDATE mesh.workspace_identity_provider SET minimum_assurance='urn:meshtransit:assurance:stronger', version=version+1, updated_at=pg_catalog.clock_timestamp() WHERE id=1902`},
	} {
		probe, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		setIntegrationChange(ctx, t, probe, "01890f01-0000-7000-8000-000000001906")
		if _, err := probe.Exec(ctx, test.statement); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		var count int
		if err := probe.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.lock_browser_registration_completion_authority_v2(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA, $5::BYTEA, $6::BYTEA, $7::TEXT
)`, deploymentPublicID, epoch, intentMaterial[:], machineMaterial[:], fingerprint[:], nodeMaterial[:], hostname.String()).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s retained completion authority: %d/%v", test.name, count, err)
		}
		if err := probe.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	completion, err := postgresadapter.NewBrowserCompletionStore(runtime, postgresadapter.RegistrationTransactionOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second, AddressCandidateLimit: 256,
	}, deploymentID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	completed, found, err := completion.Complete(ctx, identity, hostname, token.Encoded())
	if err != nil || !found || completed.Scope().WorkspaceID() != chosenWorkspace || completed.Scope().NetworkID() != chosenNetwork {
		t.Fatalf("complete into chosen Workspace = (%+v, %v, %v)", completed, found, err)
	}
	var sessionWorkspace int64
	if err := admin.QueryRow(ctx, `SELECT login_workspace_id FROM mesh.account_session WHERE public_id=$1::UUID`,
		integrationManagementSessionPublicID).Scan(&sessionWorkspace); err != nil || sessionWorkspace != 103 {
		t.Fatalf("Workspace selection changed SSO login context: %d/%v", sessionWorkspace, err)
	}
	replayed, found, err := completion.Complete(ctx, identity, hostname, token.Encoded())
	if err != nil || !found || replayed.NodeID() != completed.NodeID() {
		t.Fatalf("cross-Workspace completion replay = (%+v, %v, %v)", replayed, found, err)
	}
	assertPostgreSQLApprovalHeldElsewhereEnds(ctx, t, admin, intents, approval, completion,
		deploymentID, epoch, digest, identity, hostname, chosenWorkspace, chosenNetwork)
}

// TD-CORE-150: the keys now hold a Device in Workspace 102. An approval for
// Network 203 cannot complete, and the next sign-in ends it (schema 289)
// instead of handing the node the same approved URL until it expires; the
// person can then approve again, in either Network.
func assertPostgreSQLApprovalHeldElsewhereEnds(ctx context.Context, t *testing.T, admin *pgx.Conn,
	intents *postgresadapter.BrowserIntentStore, approval *postgresadapter.BrowserApprovalStore,
	completion *postgresadapter.BrowserCompletionStore, deploymentID deployment.ID, epoch int64,
	digest accountsession.Digest, identity node.RegistrationIdentity, hostname node.Hostname,
	homeWorkspace workspace.ID, homeNetwork network.ID,
) {
	t.Helper()
	otherWorkspace, err := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	if err != nil {
		t.Fatal(err)
	}
	otherNetwork, err := network.ParseID("01890f00-0000-7000-8000-000000000203")
	if err != nil {
		t.Fatal(err)
	}
	issue := func(id string) enrollment.BrowserIntentToken {
		t.Helper()
		intentID, err := enrollment.ParseBrowserIntentID(id)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := enrollment.NewBrowserIntentNonce()
		if err != nil {
			t.Fatal(err)
		}
		token, err := intents.Issue(ctx, deploymentID, epoch, identity, hostname, intentID, nonce, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	refused := issue("01890f00-0000-7000-8000-000000001911")
	if approved, err := approval.ApproveInWorkspace(ctx, digest, refused.Encoded(), otherWorkspace, otherNetwork); err != nil || !approved {
		t.Fatalf("approve another Network = %v/%v", approved, err)
	}
	if _, found, err := completion.Complete(ctx, identity, hostname, refused.Encoded()); found || !refusedForGood(err) {
		t.Fatalf("completion into another Network = %v/%v, want a lasting refusal", found, err)
	}
	var registrationID string
	if err := admin.QueryRow(ctx, `SELECT pending_registration_public_id::TEXT FROM mesh.browser_registration_intent
WHERE public_id='01890f00-0000-7000-8000-000000001911'`).Scan(&registrationID); err != nil {
		t.Fatal(err)
	}
	// The next sign-in (meshd ended the refused one) gets a new approval.
	fresh := issue("01890f00-0000-7000-8000-000000001912")
	if fresh.Encoded() == refused.Encoded() {
		t.Fatal("a new sign-in got the refused approval back")
	}
	var intentState, registrationState string
	if err := admin.QueryRow(ctx, `SELECT intent.state, registration.state
FROM mesh.browser_registration_intent AS intent
JOIN mesh.pending_registration AS registration ON registration.public_id=intent.pending_registration_public_id
WHERE intent.public_id='01890f00-0000-7000-8000-000000001911'`).Scan(&intentState, &registrationState); err != nil ||
		intentState != "expired" || registrationState != "expired" {
		t.Fatalf("refused approval = %s/%s/%v, want expired/expired", intentState, registrationState, err)
	}
	var changes int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation
WHERE change_public_id='01890f00-0000-7000-8000-000000001912'::UUID
  AND row_public_id IN ('01890f00-0000-7000-8000-000000001911'::UUID, $1::UUID)`, registrationID).Scan(&changes); err != nil || changes != 2 {
		t.Fatalf("ending the refused approval not under the new intent's change: %d/%v", changes, err)
	}
	// The same Network again: its expired registration no longer holds the
	// machine's slot.
	if approved, err := approval.ApproveInWorkspace(ctx, digest, fresh.Encoded(), otherWorkspace, otherNetwork); err != nil || !approved {
		t.Fatalf("approve the same Network again = %v/%v", approved, err)
	}
	if _, found, err := completion.Complete(ctx, identity, hostname, fresh.Encoded()); found || !refusedForGood(err) {
		t.Fatalf("second completion into another Network = %v/%v", found, err)
	}
	// The Device's own Network: the sign-in completes into it.
	home := issue("01890f00-0000-7000-8000-000000001913")
	if approved, err := approval.ApproveInWorkspace(ctx, digest, home.Encoded(), homeWorkspace, homeNetwork); err != nil || !approved {
		t.Fatalf("approve the Device's Network = %v/%v", approved, err)
	}
	// An approval that can complete stays: a node that lost its state after
	// approval asks again and gets it back.
	if again := issue("01890f00-0000-7000-8000-000000001914"); again.Encoded() != home.Encoded() {
		t.Fatal("a new sign-in ended an approval for the Device's own Network")
	}
	if _, found, err := completion.Complete(ctx, identity, hostname, home.Encoded()); err != nil || !found {
		t.Fatalf("complete into the Device's Network = %v/%v", found, err)
	}
}

// refusedForGood: the keys holding the Workspace 102 Device, or, first, the
// new-Device allowance in Network 203 that earlier fixtures used up. Schema
// 289 ends the approval on the keys alone, whichever refusal the node got.
func refusedForGood(err error) bool {
	return errors.Is(err, registration.ErrKeysHeldElsewhere) || errors.Is(err, registration.ErrNewDeviceLimit)
}
