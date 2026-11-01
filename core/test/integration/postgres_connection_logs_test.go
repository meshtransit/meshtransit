//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/shared/flowlog"
)

// assertPostgreSQLConnectionLogs qualifies schema 266 (connection logs
// design §16b C22–C25): only a Workspace admin manages credentials and a
// Network admin its Network's settings; a credential is stored sealed and
// opens only with the receiver's key under its binding, also after a
// rename; a Network turns logging on only once an operator granted its
// Workspace the feature and with a credential that allows it; a change
// advances the Network revision; a credential in use cannot be deleted
// nor lose that Network; the events name the changes and never the
// secret. It leaves nothing behind.
func assertPostgreSQLConnectionLogs(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, migrationConfig config.MigrationConfig,
) {
	t.Helper()
	receiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresadapter.NewConnectionLogStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second},
		&postgresadapter.CredentialSealer{KeyID: "meshflow-test", Key: receiver.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	members := newNetworkMemberFixture(t, runtimePool)
	// The fixture owner owns the Workspace while it assigns roles.
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner, scope := members.confirmer, members.scope
	workspaceID := scope.WorkspaceID()
	secret := flowlog.Credential{AccessKeyID: "TESTINTEGRATIONKEY01", SecretAccessKey: "integration/secret+value"}
	credentialID := connectionlog.CredentialID(newConnectionLogID(t))
	putAs := func(id connectionlog.CredentialID, name string, expected int64,
		secret *flowlog.Credential, networks ...network.ID,
	) (connectionlog.Credential, error) {
		return store.PutCredential(ctx, connectionlog.CredentialPut{
			Session: owner, Workspace: workspaceID,
			ID: id, ExpectedVersion: expected, Name: name, Provider: flowlog.ProviderS3,
			Secret: secret, Networks: networks, CorrelationID: newCorrelationID(t),
		})
	}
	put := func(expected int64, secret *flowlog.Credential, networks ...network.ID) (connectionlog.Credential, error) {
		return putAs(credentialID, "Audit bucket", expected, secret, networks...)
	}
	// A member without a role sees nothing; a Network admin reads its
	// Network's settings but never touches the Workspace's credentials.
	if _, err := store.ListCredentials(ctx, owner, workspaceID); !errors.Is(err, connectionlog.ErrForbidden) {
		t.Fatalf("a member listed credentials: %v", err)
	}
	revokeNetworkAdmin := members.grant(ctx, t, integrationAuthorityConfirmerID,
		authorization.BuiltinRoleNetworkAdmin, network.ID{})
	if _, err := put(0, &secret); !errors.Is(err, connectionlog.ErrForbidden) {
		t.Fatalf("a Network admin created a credential: %v", err)
	}
	if read, err := store.ReadSettings(ctx, owner, scope); err != nil || read.Settings.Version != 0 {
		t.Fatalf("a Network admin read %+v, %v", read, err)
	}
	revokeNetworkAdmin()
	revokeAdmin := members.grant(ctx, t, integrationAuthorityConfirmerID, authorization.BuiltinRoleAdmin, network.ID{})
	listing, err := store.ListCredentials(ctx, owner, workspaceID)
	if err != nil || listing.Feature || len(listing.Credentials) != 0 {
		t.Fatalf("ListCredentials() = %+v, %v", listing, err)
	}
	created, err := put(0, &secret)
	if err != nil || created.Version != 1 || created.SealedVersion != 1 || created.AccessKeySuffix != "EY01" ||
		len(created.Networks) != 0 {
		t.Fatalf("created = %+v, %v", created, err)
	}
	if _, err := putAs(connectionlog.CredentialID(newConnectionLogID(t)), "Audit bucket", 0,
		&secret); !errors.Is(err, connectionlog.ErrNameTaken) {
		t.Fatalf("a second credential with the name: %v", err)
	}
	opened := openStoredCredential(ctx, t, admin, receiver, workspaceID.String(), credentialID, 1)
	if opened != secret {
		t.Fatal("the stored credential did not open to the secret")
	}
	assertNoConnectionLogSecret(ctx, t, admin, secret)

	settings := func(expected int64, enabled bool, credential *connectionlog.CredentialID, region string,
	) (connectionlog.SettingsResult, error) {
		bucket := ""
		if credential != nil {
			bucket = "meshtransit-logs"
		}
		return store.ReplaceSettings(ctx, connectionlog.SettingsReplacement{
			Session: owner, Scope: scope,
			ExpectedVersion: expected, Settings: connectionlog.Settings{
				Enabled: enabled, Credential: credential,
				Bucket: bucket, Region: region, Prefix: "mesh", WindowSeconds: 60,
			},
			CorrelationID: newCorrelationID(t),
		})
	}
	if _, err := settings(0, true, &credentialID, "eu-central-1"); !errors.Is(err, connectionlog.ErrNotAllowed) {
		t.Fatalf("logging on without the feature: %v", err)
	}
	unknown := connectionlog.CredentialID(newConnectionLogID(t))
	if _, err := settings(0, false, &unknown, "eu-central-1"); !errors.Is(err, connectionlog.ErrNotFound) {
		t.Fatalf("a credential of no Workspace: %v", err)
	}
	operator := postgresadapter.MigrationOptions{
		Address: migrationConfig.PostgreSQL.Address, Database: migrationConfig.PostgreSQL.Database,
		User: migrationConfig.PostgreSQL.User, PasswordFile: migrationConfig.PostgreSQL.PasswordFile,
		CAFile: migrationConfig.PostgreSQL.CAFile, ConnectTimeout: migrationConfig.ConnectTimeout,
		LockTimeout: migrationConfig.LockTimeout, StatementTimeout: migrationConfig.StatementTimeout,
		Actor: migrationConfig.Actor, CodeRelease: "integration-test@local",
	}
	granted, err := postgresadapter.ChangeWorkspaceFeature(ctx, operator, publicid.ID(workspaceID),
		postgresadapter.WorkspaceFeatureConnectionLogs, true, "integration test")
	if err != nil || !granted.Changed || len(granted.Features) != 1 {
		t.Fatalf("grant = %+v, %v", granted, err)
	}
	if again, err := postgresadapter.ChangeWorkspaceFeature(ctx, operator, publicid.ID(workspaceID),
		postgresadapter.WorkspaceFeatureConnectionLogs, true, "again"); err != nil || again.Changed {
		t.Fatalf("a second grant = %+v, %v", again, err)
	}
	if _, err := settings(0, true, &credentialID, "eu-central-1"); !errors.Is(err, connectionlog.ErrNotAllowed) {
		t.Fatalf("logging on with a credential that does not allow the Network: %v", err)
	}
	scoped, err := put(1, nil, scope.NetworkID())
	if err != nil || scoped.Version != 2 || scoped.SealedVersion != 1 || len(scoped.Networks) != 1 {
		t.Fatalf("scoped = %+v, %v", scoped, err)
	}
	// A change of Networks keeps the seal: the receiver still opens it.
	if again := openStoredCredential(ctx, t, admin, receiver, workspaceID.String(), credentialID, 1); again != secret {
		t.Fatal("the credential did not open after its Networks changed")
	}
	if _, err := settings(0, true, &credentialID, "auto"); !errors.Is(err, connectionlog.ErrInvalid) {
		t.Fatalf("an R2 region for an S3 credential: %v", err)
	}
	revision := connectionLogRevision(ctx, t, admin, scope)
	on, err := settings(0, true, &credentialID, "eu-central-1")
	if err != nil || !on.Changed || !on.Feature || on.Settings.Version != 1 || !on.Settings.Enabled ||
		connectionLogRevision(ctx, t, admin, scope) != revision+1 {
		t.Fatalf("on = %+v, %v", on, err)
	}
	if features, err := postgresadapter.ListWorkspaceFeatures(ctx, operator, publicid.ID(workspaceID)); err != nil ||
		features.EnabledNetworks != 1 || len(features.Features) != 1 {
		t.Fatalf("features = %+v, %v", features, err)
	}
	// A map stream reads the setting in the Network's scope (schema 267).
	maps, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
		RelayDirectory: integrationRelayDirectory(t), RoutePeerLimit: mapsession.DefaultPeerLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if read, err := maps.ReadFlowLog(ctx, scope); err != nil || !read.Enabled || read.Forwarded ||
		read.WindowSeconds != 60 {
		t.Fatalf("ReadFlowLog() = %+v, %v", read, err)
	}
	// Another Network of the Workspace reads its own setting: none.
	other, err := network.NewScope(workspaceID, network.ID(mustIntegrationPublicID(t, "01890f00-0000-7000-8000-000000000204")))
	if err != nil {
		t.Fatal(err)
	}
	if read, err := maps.ReadFlowLog(ctx, other); err != nil || read.Enabled {
		t.Fatalf("ReadFlowLog() of another Network = %+v, %v", read, err)
	}
	assertFlowlogReceiverReads(ctx, t, admin, runtimePool, scope, credentialID)
	// Without the feature the Network stays on but logs nothing (C31).
	if _, err := postgresadapter.ChangeWorkspaceFeature(ctx, operator, publicid.ID(workspaceID),
		postgresadapter.WorkspaceFeatureConnectionLogs, false, ""); err != nil {
		t.Fatal(err)
	}
	if read, err := maps.ReadFlowLog(ctx, scope); err != nil || read.Enabled {
		t.Fatalf("ReadFlowLog() without the feature = %+v, %v", read, err)
	}
	receiverStore, err := postgresadapter.NewFlowlogReceiverStore(runtimePool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if destination, err := receiverStore.Destination(ctx, scope); err != nil ||
		destination.Reason != connectionlog.ReasonFeatureRevoked || len(destination.Sealed) == 0 {
		t.Fatalf("Destination() without the feature = %+v, %v", destination, err)
	}
	if listed, err := receiverStore.Networks(ctx, network.ID{}, connectionlog.MaxReceiverNetworks); err != nil ||
		slices.ContainsFunc(listed.Networks, func(entry connectionlog.ReceiverNetwork) bool {
			return entry.Network == scope.NetworkID()
		}) {
		t.Fatalf("a Network without the feature is listed: %v", err)
	}
	if _, err := postgresadapter.ChangeWorkspaceFeature(ctx, operator, publicid.ID(workspaceID),
		postgresadapter.WorkspaceFeatureConnectionLogs, true, "integration test again"); err != nil {
		t.Fatal(err)
	}
	if same, err := settings(1, true, &credentialID, "eu-central-1"); err != nil || same.Changed {
		t.Fatalf("the same settings = %+v, %v", same, err)
	}
	if _, err := settings(0, false, nil, ""); !errors.Is(err, connectionlog.ErrConflict) {
		t.Fatalf("a stale version: %v", err)
	}
	read, err := store.ReadSettings(ctx, owner, scope)
	if err != nil || !read.Feature || read.Settings.Version != 1 || read.Settings.Credential == nil ||
		*read.Settings.Credential != credentialID {
		t.Fatalf("ReadSettings() = %+v, %v", read, err)
	}
	if err := store.DeleteCredential(ctx, connectionlog.CredentialDeletion{
		Session: owner, Workspace: workspaceID,
		ID: credentialID, ExpectedVersion: 2, CorrelationID: newCorrelationID(t),
	}); !errors.Is(err, connectionlog.ErrInUse) {
		t.Fatalf("deleting a credential in use: %v", err)
	}
	if _, err := put(2, nil); !errors.Is(err, connectionlog.ErrInUse) {
		t.Fatalf("taking a Network off a credential it sends with: %v", err)
	}
	rotated, err := put(2, &flowlog.Credential{AccessKeyID: "TESTINTEGRATIONROT22", SecretAccessKey: "rotated"},
		scope.NetworkID())
	if err != nil || rotated.Version != 3 || rotated.SealedVersion != 3 || rotated.AccessKeySuffix != "OT22" {
		t.Fatalf("rotated = %+v, %v", rotated, err)
	}
	if again := openStoredCredential(ctx, t, admin, receiver, workspaceID.String(), credentialID, 3); again.SecretAccessKey != "rotated" {
		t.Fatal("the rotated credential did not open")
	}
	// An S3 destination names its bucket owner (C52); the receiver reads it;
	// a malformed one, or one on an R2 destination, is refused.
	ownedSettings := connectionlog.Settings{
		Enabled: true, Credential: &credentialID, Bucket: "meshtransit-logs", Region: "eu-central-1", Prefix: "mesh",
		WindowSeconds: 60, ExpectedBucketOwner: "123456789012",
	}
	replace := func(expected int64, changed connectionlog.Settings) (connectionlog.SettingsResult, error) {
		return store.ReplaceSettings(ctx, connectionlog.SettingsReplacement{
			Session: owner, Scope: scope, ExpectedVersion: expected, Settings: changed, CorrelationID: newCorrelationID(t),
		})
	}
	owned, err := replace(1, ownedSettings)
	if err != nil || owned.Settings.Version != 2 || owned.Settings.ExpectedBucketOwner != "123456789012" {
		t.Fatalf("owned = %+v, %v", owned, err)
	}
	if read, err := store.ReadSettings(ctx, owner, scope); err != nil ||
		read.Settings.ExpectedBucketOwner != "123456789012" {
		t.Fatalf("ReadSettings() with an owner = %+v, %v", read, err)
	}
	if same, err := replace(2, ownedSettings); err != nil || same.Changed {
		t.Fatalf("the same owner = %+v, %v", same, err)
	}
	if destination, err := receiverStore.Destination(ctx, scope); err != nil ||
		destination.ExpectedBucketOwner != "123456789012" {
		t.Fatalf("the receiver's destination = %+v, %v", destination, err)
	}
	malformed := ownedSettings
	malformed.ExpectedBucketOwner = "12345678901"
	if _, err := replace(2, malformed); !errors.Is(err, connectionlog.ErrInvalid) {
		t.Fatalf("a malformed owner: %v", err)
	}
	r2ID := connectionlog.CredentialID(newConnectionLogID(t))
	if _, err := store.PutCredential(ctx, connectionlog.CredentialPut{
		Session: owner, Workspace: workspaceID, ID: r2ID, Name: "R2 bucket", Provider: flowlog.ProviderR2,
		AccountID: strings.Repeat("a", 32), Networks: []network.ID{scope.NetworkID()}, CorrelationID: newCorrelationID(t),
		Secret: &flowlog.Credential{AccessKeyID: strings.Repeat("f", 32), SecretAccessKey: "r2-secret"},
	}); err != nil {
		t.Fatalf("an R2 credential: %v", err)
	}
	onR2 := ownedSettings
	onR2.Credential, onR2.Region = &r2ID, "auto"
	if _, err := replace(2, onR2); !errors.Is(err, connectionlog.ErrInvalid) {
		t.Fatalf("an owner on an R2 destination: %v", err)
	}
	if err := store.DeleteCredential(ctx, connectionlog.CredentialDeletion{
		Session: owner, Workspace: workspaceID, ID: r2ID, ExpectedVersion: 1, CorrelationID: newCorrelationID(t),
	}); err != nil {
		t.Fatalf("deleting the R2 credential: %v", err)
	}
	unowned := ownedSettings
	unowned.ExpectedBucketOwner = ""
	if cleared, err := replace(2, unowned); err != nil || !cleared.Changed || cleared.Settings.Version != 3 ||
		cleared.Settings.ExpectedBucketOwner != "" {
		t.Fatalf("clearing the owner = %+v, %v", cleared, err)
	}
	off, err := settings(3, false, nil, "")
	if err != nil || !off.Changed || off.Settings.Enabled || off.Settings.Credential != nil {
		t.Fatalf("off = %+v, %v", off, err)
	}
	// Off with no credential is no destination at all.
	if _, err := receiverStore.Destination(ctx, scope); !errors.Is(err, postgresadapter.ErrFlowlogNotFound) {
		t.Fatalf("Destination() of a Network without one: %v", err)
	}
	if err := store.DeleteCredential(ctx, connectionlog.CredentialDeletion{
		Session: owner, Workspace: workspaceID,
		ID: credentialID, ExpectedVersion: 3, CorrelationID: newCorrelationID(t),
	}); err != nil {
		t.Fatalf("deleting a credential no Network uses: %v", err)
	}
	for _, action := range []string{
		"storage_credential.created", "storage_credential.updated",
		"storage_credential.rotated", "storage_credential.deleted", "connection_log.settings_replaced",
		"workspace_feature.granted",
	} {
		var events int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event WHERE action = $1`,
			action).Scan(&events); err != nil || events == 0 {
			t.Errorf("no %s event: %v", action, err)
		}
	}
	revoked, err := postgresadapter.ChangeWorkspaceFeature(ctx, operator, publicid.ID(workspaceID),
		postgresadapter.WorkspaceFeatureConnectionLogs, false, "")
	if err != nil || !revoked.Changed || len(revoked.Features) != 0 || revoked.EnabledNetworks != 0 {
		t.Fatalf("revoke = %+v, %v", revoked, err)
	}
	var revokes int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
WHERE action = 'workspace_feature.revoked' AND permission = 'system.operator'`).Scan(&revokes); err != nil || revokes == 0 {
		t.Fatalf("no revoke event: %v", err)
	}
	assertNoConnectionLogSecret(ctx, t, admin, secret)
	revokeAdmin()
	revocationBypass(ctx, t, admin, []string{`DELETE FROM mesh.network_connection_log`})
}

// assertNoConnectionLogSecret finds the secret nowhere in clear: not in a
// credential row, an audit event or an outbox event.
func assertNoConnectionLogSecret(ctx context.Context, t *testing.T, admin *pgx.Conn, secret flowlog.Credential) {
	t.Helper()
	var leaks int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.storage_credential AS credential
     WHERE pg_catalog.position(credential.sealed, $1::BYTEA) > 0
        OR pg_catalog.position(credential.sealed, $2::BYTEA) > 0) +
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS event
     WHERE pg_catalog.strpos(event.payload::TEXT, $3) > 0 OR pg_catalog.strpos(event.payload::TEXT, $4) > 0) +
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS event
     WHERE pg_catalog.strpos(event.payload::TEXT, $3) > 0 OR pg_catalog.strpos(event.payload::TEXT, $4) > 0)`,
		[]byte(secret.SecretAccessKey), []byte(secret.AccessKeyID), secret.SecretAccessKey,
		secret.AccessKeyID).Scan(&leaks); err != nil || leaks != 0 {
		t.Fatalf("the secret leaked %d times: %v", leaks, err)
	}
}

func newConnectionLogID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func connectionLogRevision(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope) int64 {
	t.Helper()
	var value int64
	if err := admin.QueryRow(ctx, `SELECT revision.network_revision FROM mesh_ops.network_revision AS revision
JOIN mesh.network AS network ON network.id = revision.network_id WHERE network.public_id = $1::UUID`,
		scope.NetworkID().String()).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

// openStoredCredential opens the row as the receiver would.
func openStoredCredential(ctx context.Context, t *testing.T, admin *pgx.Conn, receiver *ecdh.PrivateKey,
	workspace string, credential connectionlog.CredentialID, version int64,
) flowlog.Credential {
	t.Helper()
	var sealed []byte
	var keyID string
	var sealedVersion int64
	if err := admin.QueryRow(ctx, `SELECT sealed, sealing_key_id, sealed_version FROM mesh.storage_credential
WHERE public_id = $1::UUID`, credential.String()).Scan(&sealed, &keyID, &sealedVersion); err != nil ||
		keyID != "meshflow-test" || sealedVersion != version {
		t.Fatalf("stored credential: %s %d %v", keyID, sealedVersion, err)
	}
	if bytes.Contains(sealed, []byte("TESTINTEGRATION")) {
		t.Fatal("the access key is in clear")
	}
	opened, err := flowlog.OpenCredential(receiver, sealed, flowlog.CredentialBinding{
		WorkspaceID:  workspace,
		CredentialID: credential.String(), Version: version, Provider: flowlog.ProviderS3,
	})
	if err != nil {
		t.Fatalf("OpenCredential(): %v", err)
	}
	return opened
}

// assertFlowlogReceiverReads qualifies schema 268 (design §16c, s4c1b) on a
// Network that logs: the receiver lists it, reads its destination for the
// exact pair only, sees nothing of a Network without a destination, and
// learns a suspended Device's machine key.
func assertFlowlogReceiverReads(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, scope network.Scope, credentialID connectionlog.CredentialID,
) {
	t.Helper()
	store, err := postgresadapter.NewFlowlogReceiverStore(runtimePool, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertFlowlogReaderSeesOnlyLoggingNetworks(ctx, t, admin, scope)
	listed, err := store.Networks(ctx, network.ID{}, connectionlog.MaxReceiverNetworks)
	if err != nil || listed.GeneratedAt.IsZero() {
		t.Fatalf("Networks() = %+v, %v", listed, err)
	}
	found := false
	for _, entry := range listed.Networks {
		if entry.Network == scope.NetworkID() {
			found = entry.Enabled && entry.Workspace == scope.WorkspaceID() && entry.Credential == credentialID &&
				entry.SealedVersion == 1 && entry.SealingKeyID == "meshflow-test"
		}
	}
	if !found {
		t.Fatalf("the logging Network is not listed right: %+v", listed.Networks)
	}
	destination, err := store.Destination(ctx, scope)
	if err != nil || destination.Reason != connectionlog.ReasonLogging || destination.Credential != credentialID ||
		destination.SealedVersion != 1 || len(destination.Sealed) == 0 || destination.Bucket != "meshtransit-logs" ||
		destination.Provider != "aws_s3" {
		t.Fatalf("Destination() = %+v, %v", destination, err)
	}
	other, err := network.NewScope(workspace.ID(newConnectionLogID(t)), scope.NetworkID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Destination(ctx, other); !errors.Is(err, postgresadapter.ErrFlowlogNotFound) {
		t.Fatalf("the Network under another Workspace: %v", err)
	}
	quiet, err := network.NewScope(scope.WorkspaceID(), network.ID(mustIntegrationPublicID(t,
		"01890f00-0000-7000-8000-000000000204")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Destination(ctx, quiet); !errors.Is(err, postgresadapter.ErrFlowlogNotFound) {
		t.Fatalf("a Network without a destination: %v", err)
	}
	// A suspended Device's current machine key is revoked; restored, it is
	// live again and never listed as such.
	var device string
	var key []byte
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT, epoch.public_key FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS epoch ON epoch.workspace_id = device.workspace_id
 AND epoch.network_id = device.network_id AND epoch.device_id = device.id AND epoch.epoch = device.current_machine_key_epoch
JOIN mesh.network AS network ON network.workspace_id = device.workspace_id AND network.id = device.network_id
WHERE network.public_id = $1::UUID AND device.state = 'active' AND device.deleted_at IS NULL
  AND epoch.state = 'active' ORDER BY device.id LIMIT 1`, scope.NetworkID().String()).Scan(&device, &key); err != nil {
		t.Fatalf("an active Device: %v", err)
	}
	revocationBypass(ctx, t, admin, []string{fmt.Sprintf(
		`UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin', updated_at = pg_catalog.now()
WHERE public_id = '%s'::UUID`, device,
	)})
	revoked, err := store.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listedRevocation := func() bool {
		for _, entry := range revoked.Revocations {
			if entry.Device.String() == device && bytes.Equal(entry.MachineKey[:], key) && entry.Network == scope.NetworkID() {
				return true
			}
		}
		return false
	}
	if !listedRevocation() {
		t.Fatalf("the suspended Device's key is not revoked: %+v", revoked)
	}
	revocationBypass(ctx, t, admin, []string{fmt.Sprintf(
		`UPDATE mesh.device SET state = 'active', suspended_reason = NULL WHERE public_id = '%s'::UUID`, device,
	)})
	if revoked, err = store.Revocations(ctx); err != nil || listedRevocation() {
		t.Fatalf("a live Device's key is listed: %v", err)
	}
	if listed.Networks[slices.IndexFunc(listed.Networks, func(entry connectionlog.ReceiverNetwork) bool {
		return entry.Network == scope.NetworkID()
	})].DirectoryRevision != connectionLogRevision(ctx, t, admin, scope) {
		t.Fatal("the listed directory revision is not the Network's")
	}
	assertFlowlogDirectory(ctx, t, admin, store, scope)
}

// assertFlowlogReaderSeesOnlyLoggingNetworks reads as mesh_flowlog_reader:
// rows of a Network with no destination, and credentials no destination
// uses, stay invisible to it (review s4c1b H1, M3).
func assertFlowlogReaderSeesOnlyLoggingNetworks(ctx context.Context, t *testing.T, admin *pgx.Conn,
	scope network.Scope,
) {
	t.Helper()
	// The check means something only when such rows exist.
	var outside int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device AS device
WHERE (device.workspace_id, device.network_id) NOT IN (SELECT logged.workspace_id, logged.network_id
                                                      FROM mesh.network_connection_log AS logged)`).Scan(&outside); err != nil ||
		outside == 0 {
		t.Fatalf("no Device outside a logging Network to hide: %d, %v", outside, err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_flowlog_reader`); err != nil {
		t.Fatal(err)
	}
	var foreignDevices, foreignEpochs, foreignNetworks, workspaces, unusedCredentials int
	if err := tx.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.device AS device
     WHERE (device.workspace_id, device.network_id) NOT IN (SELECT logged.workspace_id, logged.network_id
                                                           FROM mesh.network_connection_log AS logged)),
    (SELECT pg_catalog.count(*) FROM mesh.device_machine_key_epoch AS epoch
     WHERE (epoch.workspace_id, epoch.network_id) NOT IN (SELECT logged.workspace_id, logged.network_id
                                                         FROM mesh.network_connection_log AS logged)),
    (SELECT pg_catalog.count(*) FROM mesh.network AS network WHERE network.public_id <> $1::UUID),
    (SELECT pg_catalog.count(*) FROM mesh.workspace),
    (SELECT pg_catalog.count(*) FROM mesh.storage_credential AS credential
     WHERE (credential.workspace_id, credential.id) NOT IN (SELECT logged.workspace_id, logged.credential_id
                                                           FROM mesh.network_connection_log AS logged
                                                           WHERE logged.credential_id IS NOT NULL))`,
		scope.NetworkID().String()).Scan(&foreignDevices, &foreignEpochs, &foreignNetworks, &workspaces,
		&unusedCredentials); err != nil {
		t.Fatal(err)
	}
	var foreignRevisions, foreignMemberships, foreignPseudonyms, tenantPools int
	if err := tx.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_ops.network_revision AS revision
     WHERE (revision.workspace_id, revision.network_id) NOT IN (SELECT logged.workspace_id, logged.network_id
                                                               FROM mesh.network_connection_log AS logged)),
    (SELECT pg_catalog.count(*) FROM mesh.workspace_membership AS membership
     WHERE membership.workspace_id NOT IN (SELECT logged.workspace_id FROM mesh.network_connection_log AS logged)),
    (SELECT pg_catalog.count(*) FROM mesh.connection_log_owner_pseudonym AS pseudonym
     WHERE pseudonym.workspace_id NOT IN (SELECT logged.workspace_id FROM mesh.network_connection_log AS logged)),
    (SELECT pg_catalog.count(*) FROM mesh.address_pool AS pool
     WHERE pool.workspace_id IS NOT NULL
        OR pool.purpose NOT IN ('federation_resource_alias', 'federation_consumer_alias'))`).Scan(
		&foreignRevisions, &foreignMemberships, &foreignPseudonyms, &tenantPools,
	); err != nil {
		t.Fatal(err)
	}
	if foreignRevisions != 0 || foreignMemberships != 0 || foreignPseudonyms != 0 || tenantPools != 0 {
		t.Fatalf("the reader sees %d revisions, %d memberships, %d pseudonyms, %d pools it should not",
			foreignRevisions, foreignMemberships, foreignPseudonyms, tenantPools)
	}
	// The directory's Network-scoped tables (schema 269).
	for _, table := range []string{
		"device_tag", "device_tag_assignment", "device_group", "device_group_member", "network_site",
		"network_site_router", "network_exit_pool", "network_exit_node", "node_address_lease", "network_prefix",
	} {
		var foreign int
		if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT pg_catalog.count(*) FROM mesh.%s AS guarded
WHERE (guarded.workspace_id, guarded.network_id) NOT IN (SELECT logged.workspace_id, logged.network_id
                                                         FROM mesh.network_connection_log AS logged)`, table)).Scan(
			&foreign); err != nil || foreign != 0 {
			t.Fatalf("the reader sees %d rows of mesh.%s it should not: %v", foreign, table, err)
		}
	}
	if foreignDevices != 0 || foreignEpochs != 0 || foreignNetworks != 0 || workspaces != 1 || unusedCredentials != 0 {
		t.Fatalf("the reader sees %d Devices, %d key epochs, %d Networks, %d Workspaces, %d credentials it should not",
			foreignDevices, foreignEpochs, foreignNetworks, workspaces, unusedCredentials)
	}
	var visible int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device AS device
JOIN mesh.network AS network ON network.workspace_id = device.workspace_id AND network.id = device.network_id
WHERE network.public_id = $1::UUID`, scope.NetworkID().String()).Scan(&visible); err != nil || visible == 0 {
		t.Fatalf("the reader sees no Device of the logging Network: %v", err)
	}
}
