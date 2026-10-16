//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/enrollment"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
)

// deviceNeverExpiresAt is mesh_ops.device_never_expires_v1().
var deviceNeverExpiresAt = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)

// assertPostgreSQLSingleUseEnrollmentKey checks that two machines racing
// with one key enroll exactly one Device; that the Device lives as the key
// chose (here: never expires) and belongs to the key's issuer; that revoking
// the spent key leaves the Device active; and that the spent key cannot
// enroll again.
func assertPostgreSQLSingleUseEnrollmentKey(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	first, second, third := seedSharedKeyRegistrations(ctx, t, admin)
	service := newIntegrationRegistrationService(t, runtimePool)

	start := make(chan struct{})
	outcomes := make(chan registrationServiceOutcome, 2)
	for _, command := range []registrationapp.Command{first, second} {
		go func() {
			<-start
			result, err := service.Register(ctx, command)
			outcomes <- registrationServiceOutcome{result: result, err: err}
		}()
	}
	close(start)
	var enrolled []registrationapp.Result
	exhausted := 0
	for range 2 {
		outcome := <-outcomes
		switch {
		case outcome.err == nil:
			enrolled = append(enrolled, outcome.result)
		case errors.Is(outcome.err, enrollment.ErrCredentialExhausted):
			exhausted++
		default:
			t.Fatalf("racing registration error = %v", outcome.err)
		}
	}
	if len(enrolled) != 1 || exhausted != 1 {
		t.Fatalf("racing registrations: %d enrolled, %d exhausted; want 1 and 1", len(enrolled), exhausted)
	}
	nodeID := enrolled[0].NodeID().String()
	var expiresAt time.Time
	var owner, registeredBy int64
	var kind string
	if err := admin.QueryRow(ctx, `SELECT device.expires_at, device.owner_principal_id,
    device.registered_by_kind, device.registered_by_credential_id
FROM mesh.device AS device WHERE device.public_id = $1::UUID`, nodeID).Scan(
		&expiresAt, &owner, &kind, &registeredBy); err != nil {
		t.Fatalf("read key-enrolled Device: %v", err)
	}
	if !expiresAt.Equal(deviceNeverExpiresAt) || owner != 11 || kind != "credential" ||
		registeredBy != sharedKeyInternalID {
		t.Fatalf("key-enrolled Device expires %v, owner %d, registered by %s %d", expiresAt, owner, kind,
			registeredBy)
	}

	// Revoking the spent key does not touch the Device it enrolled.
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `UPDATE mesh.enrollment_credential
SET state = 'revoked', revoked_at = pg_catalog.now(), version = version + 1, updated_at = pg_catalog.now()
WHERE id = $1`, args: []any{sharedKeyInternalID}}})
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.device WHERE public_id = $1::UUID`,
		nodeID).Scan(&state); err != nil || state != "active" {
		t.Fatalf("Device after its key was revoked: %q, %v", state, err)
	}
	if _, err := service.Register(ctx, third); !errors.Is(err, enrollment.ErrCredentialInactive) &&
		!errors.Is(err, enrollment.ErrCredentialExhausted) {
		t.Fatalf("spent key enrolled another machine: %v", err)
	}
}

// sharedKeyInternalID is the single-use key three machines present.
const sharedKeyInternalID = 64200

// seedSharedKeyRegistrations stores one single-use, never-expiring key and
// three pending registrations of different machines that present it.
func seedSharedKeyRegistrations(ctx context.Context, t *testing.T, connection *pgx.Conn) (
	registrationapp.Command, registrationapp.Command, registrationapp.Command) {
	t.Helper()
	fixtures := [3]registrationAuthorityFixture{}
	for index := range fixtures {
		suffix := 64600 + index
		fixtures[index] = registrationAuthorityFixture{
			authorityInternalID:    sharedKeyInternalID,
			registrationInternalID: int64(suffix),
			authorityPublicID:      "01890f20-0000-7000-8000-000000064200",
			registrationPublicID:   fmt.Sprintf("01890f20-0000-7000-8000-%012d", suffix),
			hostname:               fmt.Sprintf("key-node-%d.example", index+1),
			machineMaterial:        byte(0xc6 + index),
			nodeMaterial:           byte(0xf6 + index),
		}
	}
	commands := [3]registrationapp.Command{}
	for index := range fixtures {
		commands[index] = registrationCommand(t, fixtures[index])
	}
	var currentNetworkRevision int64
	if err := connection.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&currentNetworkRevision); err != nil {
		t.Fatalf("read Network revision before the shared key seed: %v", err)
	}
	authorityMaterial := filledIntegrationKey(0xda)
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f21-0000-7000-8000-000000064100",
		eventPublicID:          "01890f22-0000-7000-8000-000000064100",
		outboxPublicID:         "01890f23-0000-7000-8000-000000064100",
		streamID:               201,
		aggregateKind:          "pending_registration",
		aggregatePublicID:      commands[0].RegistrationID.String(),
		aggregateVersion:       1,
		networkRevision:        currentNetworkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "registration.created",
		permission:             "device.register",
		outboxEventClass:       "registration.created",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.enrollment_credential (
    id, public_id, workspace_id, network_id, enrollment_profile_id, issuer_principal_id,
    digest_algorithm, digest_key_id, token_digest, token_fingerprint, issued_recovery_epoch,
    use_limit_kind, max_uses, used_count, valid_from, expires_at, state, device_never_expires
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, 101, 201, 601, 11, 'hmac-sha256-v1', 'integration-shared-key-v1',
    $3::BYTEA, $4::BYTEA, 1, 'bounded', 1, 0,
    pg_catalog.now() - INTERVAL '1 minute', pg_catalog.now() + INTERVAL '1 hour', 'active', TRUE
)`, sharedKeyInternalID, fixtures[0].authorityPublicID, authorityMaterial[:], authorityMaterial[:16]); err != nil {
			t.Fatalf("insert the shared key: %v", err)
		}
		for index, command := range commands {
			requestHash, err := command.RequestHash()
			if err != nil {
				t.Fatal(err)
			}
			hash := requestHash.Bytes()
			machine := command.Identity.MachineKey().Fingerprint()
			nodeKey := command.Identity.NodeKey().Bytes()
			if _, err := transaction.Exec(ctx, `INSERT INTO mesh.pending_registration (
    id, public_id, workspace_id, network_id, enrollment_profile_id, authorization_kind,
    enrollment_credential_id, request_hash, machine_key_fingerprint, requested_node_key, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, 101, 201, 601, 'credential', $3, $4::BYTEA, $5::BYTEA, $6::BYTEA,
    pg_catalog.now() + INTERVAL '10 minutes', 'pending'
)`, fixtures[index].registrationInternalID, fixtures[index].registrationPublicID, sharedKeyInternalID,
				hash[:], machine[:], nodeKey[:]); err != nil {
				t.Fatalf("insert pending registration %d: %v", index+1, err)
			}
		}
	})
	return commands[0], commands[1], commands[2]
}
