//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/shared/kubejoin"
)

// assertGatewayRotationTokens checks schema 232 against a live gateway
// Device (K1.1 design §8): no key epoch without a verified token recorded in
// the same transaction, whichever function writes it; the trust and pod the
// rotation reads; one use per token, key and purpose; a trust that changed,
// a token past its time, another Device. Every rotation here rolls back, so
// the Device keeps its keys.
func assertGatewayRotationTokens(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, keys replicaKeys,
	deviceID string) {
	t.Helper()
	// Schema 227's function, as Core 231 calls it, rotates nothing now.
	if code := gatewayRotationState(ctx, t, runtime, keys.machine, keys.node, newReplicaKeys(t).machine); code != "MTK19" {
		t.Fatalf("a rotation without a token: SQLSTATE %q, want MTK19", code)
	}
	// Nor does a node key epoch written directly.
	if code := insertGatewayNodeEpoch(ctx, t, admin, deviceID, nil); code != "MTK19" {
		t.Fatalf("a node key epoch without a token: SQLSTATE %q, want MTK19", code)
	}

	// The first replica's approval set the cluster's trust and bound its
	// pod.
	read := readGatewayRotationTrust(ctx, t, runtime, keys)
	if read.device != deviceID || read.version == nil || *read.version != 1 || read.pod == nil ||
		*read.pod != fixturePodName(keys) || read.namespace == nil || *read.namespace != "mt-kube-k1" {
		t.Fatalf("read = %+v", read)
	}
	assertTrustImmutableOnTheRequest(ctx, t, admin, deviceID)

	expires := time.Now().Add(9 * time.Minute)
	rotate := func(tx pgx.Tx, jti string, version int64, until time.Time) string {
		t.Helper()
		next := newReplicaKeys(t).machine
		key, fingerprint := next.Bytes(), next.Fingerprint()
		machine, nodeKey := keys.machine.Fingerprint(), keys.node.Bytes()
		_, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.rotate_kubernetes_gateway_machine_key_v2(
    $1, $2, $3, $4, pg_catalog.uuidv7(), pg_catalog.uuidv7(), $5::UUID, $6, $7, $8)`,
			machine[:], nodeKey[:], key[:], fingerprint[:], deviceID, version, jti, until)
		return sqlState(t, err)
	}
	// A verified token rotates, and its use names the transaction.
	inTokenTx(ctx, t, runtime, keys, func(tx pgx.Tx) {
		if code := rotate(tx, "jti-1", 1, expires); code != "" {
			t.Fatalf("rotate v2 with a token: SQLSTATE %q", code)
		}
		// The runtime role reads no token use itself.
		if _, err := tx.Exec(ctx, `SAVEPOINT direct`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, `SELECT 1 FROM mesh_ops.kubernetes_gateway_token_use`)
		if code := sqlState(t, err); code != "42501" {
			t.Fatalf("runtime read token uses: SQLSTATE %q, want 42501", code)
		}
	})
	for name, test := range map[string]struct {
		version int64
		until   time.Time
		device  string
		want    string
	}{
		"trust changed":      {2, expires, deviceID, "MTK18"},
		"token expired":      {1, time.Now().Add(-time.Second), deviceID, "MTK20"},
		"token lives longer": {1, time.Now().Add(16 * time.Minute), deviceID, "MTK20"},
		"another Device":     {1, expires, mustPublicID(t).String(), "P0002"},
	} {
		inTokenTx(ctx, t, runtime, keys, func(tx pgx.Tx) {
			_, err := tx.Exec(ctx, `SELECT mesh_ops.consume_kubernetes_gateway_rotation_token_v1(
    $1::UUID, $2, $3, 'machine_key', $4, 'jti-2', $5)`, test.device, fingerprintOf(keys), nodeKeyOf(keys),
				test.version, test.until)
			if code := sqlState(t, err); code != test.want {
				t.Errorf("%s: SQLSTATE %q, want %s", name, code, test.want)
			}
		})
	}
	// One use per token, purpose and key; the same token may rotate the node
	// key, which another purpose names.
	inTokenTx(ctx, t, runtime, keys, func(tx pgx.Tx) {
		consume := func(purpose string) string {
			_, err := tx.Exec(ctx, `SELECT mesh_ops.consume_kubernetes_gateway_rotation_token_v1(
    $1::UUID, $2, $3, $4, 1, 'jti-3', $5)`, deviceID, fingerprintOf(keys), nodeKeyOf(keys), purpose, expires)
			return sqlState(t, err)
		}
		if code := consume("machine_key"); code != "" {
			t.Fatalf("first use: SQLSTATE %q", code)
		}
		if code := consume("node_key"); code != "" {
			t.Fatalf("the same token for the node key: SQLSTATE %q", code)
		}
		if _, err := tx.Exec(ctx, `SAVEPOINT replay`); err != nil {
			t.Fatal(err)
		}
		if code := consume("machine_key"); code != "MTK17" {
			t.Fatalf("a second use: SQLSTATE %q, want MTK17", code)
		}
	})
	// A use recorded by another transaction admits nothing.
	committedUse(ctx, t, runtime, keys, deviceID, "jti-4", expires)
	if code := gatewayRotationState(ctx, t, runtime, keys.machine, keys.node, newReplicaKeys(t).machine); code != "MTK19" {
		t.Fatalf("a rotation with another transaction's token use: SQLSTATE %q, want MTK19", code)
	}
	// A node key epoch enters with a node-key use of its own transaction,
	// not with a machine-key use.
	if code := insertGatewayNodeEpoch(ctx, t, admin, deviceID, &tokenUse{keys: keys, purpose: "machine_key"}); code != "MTK19" {
		t.Fatalf("a node key epoch with a machine-key use: SQLSTATE %q, want MTK19", code)
	}
	if code := insertGatewayNodeEpoch(ctx, t, admin, deviceID, &tokenUse{keys: keys, purpose: "node_key"}); code != "" {
		t.Fatalf("a node key epoch with a node-key use: SQLSTATE %q", code)
	}
	assertTokenUsesPruned(ctx, t, admin, deviceID)
	assertTrustDigestMatchesGo(ctx, t, admin)
}

type rotationTrustRead struct {
	device    string
	version   *int64
	namespace *string
	pod       *string
}

func readGatewayRotationTrust(ctx context.Context, t *testing.T, runtime *pgx.Conn, keys replicaKeys) rotationTrustRead {
	t.Helper()
	var read rotationTrustRead
	inTokenTx(ctx, t, runtime, keys, func(tx pgx.Tx) {
		if err := tx.QueryRow(ctx, `SELECT device_public_id::TEXT, trust_version, namespace, pod_name
FROM mesh_ops.read_kubernetes_gateway_rotation_trust_v1($1, $2)`, fingerprintOf(keys), nodeKeyOf(keys)).Scan(
			&read.device, &read.version, &read.namespace, &read.pod); err != nil {
			t.Fatalf("read the rotation trust: %v", err)
		}
	})
	// Without the session's mark the function reads nothing.
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var rows int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.read_kubernetes_gateway_rotation_trust_v1($1, $2)`,
		fingerprintOf(keys), nodeKeyOf(keys)).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("an unproven session read %d rows, %v", rows, err)
	}
	return read
}

// inTokenTx runs f in a runtime transaction set up as Core's store does for
// a gateway rotation (session proof, Network scope), then rolls it back.
func inTokenTx(ctx context.Context, t *testing.T, runtime *pgx.Conn, keys replicaKeys, f func(pgx.Tx)) {
	t.Helper()
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.mark_session_proven_v1($1, $2)`, fingerprintOf(keys),
		nodeKeyOf(keys)); err != nil {
		t.Fatal(err)
	}
	var workspaceID, networkID string
	if err := tx.QueryRow(ctx, `SELECT workspace_public_id::TEXT, network_public_id::TEXT
FROM mesh_ops.resolve_map_session_scope($1, $2)`, fingerprintOf(keys), nodeKeyOf(keys)).Scan(&workspaceID,
		&networkID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.set_network_scope($1::UUID, $2::UUID)`, workspaceID,
		networkID); err != nil {
		t.Fatal(err)
	}
	f(tx)
}

// committedUse records a token use in a transaction of its own, which
// commits.
func committedUse(ctx context.Context, t *testing.T, runtime *pgx.Conn, keys replicaKeys, deviceID, jti string,
	expires time.Time) {
	t.Helper()
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.mark_session_proven_v1($1, $2)`, fingerprintOf(keys),
		nodeKeyOf(keys)); err != nil {
		t.Fatal(err)
	}
	var workspaceID, networkID string
	if err := tx.QueryRow(ctx, `SELECT workspace_public_id::TEXT, network_public_id::TEXT
FROM mesh_ops.resolve_map_session_scope($1, $2)`, fingerprintOf(keys), nodeKeyOf(keys)).Scan(&workspaceID,
		&networkID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.set_network_scope($1::UUID, $2::UUID)`, workspaceID,
		networkID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.consume_kubernetes_gateway_rotation_token_v1(
    $1::UUID, $2, $3, 'machine_key', 1, $4, $5)`, deviceID, fingerprintOf(keys), nodeKeyOf(keys), jti,
		expires); err != nil {
		t.Fatalf("record a token use: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

type tokenUse struct {
	keys    replicaKeys
	purpose string
}

// insertGatewayNodeEpoch writes the gateway's next node key epoch as the
// migrator would, rolled back, after recording use when it is not nil, and
// returns the SQLSTATE raised.
func insertGatewayNodeEpoch(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceID string, use *tokenUse) string {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if use != nil {
		if _, err := tx.Exec(ctx, `SELECT mesh_ops.mark_session_proven_v1($1, $2)`, fingerprintOf(use.keys),
			nodeKeyOf(use.keys)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT mesh_ops.set_network_scope(workspace.public_id, network.public_id)
FROM mesh.device AS device
JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
JOIN mesh.network AS network ON network.id = device.network_id
WHERE device.public_id = $1::UUID`, deviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT mesh_ops.consume_kubernetes_gateway_rotation_token_v1(
    $1::UUID, $2, $3, $4, 1, 'jti-node', $5)`, deviceID, fingerprintOf(use.keys), nodeKeyOf(use.keys), use.purpose,
			time.Now().Add(5*time.Minute)); err != nil {
			t.Fatalf("record a %s use: %v", use.purpose, err)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`); err != nil {
		t.Fatal(err)
	}
	next := newReplicaKeys(t).node.Bytes()
	fingerprint := sha256.Sum256(next[:])
	_, err = tx.Exec(ctx, `INSERT INTO mesh.device_node_key_epoch (
    public_id, workspace_id, network_id, device_id, epoch, public_key, fingerprint, valid_from, valid_until, state,
    created_at, updated_at)
SELECT pg_catalog.uuidv7(), device.workspace_id, device.network_id, device.id, device.current_node_key_epoch + 100,
    $2, $3, pg_catalog.now(), pg_catalog.now(), 'expired', pg_catalog.now(), pg_catalog.now()
FROM mesh.device AS device WHERE device.public_id = $1::UUID`, deviceID, next[:], fingerprint[:])
	return sqlState(t, err)
}

// assertTrustImmutableOnTheRequest checks that the trust a request carries
// never changes (design §6.3), even from NULL, and stays consistent with its
// code version.
func assertTrustImmutableOnTheRequest(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceID string) {
	t.Helper()
	for name, update := range map[string]string{
		"pod renamed":           `sa_pod_name = 'meshgw-99999'`,
		"code version back":     `code_version = 1`,
		"trust half removed":    `sa_digest = NULL`,
		"issuer to http":        `sa_issuer = 'http://kubernetes.default.svc.cluster.local'`,
		"key not among keys":    `sa_join_key_thumbprint = pg_catalog.sha256('other'::BYTEA)`,
		"pod of another sts":    `sa_pod_name = 'other-0'`,
		"pod without ordinal":   `sa_pod_name = 'meshgw-x'`,
		"digest of other trust": `sa_digest = pg_catalog.sha256('other'::BYTEA)`,
	} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `UPDATE mesh.kubernetes_replica_request AS request
SET `+update+`, version = request.version + 1
FROM mesh.device AS device WHERE device.public_id = $1::UUID AND request.device_id = device.id`, deviceID)
		if code := sqlState(t, err); code != "23514" {
			t.Errorf("%s: SQLSTATE %q, want 23514", name, code)
		}
		_ = tx.Rollback(ctx)
	}
	// Even past the transition guard, the CHECK keeps the trust whole.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `UPDATE mesh.kubernetes_replica_request AS request SET sa_digest = NULL
FROM mesh.device AS device WHERE device.public_id = $1::UUID AND request.device_id = device.id`, deviceID)
	if code := sqlState(t, err); code != "23514" {
		t.Fatalf("a version 2 request without its digest: SQLSTATE %q, want 23514", code)
	}
}

// assertTokenUsesPruned checks that pruning removes uses whose token expired
// more than five minutes ago, and only those.
func assertTokenUsesPruned(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceID string) {
	t.Helper()
	// One use expired ten minutes ago, past the margin; one a minute ago,
	// within it.
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_token_use
SET expires_at = pg_catalog.now() - INTERVAL '10 minutes' WHERE jti = 'jti-4'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO mesh_ops.kubernetes_gateway_token_use (
    kubernetes_cluster_id, jti, purpose, replaced_key, device_id, expires_at, xact_id, used_at)
SELECT use.kubernetes_cluster_id, 'jti-5', use.purpose, use.replaced_key, use.device_id,
    pg_catalog.now() - INTERVAL '1 minute', use.xact_id, use.used_at
FROM mesh_ops.kubernetes_gateway_token_use AS use WHERE use.jti = 'jti-4'`); err != nil {
		t.Fatal(err)
	}
	var installation string
	if err := admin.QueryRow(ctx, `SELECT deployment.installation_public_id::TEXT
FROM mesh.device AS device
JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
WHERE device.public_id = $1::UUID`, deviceID).Scan(&installation); err != nil {
		t.Fatal(err)
	}
	var removed int
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.prune_kubernetes_gateway_token_uses_v1($1::UUID, 100)`,
		installation).Scan(&removed); err != nil || removed != 1 {
		t.Fatalf("prune removed %d, %v", removed, err)
	}
	var left int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_token_use
WHERE jti IN ('jti-4', 'jti-5')`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("after pruning %d uses left, %v; want the one within the margin", left, err)
	}
}

func fingerprintOf(keys replicaKeys) []byte {
	fingerprint := keys.machine.Fingerprint()
	return bytes.Clone(fingerprint[:])
}

func nodeKeyOf(keys replicaKeys) []byte {
	key := keys.node.Bytes()
	return bytes.Clone(key[:])
}

// sqlState returns err's SQLSTATE, "" for no error.
func sqlState(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return pgError.Code
	}
	t.Fatalf("not a PostgreSQL error: %v", err)
	return ""
}

// The database computes the trust digest and the join code v2 exactly as
// shared/kubejoin does, so an administrator's code checks the same bytes in
// Go and in SQL.
func assertTrustDigestMatchesGo(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	jwks, err := kubejoin.ParseJWKS([]byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"a<b>&",` +
		`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	trust := kubejoin.Trust{Issuer: "https://oidc.eks.ap-southeast-1.amazonaws.com/id/ABC", JWKS: jwks,
		Namespace: "mt-kube-k1", ServiceAccount: "meshgw", PodName: "meshgw-12"}
	want, err := kubejoin.TrustDigest(trust)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.kubernetes_trust_digest_v1($1, $2, $3, $4, $5)`, trust.Issuer,
		jwks.Canonical(), trust.Namespace, trust.ServiceAccount, trust.PodName).Scan(&got); err != nil ||
		!bytes.Equal(got, want[:]) {
		t.Fatalf("SQL trust digest = %x, %v; Go = %x", got, err, want)
	}
	keys := newReplicaKeys(t)
	cluster := mustPublicID(t)
	var nonce [32]byte
	for index := range nonce {
		nonce[index] = byte(index + 7)
	}
	code, err := kubejoin.ComputeV2(kubejoin.Inputs{MachineKey: keys.machine.Bytes(), NodeKey: keys.node.Bytes(),
		ClusterID: [16]byte(cluster), RequestNonce: nonce}, want)
	if err != nil {
		t.Fatal(err)
	}
	bits, _ := code.Bits()
	machine, nodeKey := keys.machine.Bytes(), keys.node.Bytes()
	var sqlBits int64
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.kubernetes_join_code_v2($1, $2, $3::UUID, $4, $5)`, machine[:],
		nodeKey[:], cluster.String(), nonce[:], want[:]).Scan(&sqlBits); err != nil || uint64(sqlBits) != bits { //nolint:gosec // G115: a code has 50 bits
		t.Fatalf("SQL code bits = %d, %v; Go = %d (%s)", sqlBits, err, bits, code)
	}
}
