//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

// mapScopeIDs returns the fixture Network's internal Workspace and Network
// IDs, as the map's inventory transaction scopes them.
func mapScopeIDs(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture) (int64, int64) {
	t.Helper()
	var workspaceID, networkID int64
	if err := admin.QueryRow(ctx, `SELECT network.workspace_id, network.id FROM mesh.network AS network
WHERE network.public_id = $1::UUID`, fixture.scope.NetworkID().String()).Scan(&workspaceID, &networkID); err != nil {
		t.Fatal(err)
	}
	return workspaceID, networkID
}

// readMapScoped runs query, answering one text value, as the map's runtime
// role in the scope of workspaceID and networkID.
func readMapScoped(ctx context.Context, runtime *pgx.Conn, workspaceID, networkID int64, query string,
	arguments ...any,
) (string, error) {
	tx, err := runtime.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', $1::TEXT, TRUE),
    pg_catalog.set_config('mesh.network_id', $2::TEXT, TRUE)`, strconv.FormatInt(workspaceID, 10),
		strconv.FormatInt(networkID, 10)); err != nil {
		return "", err
	}
	var encoded string
	err = tx.QueryRow(ctx, query, arguments...).Scan(&encoded)
	return encoded, err
}

// assertMapKubernetesClientCAs: schema 244 names, for each active cluster of
// the map's Network, its ID, the TLS name its gateways' certificates carry,
// the gateway's CAs as v1 does, and the roots a client trusts; the roots'
// DER comes by fingerprint, roots of the Network only (K1a4d design §3.1).
func assertMapKubernetesClientCAs(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	fixture clusterCAFixture, root, intermediate kubeca.StoredCA,
) {
	t.Helper()
	workspaceID, networkID := mapScopeIDs(ctx, t, admin, fixture)
	encoded, err := readMapScoped(ctx, runtime, workspaceID, networkID,
		`SELECT mesh_ops.load_map_network_kubernetes_cas_v2(10)::TEXT`)
	if err != nil {
		t.Fatalf("read the map's client CAs: %v", err)
	}
	answer := decodeCertificateAnswer(t, encoded)
	rootPrint, signingPrint := sha256.Sum256(root.Certificate), sha256.Sum256(intermediate.Certificate)
	clusters, _ := answer["clusters"].([]any)
	var found map[string]any
	for _, entry := range clusters {
		if cluster, _ := entry.(map[string]any); cluster["id"] == fixture.cluster.String() {
			found = cluster
		}
	}
	trusted, _ := found["trusted"].([]any)
	if answer["withheld"] != false || found == nil || found["signing"] != hex.EncodeToString(signingPrint[:]) ||
		found["signing_root"] != hex.EncodeToString(rootPrint[:]) || found["tls_name"] != fixture.dnsName ||
		len(trusted) != 1 || trusted[0] != hex.EncodeToString(rootPrint[:]) {
		t.Fatalf("the map's client CAs: %v", answer)
	}

	roots := func(fingerprints ...[]byte) map[string]any {
		t.Helper()
		encoded, err := readMapScoped(ctx, runtime, workspaceID, networkID,
			`SELECT mesh_ops.load_map_kubernetes_ca_roots_v1($1::BYTEA[])::TEXT`, fingerprints)
		if err != nil {
			t.Fatalf("read roots: %v", err)
		}
		return decodeCertificateAnswer(t, encoded)
	}
	// The root, never the intermediate, whatever is asked.
	read := roots(rootPrint[:], signingPrint[:], make([]byte, 32))
	der, _ := read["roots"].([]any)
	if read["withheld"] != false || len(der) != 1 || der[0] != hex.EncodeToString(root.Certificate) {
		t.Fatalf("roots read: %v", read)
	}
	// Another Network's scope reads none of them.
	other, err := readMapScoped(ctx, runtime, workspaceID, networkID+1_000_000,
		`SELECT mesh_ops.load_map_kubernetes_ca_roots_v1($1::BYTEA[])::TEXT`, [][]byte{rootPrint[:]})
	if err != nil {
		t.Fatalf("read roots of another Network: %v", err)
	}
	if otherRoots, _ := decodeCertificateAnswer(t, other)["roots"].([]any); len(otherRoots) != 0 {
		t.Fatalf("another Network read the roots: %v", other)
	}
	// At most 1,024 fingerprints a read, none empty.
	tooMany := make([][]byte, 1025)
	for index := range tooMany {
		tooMany[index] = rootPrint[:]
	}
	for name, fingerprints := range map[string][][]byte{"1025": tooMany, "none": {}, "null": {nil}} {
		_, err := readMapScoped(ctx, runtime, workspaceID, networkID,
			`SELECT mesh_ops.load_map_kubernetes_ca_roots_v1($1::BYTEA[])::TEXT`, fingerprints)
		if postgresError, ok := errors.AsType[*pgconn.PgError](err); !ok || postgresError.Code != "22023" {
			t.Fatalf("%s fingerprints: %v", name, err)
		}
	}
	// A next root is trusted, after the active one (id order), and read;
	// once retired, neither (design §2.4).
	next := fixture.creation(t, fixture.newRoot(t, fixture.dnsName), publicid.ID{}, kubeca.StateNext,
		kubeca.ReasonAdmin)
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{{Create: next}}})
	nextPrint := sha256.Sum256(next.Certificate)
	trustedRoots := func() []any {
		t.Helper()
		encoded, err := readMapScoped(ctx, runtime, workspaceID, networkID,
			`SELECT mesh_ops.load_map_network_kubernetes_cas_v2(10)::TEXT`)
		if err != nil {
			t.Fatal(err)
		}
		clusters, _ := decodeCertificateAnswer(t, encoded)["clusters"].([]any)
		for _, entry := range clusters {
			if cluster, _ := entry.(map[string]any); cluster["id"] == fixture.cluster.String() {
				trusted, _ := cluster["trusted"].([]any)
				return trusted
			}
		}
		return nil
	}
	if trusted := trustedRoots(); len(trusted) != 2 || trusted[0] != hex.EncodeToString(rootPrint[:]) ||
		trusted[1] != hex.EncodeToString(nextPrint[:]) {
		t.Fatalf("trusted with a next root: %v", trusted)
	}
	if read, _ := roots(nextPrint[:])["roots"].([]any); len(read) != 1 {
		t.Fatalf("the next root's DER: %v", read)
	}
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{
		move(next.ID, 1, kubeca.StateRetired, kubeca.ReasonAdmin),
	}})
	if trusted := trustedRoots(); len(trusted) != 1 || trusted[0] != hex.EncodeToString(rootPrint[:]) {
		t.Fatalf("trusted after the next root retired: %v", trusted)
	}
	if read, _ := roots(nextPrint[:])["roots"].([]any); len(read) != 0 {
		t.Fatalf("a retired root's DER: %v", read)
	}
	// Only the map's runtime role runs either.
	for _, role := range []string{"mesh_worker", "mesh_observer", "mesh_audit_writer", "mesh_share_writer"} {
		for _, function := range []string{
			"mesh_ops.load_map_network_kubernetes_cas_v2(integer)",
			"mesh_ops.load_map_kubernetes_ca_roots_v1(bytea[])",
		} {
			var granted bool
			if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege($1, $2, 'EXECUTE')`, role,
				function).Scan(&granted); err != nil || granted {
				t.Fatalf("%s may run %s (%v)", role, function, err)
			}
		}
	}
}

// assertMapKubernetesClientCAsWithheld: while a restore is suspected both
// schema 244 readers withhold.
func assertMapKubernetesClientCAsWithheld(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	fixture clusterCAFixture, root kubeca.StoredCA,
) {
	t.Helper()
	workspaceID, networkID := mapScopeIDs(ctx, t, admin, fixture)
	rootPrint := sha256.Sum256(root.Certificate)
	for query, arguments := range map[string][]any{
		`SELECT mesh_ops.load_map_network_kubernetes_cas_v2(10)::TEXT`:       nil,
		`SELECT mesh_ops.load_map_kubernetes_ca_roots_v1($1::BYTEA[])::TEXT`: {[][]byte{rootPrint[:]}},
	} {
		encoded, err := readMapScoped(ctx, runtime, workspaceID, networkID, query, arguments...)
		if err != nil {
			t.Fatal(err)
		}
		if answer := decodeCertificateAnswer(t, encoded); answer["withheld"] != true {
			t.Fatalf("%s while a restore is suspected: %v", query, answer)
		}
	}
}
