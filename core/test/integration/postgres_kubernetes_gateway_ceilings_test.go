//go:build integration

package integration

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubeprofile"
)

// assertGatewayCeilings checks schema 265 against a live gateway Device:
// its latest ceiling is kept and read back by the cluster's readers, an
// older one never replaces a newer, keys no gateway holds keep nothing, and
// the database keeps the shape whatever the caller.
func assertGatewayCeilings(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, keys replicaKeys, deviceID string, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID,
) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesGatewayCeilingStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	if granted, err := store.Granted(ctx); err != nil || !granted {
		t.Fatalf("Granted() = %t, %v", granted, err)
	}
	device, err := node.ParseID(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	machine := keys.machine.Fingerprint()
	nodeKey := keys.node.Bytes()
	body := func(verb string) kubecluster.CeilingBody {
		return kubecluster.CeilingBody{Groups: []kubecluster.CeilingGroup{{
			Group: "edit", ClusterRole: "edit",
			Everywhere: kubecluster.CeilingScope{Measured: true, Incomplete: true, Rules: []kubeprofile.Rule{
				{Verbs: []string{"get"}, NonResourceURLs: []string{"/api", "/api/*"}},
			}},
			Namespaces: []kubecluster.CeilingScope{{Namespace: "default", Measured: true, RulesDropped: 1,
				Rules: []kubeprofile.Rule{{APIGroups: []string{""}, Resources: []string{"pods", "pods/log"},
					Verbs: []string{verb}}, {APIGroups: []string{"x.io"}, Resources: []string{"things"},
					Verbs: []string{"get"}, ResourceNames: []string{`<a&"b\\c>`}}}}},
		}}}
	}
	record := func(body kubecluster.CeilingBody, checked, received time.Time,
		want postgresadapter.GatewayCeilingOutcome,
	) {
		t.Helper()
		ceiling, err := body.Encoded(checked, received)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := store.Record(ctx, machine, nodeKey[:], ceiling); err != nil || got != want {
			t.Fatalf("Record() = %d, %v; want %d", got, err, want)
		}
	}
	list := func() kubecluster.ClusterCeilings {
		t.Helper()
		ceilings, err := service.ListGroupCeilings(ctx, owner, scope, clusterID)
		if err != nil {
			t.Fatal(err)
		}
		return ceilings
	}
	hashOf := func(ceiling kubecluster.CeilingBody) string {
		_, hash, err := ceiling.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(hash[:])
	}

	if ceilings := list(); len(ceilings.Replicas) != 1 || ceilings.Replicas[0].DeviceID != device ||
		ceilings.Replicas[0].ContentHash != "" || len(ceilings.Bodies) != 0 {
		t.Fatalf("before any ceiling: %+v", ceilings)
	}
	received := time.Now().UTC().Truncate(time.Millisecond)
	checked := received.Add(-time.Minute)
	record(body("get"), checked, received, postgresadapter.GatewayCeilingStored)
	ceilings := list()
	if len(ceilings.Replicas) != 1 || ceilings.Replicas[0].ContentHash != hashOf(body("get")) ||
		!ceilings.Replicas[0].CheckedAt.Equal(checked) || !ceilings.Replicas[0].ReceivedAt.Equal(received) ||
		len(ceilings.Bodies) != 1 || ceilings.Bodies[0].Body.Groups[0].Namespaces[0].Rules[0].Verbs[0] != "get" ||
		!ceilings.Bodies[0].Body.Groups[0].Everywhere.Incomplete ||
		ceilings.Bodies[0].Body.Groups[0].Namespaces[0].Rules[1].ResourceNames[0] != `<a&"b\\c>` {
		t.Fatalf("after a ceiling: %+v", ceilings)
	}
	// An older ceiling, written late by another Core replica, changes nothing.
	record(body("list"), time.Time{}, received.Add(-time.Second), postgresadapter.GatewayCeilingOlder)
	if ceilings := list(); ceilings.Replicas[0].ContentHash != hashOf(body("get")) {
		t.Fatalf("an older ceiling replaced a newer: %+v", ceilings.Replicas[0])
	}
	// A measurement time far off the database's clock is not kept.
	record(body("watch"), received.Add(-60*24*time.Hour), received.Add(time.Second),
		postgresadapter.GatewayCeilingStored)
	watch := hashOf(body("watch"))
	if ceilings := list(); ceilings.Replicas[0].ContentHash != watch || !ceilings.Replicas[0].CheckedAt.IsZero() {
		t.Fatalf("a newer ceiling: %+v", ceilings.Replicas[0])
	}
	var hash [32]byte
	if _, err := hex.Decode(hash[:], []byte(watch)); err != nil {
		t.Fatal(err)
	}
	if document, err := service.ReadGroupCeiling(ctx, owner, scope, clusterID, hash); err != nil ||
		document.ContentHash != watch {
		t.Fatalf("ReadGroupCeiling() = %+v, %v", document, err)
	}
	if _, err := service.ReadGroupCeiling(ctx, owner, scope, clusterID, [32]byte{1}); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("an unknown hash: %v", err)
	}
	// Keys no gateway holds keep nothing.
	other := newReplicaKeys(t).node.Bytes()
	encoded, err := body("get").Encoded(time.Time{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.Record(ctx, machine, other[:], encoded); err != nil ||
		got != postgresadapter.GatewayCeilingNotGateway {
		t.Fatalf("other keys = %d, %v", got, err)
	}
	// The database keeps the shape and the bounds, whatever the caller; the
	// runtime role reads the table only through the functions.
	var pgError *pgconn.PgError
	for name, value := range map[string]string{
		"not an object":    `[]`,
		"no groups":        `{"truncated":false}`,
		"groups not array": `{"groups":{},"truncated":false}`,
		"no truncated":     `{"groups":[]}`,
		"null truncated":   `{"groups":[],"truncated":null}`,
		"65 groups":        `{"groups":[` + strings.Repeat(`{},`, 64) + `{}],"truncated":false}`,
	} {
		if _, err := runtime.Exec(ctx, `SELECT mesh_ops.record_kubernetes_gateway_ceiling_v1($1, $2, $3::JSONB,
$4, NULL, pg_catalog.clock_timestamp())`, machine[:], nodeKey[:], value, hash[:]); !errors.As(err, &pgError) ||
			pgError.Code != "22023" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := runtime.Exec(ctx, `SELECT mesh_ops.record_kubernetes_gateway_ceiling_v1($1, $2,
'{"groups":[],"truncated":false}'::JSONB, $3, NULL, pg_catalog.clock_timestamp() - INTERVAL '2 hours')`,
		machine[:], nodeKey[:], hash[:]); !errors.As(err, &pgError) || pgError.Code != "22023" {
		t.Errorf("a ceiling received two hours ago: %v", err)
	}
	if _, err := runtime.Exec(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_ceiling`); !errors.As(
		err, &pgError) || pgError.Code != "42501" {
		t.Errorf("the runtime role read the table: %v", err)
	}
	var kept int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_ceiling AS kept
JOIN mesh.device AS device ON device.id = kept.device_id WHERE device.public_id = $1::UUID`,
		deviceID).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("rows for the gateway: %d, %v", kept, err)
	}
	// A body changed behind Core's back no longer matches its hash: the
	// list leaves it out, keeping the replica's hash, and reading it is
	// unavailable, never wrong data.
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_ceiling SET body = pg_catalog.jsonb_set(
body, '{truncated}', 'true'::JSONB) WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`,
		deviceID); err != nil {
		t.Fatal(err)
	}
	if ceilings := list(); len(ceilings.Bodies) != 0 || ceilings.Replicas[0].ContentHash != watch {
		t.Fatalf("a damaged body was read: %+v", ceilings)
	}
	if _, err := service.ReadGroupCeiling(ctx, owner, scope, clusterID, hash); !errors.Is(err,
		kubecluster.ErrUnavailable) {
		t.Fatalf("reading a damaged body: %v", err)
	}
	// The next ceiling puts it right.
	record(body("watch"), time.Time{}, received.Add(2*time.Second), postgresadapter.GatewayCeilingStored)
	if ceilings := list(); len(ceilings.Bodies) != 1 {
		t.Fatalf("after a new ceiling: %+v", ceilings)
	}
	// Under 1 MiB as Core encodes it, over 1 MiB as PostgreSQL writes it
	// out: still read whole (review h4c re-check).
	short := make([]string, 64)
	for index := range short {
		short[index] = string(rune('a'+index%26)) + string(rune('a'+index/26))
	}
	wide := func() kubecluster.CeilingScope {
		scope := kubecluster.CeilingScope{Measured: true, Rules: []kubeprofile.Rule{}}
		for range 480 {
			scope.Rules = append(scope.Rules, kubeprofile.Rule{APIGroups: []string{""}, Resources: short,
				Verbs: []string{"get"}})
		}
		return scope
	}
	large := kubecluster.CeilingBody{Groups: []kubecluster.CeilingGroup{{Group: "edit", Everywhere: wide(),
		Namespaces: []kubecluster.CeilingScope{}}}}
	for _, namespace := range []string{"a", "b", "c", "d"} {
		scope := wide()
		scope.Namespace = namespace
		large.Groups[0].Namespaces = append(large.Groups[0].Namespaces, scope)
	}
	encodedLarge, largeHash, err := large.Encode()
	if err != nil || len(encodedLarge) >= kubecluster.MaximumCeilingBytes {
		t.Fatalf("the large body: %d bytes, %v", len(encodedLarge), err)
	}
	record(large, time.Time{}, received.Add(3*time.Second), postgresadapter.GatewayCeilingStored)
	var text int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.octet_length(body::TEXT) FROM mesh_ops.kubernetes_gateway_ceiling
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, deviceID).Scan(&text); err != nil ||
		text <= kubecluster.MaximumCeilingBytes {
		t.Fatalf("the stored text: %d bytes, %v", text, err)
	}
	if ceilings := list(); len(ceilings.Bodies) != 1 || ceilings.Bodies[0].ContentHash != hex.EncodeToString(largeHash[:]) {
		t.Fatalf("a large body was not read: %d bodies", len(ceilings.Bodies))
	}
	if _, err := service.ReadGroupCeiling(ctx, owner, scope, clusterID, largeHash); err != nil {
		t.Fatalf("reading a large body: %v", err)
	}
}
