//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// assertGatewayGroupReports checks schema 254 against a live gateway
// Device: the latest report is kept and read back with the replica, a group
// newly turned off is audited at most 4 times a cluster, group and day, and
// a session without gateway.groups1 reads as unsupported.
func assertGatewayGroupReports(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, keys replicaKeys, deviceID string, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID,
) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesGatewayGroupReportStore(runtimePool)
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
	group := func(name, state, reason string) kubecluster.GatewayGroupStatus {
		return kubecluster.GatewayGroupStatus{Group: name, State: state, Reason: reason}
	}
	view := group("view", kubecluster.GroupStateEnabled, kubecluster.GroupReasonNone)
	editOff := group("edit", kubecluster.GroupStateDisabled, kubecluster.GroupReasonRBACExceeds)
	editOn := group("edit", kubecluster.GroupStateEnabled, kubecluster.GroupReasonNone)
	record := func(report kubecluster.GatewayGroupReport, want postgresadapter.GatewayGroupReportOutcome) {
		t.Helper()
		if report.ReceivedAt.IsZero() {
			report.ReceivedAt = time.Now()
		}
		if got, err := store.Record(ctx, machine, nodeKey[:], report); err != nil || got != want {
			t.Fatalf("Record(%+v) = %d, %v; want %d", report, got, err, want)
		}
	}
	events := func() int {
		t.Helper()
		var count int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'kubernetes_gateway_group_event' AND action = 'kubernetes_gateway.group_disabled'
  AND target_public_id IN (SELECT public_id FROM mesh_ops.kubernetes_gateway_group_event
                           WHERE device_public_id = $1::UUID)`, deviceID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	read := func() kubecluster.ReplicaGroups {
		t.Helper()
		replica, err := service.ReadReplica(ctx, owner, scope, clusterID, device)
		if err != nil {
			t.Fatal(err)
		}
		return replica.Groups
	}

	if groups := read(); groups.Status != kubecluster.GroupReportNone || len(groups.Items) != 0 {
		t.Fatalf("before any report: %+v", groups)
	}
	checked := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)
	record(kubecluster.GatewayGroupReport{Supported: true, CheckedAt: checked,
		Groups: []kubecluster.GatewayGroupStatus{view, editOff}}, postgresadapter.GatewayGroupReportAudited)
	if events() != 1 {
		t.Fatalf("group_disabled events: %d, want 1", events())
	}
	groups := read()
	if groups.Status != kubecluster.GroupReportCurrent || len(groups.Items) != 2 ||
		groups.Items[1] != editOff || !groups.CheckedAt.Equal(checked) {
		t.Fatalf("after a report: %+v", groups)
	}
	// The same news again is kept, not audited.
	record(kubecluster.GatewayGroupReport{Supported: true, Groups: []kubecluster.GatewayGroupStatus{view, editOff}},
		postgresadapter.GatewayGroupReportStored)
	// Off and on again: three more audits in the day, then none.
	for range 3 {
		record(kubecluster.GatewayGroupReport{Supported: true, Groups: []kubecluster.GatewayGroupStatus{editOn}},
			postgresadapter.GatewayGroupReportStored)
		record(kubecluster.GatewayGroupReport{Supported: true, Groups: []kubecluster.GatewayGroupStatus{editOff}},
			postgresadapter.GatewayGroupReportAudited)
	}
	record(kubecluster.GatewayGroupReport{Supported: true, Groups: []kubecluster.GatewayGroupStatus{editOn}},
		postgresadapter.GatewayGroupReportStored)
	record(kubecluster.GatewayGroupReport{Supported: true, Groups: []kubecluster.GatewayGroupStatus{editOff}},
		postgresadapter.GatewayGroupReportStored)
	if events() != 4 {
		t.Fatalf("group_disabled events: %d, want 4 a day", events())
	}

	// Over 20 minutes old reads as stale.
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_group_report
SET reported_at = reported_at - INTERVAL '21 minutes'
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, deviceID); err != nil {
		t.Fatal(err)
	}
	if groups := read(); groups.Status != kubecluster.GroupReportStale {
		t.Fatalf("an old report: %+v", groups)
	}
	// A session of a meshgw that does not report.
	record(kubecluster.GatewayGroupReport{Supported: false}, postgresadapter.GatewayGroupReportStored)
	if groups := read(); groups.Status != kubecluster.GroupReportUnsupported || len(groups.Items) != 0 {
		t.Fatalf("an older meshgw: %+v", groups)
	}
	// Keys no gateway holds.
	other := newReplicaKeys(t).node.Bytes()
	if got, err := store.Record(ctx, machine, other[:], kubecluster.GatewayGroupReport{Supported: true,
		ReceivedAt: time.Now()}); err != nil ||
		got != postgresadapter.GatewayGroupReportNotGateway {
		t.Fatalf("other keys = %d, %v", got, err)
	}
	// The database refuses what §6.11 does, whatever the caller.
	var pgError *pgconn.PgError
	for name, groups := range map[string]string{
		"an invalid group name": `[{"group":"Edit","privileged":false,"state":"enabled","reason":"none"}]`,
		"enabled for a reason":  `[{"group":"edit","privileged":false,"state":"enabled","reason":"rbac_exceeds"}]`,
		"impersonation off, not privileged": `[{"group":"edit","privileged":false,"state":"enabled",` +
			`"reason":"impersonation_off"}]`,
	} {
		if _, err := runtime.Exec(ctx, `SELECT mesh_ops.record_kubernetes_gateway_group_report_v1($1, $2, TRUE,
$3::JSONB, FALSE, NULL, pg_catalog.clock_timestamp(),
'01890f00-0000-7000-8000-0000000c0001', '01890f00-0000-7000-8000-0000000c0002')`, machine[:], nodeKey[:],
			groups); !errors.As(err, &pgError) || pgError.Code != "22023" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A report another Core replica took later is never replaced by an
	// older one retried here.
	record(kubecluster.GatewayGroupReport{Supported: true, Groups: []kubecluster.GatewayGroupStatus{view}},
		postgresadapter.GatewayGroupReportStored)
	record(kubecluster.GatewayGroupReport{Supported: true, ReceivedAt: time.Now().Add(-time.Minute),
		Groups: []kubecluster.GatewayGroupStatus{editOff}}, postgresadapter.GatewayGroupReportStored)
	if groups := read(); len(groups.Items) != 1 || groups.Items[0] != view {
		t.Fatalf("an older report replaced a newer one: %+v", groups)
	}
	// However a gateway names its groups, its audit is bounded: 48 events a
	// Device and day (4 so far).
	audited := 0
	for index := range 50 {
		name := fmt.Sprintf("flood-%d", index)
		report := kubecluster.GatewayGroupReport{Supported: true, ReceivedAt: time.Now(),
			Groups: []kubecluster.GatewayGroupStatus{group(name, kubecluster.GroupStateDisabled,
				kubecluster.GroupReasonRBACExceeds)}}
		outcome, err := store.Record(ctx, machine, nodeKey[:], report)
		if err != nil {
			t.Fatal(err)
		}
		if outcome == postgresadapter.GatewayGroupReportAudited {
			audited++
		}
	}
	if audited != 44 || events() != 48 {
		t.Fatalf("a flood audited %d reports, %d events in all; want 44 and 48", audited, events())
	}
	// Forgotten for the checks that follow.
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_group_event
SET recorded_at = recorded_at - INTERVAL '2 days'`); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Exec(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_group_report`); !errors.As(
		err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("the runtime role read the report table: %v", err)
	}
}
