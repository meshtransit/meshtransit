//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/config"
)

func TestRoleWorkerProcessExpiryConvergesAcrossRestart(t *testing.T) {
	if os.Getenv("MESHTRANSIT_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_INTEGRATION=1 with disposable TLS dependencies")
	}
	binary := validateTestBinary(t, os.Getenv(testMeshcoreBinaryEnvironment))
	settings, err := config.Load(os.LookupEnv)
	if err != nil || settings.Storage == nil {
		t.Fatal("load process configuration", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	adminSettings := loadIntegrationAdminConfig(t)
	admin := openIntegrationPostgreSQLConnection(
		ctx,
		t,
		adminSettings.PostgreSQL.Address,
		adminSettings.PostgreSQL.Database,
		adminSettings.PostgreSQL.User,
		adminSettings.PostgreSQL.PasswordFile,
		adminSettings.PostgreSQL.CAFile,
		adminSettings.ConnectTimeout,
	)
	pool := openDependencyRolePool(
		ctx,
		t,
		postgresadapter.PoolRoleRuntime,
		settings.Storage.PostgreSQL,
		settings.Storage.PostgreSQL.Runtime,
		settings.Dependencies.CheckTimeout,
	)
	creation, err := postgresadapter.NewAuthTransactionStore(pool, testProcessExpirySQLBounds())
	if err != nil {
		t.Fatal(err)
	}
	for _, cycle := range []struct {
		role, suffix string
		consuming    bool
	}{
		{role: "worker", suffix: "fe2"}, {role: "worker", suffix: "fe3", consuming: true},
	} {
		t.Run(cycle.role+"-"+cycle.suffix, func(t *testing.T) {
			snapshot := integrationExpirySnapshot(ctx, t, admin, creation, cycle.suffix, cycle.consuming)
			before := authAdmissionAuthorityCounts(ctx, t, admin)
			var sessionsBefore []byte
			if err := admin.QueryRow(ctx, integrationExpirySessionStateSQL).Scan(&sessionsBefore); err != nil {
				t.Fatal(err)
			}
			health := reserveLoopbackAddress(t)
			environment := integrationProcessEnvironment(health, reserveLoopbackAddress(t))
			for _, setting := range []struct{ key, value string }{
				{key: "MESHTRANSIT_ROLE", value: cycle.role},
				{key: "MESHTRANSIT_SHUTDOWN_TIMEOUT", value: "5s"},
				{key: "MESHTRANSIT_AUTH_EXPIRY_ENABLED", value: "true"},
				{key: "MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID", value: snapshot.DeploymentID().String()},
				{key: "MESHTRANSIT_AUTH_EXPIRY_BATCH_SIZE", value: "1"},
				{key: "MESHTRANSIT_AUTH_EXPIRY_POLL_INTERVAL", value: "100ms"},
				{key: "MESHTRANSIT_AUTH_EXPIRY_SWEEP_TIMEOUT", value: "3s"},
			} {
				environment = setEnvironmentValue(environment, setting.key, setting.value)
			}
			process := startIntegrationProcess(t, binary, environment)
			t.Cleanup(func() { process.forceStop(t) })
			start, cancelStart := context.WithTimeout(ctx, 15*time.Second)
			err := waitForReady(start, process, health)
			cancelStart()
			if err != nil {
				process.forceStop(t)
				t.Fatal("expiry process did not start", err)
			}
			pass, cancelPass := context.WithTimeout(ctx, 5*time.Second)
			err = waitForProcessExpiryMetrics(
				pass,
				process,
				health,
				processExpiryExpectation{snapshot: snapshot, confirmed: 1},
			)
			cancelPass()
			if err != nil {
				process.forceStop(t)
				t.Fatal("expiry process did not converge", err)
			}
			stopIntegrationProcess(t, process)
			// Read stderr only after the child and its writing goroutines joined.
			for _, private := range []string{snapshot.DeploymentID().String(), snapshot.TransactionID().String()} {
				if strings.Contains(process.stderr.String(), private) {
					t.Fatal("process logged private assignment")
				}
			}
			command := readProcessExpiryCommand(ctx, t, admin, snapshot)
			assertExpiryEvidence(ctx, t, admin, command)
			after := authAdmissionAuthorityCounts(ctx, t, admin)
			if after[0] != before[0] || after[1] != before[1]+1 || after[2] != before[2]+1 ||
				after[3] != before[3]+1 || after[4] != before[4] {
				t.Fatal("poller duplicated evidence or changed Network authority")
			}
			var sessionsAfter []byte
			if err := admin.QueryRow(ctx, integrationExpirySessionStateSQL).Scan(&sessionsAfter); err != nil ||
				!bytes.Equal(sessionsBefore, sessionsAfter) {
				t.Fatal("poller changed issued Sessions", err)
			}
			// Restart the same assignment without creating another Auth. A fresh
			// successful empty pass must not replay the previous terminal mutation.
			restarted := startIntegrationProcess(t, binary, environment)
			t.Cleanup(func() { restarted.forceStop(t) })
			restart, cancelRestart := context.WithTimeout(ctx, 15*time.Second)
			err = waitForReady(restart, restarted, health)
			cancelRestart()
			if err == nil {
				recheck, cancelRecheck := context.WithTimeout(ctx, 5*time.Second)
				err = waitForProcessExpiryMetrics(
					recheck,
					restarted,
					health,
					processExpiryExpectation{snapshot: snapshot},
				)
				cancelRecheck()
			}
			if err != nil {
				restarted.forceStop(t)
				t.Fatal("same-assignment restart did not converge", err)
			}
			stopIntegrationProcess(t, restarted)
			if authAdmissionAuthorityCounts(ctx, t, admin) != after {
				t.Fatal("restart replayed authority/evidence")
			}
			assertExpiryEvidence(ctx, t, admin, command)
			if err := admin.QueryRow(ctx, integrationExpirySessionStateSQL).Scan(&sessionsAfter); err != nil ||
				!bytes.Equal(sessionsBefore, sessionsAfter) {
				t.Fatal("restart changed issued Sessions", err)
			}
		})
	}
}

func testProcessExpirySQLBounds() postgresadapter.AuthTransactionOptions {
	return postgresadapter.AuthTransactionOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second,
	}
}

type processExpiryExpectation struct {
	snapshot  oidcauth.ExpirySnapshot
	confirmed uint64
}

func waitForProcessExpiryMetrics(
	ctx context.Context,
	process *integrationProcess,
	address string,
	expectation processExpiryExpectation,
) error {
	snapshot := expectation.snapshot
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	timer := time.NewTicker(20 * time.Millisecond)
	defer timer.Stop()
	for {
		if exited, err := process.poll(); exited {
			return errors.Join(errors.New("expiry worker exited"), err)
		}
		status, body, err := integrationGET(ctx, client, address, "/metrics")
		if err == nil && status == http.StatusOK {
			if strings.Contains(body, snapshot.DeploymentID().String()) ||
				strings.Contains(body, snapshot.TransactionID().String()) {
				return errors.New("private assignment entered metrics")
			}
			running, live := parseProcessMetric(body, "meshtransit_oidc_expiry_worker_running")
			confirmed, receipts := parseProcessMetric(body, "meshtransit_oidc_expiry_units_confirmed_total")
			success := processExpiryTimestampPositive(body)
			if live && receipts && success && running == 1 && confirmed == expectation.confirmed {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func processExpiryTimestampPositive(body string) bool {
	for line := range strings.SplitSeq(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "meshtransit_oidc_expiry_last_success_timestamp_seconds" {
			continue
		}
		// Prometheus gauges may encode an integral timestamp in scientific notation.
		value, err := strconv.ParseFloat(fields[1], 64)
		return err == nil && value > 0 && value < 1e11
	}
	return false
}

func FuzzProcessExpiryTimestamp(f *testing.F) {
	f.Add("meshtransit_oidc_expiry_last_success_timestamp_seconds 1.789e+09\n")
	f.Add("meshtransit_oidc_expiry_last_success_timestamp_seconds NaN\n")
	f.Add("meshtransit_oidc_expiry_last_success_timestamp_seconds +Inf\n")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		positive := processExpiryTimestampPositive(body)
		if positive && !strings.Contains(body, "meshtransit_oidc_expiry_last_success_timestamp_seconds") {
			t.Fatal("unrelated metric admitted")
		}
	})
}

func readProcessExpiryCommand(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	snapshot oidcauth.ExpirySnapshot,
) oidcauth.ExpiryCommand {
	t.Helper()
	// Exact target/version access via the existing mutation row/aggregate index;
	// joins use indexed change IDs. This is read-only disposable admin evidence.
	var change, event, outbox string
	var count int64
	if err := admin.QueryRow(ctx, `SELECT mutation.change_public_id::TEXT,
    identity.public_id::TEXT, outbox.public_id::TEXT, count(*) OVER ()
    FROM mesh_audit.authority_mutation AS mutation
    JOIN mesh_audit.audit_event_identity AS identity
      ON identity.change_public_id=mutation.change_public_id AND identity.transaction_id=mutation.transaction_id
    JOIN mesh_ops.outbox_event AS outbox
      ON outbox.change_public_id=mutation.change_public_id AND outbox.transaction_id=mutation.transaction_id
    WHERE mutation.row_public_id=$1::UUID AND mutation.aggregate_kind='auth_transaction'
      AND mutation.before_version=$2::BIGINT AND mutation.after_version=$3::BIGINT`,
		snapshot.TransactionID().String(),
		snapshot.Version(),
		snapshot.Version()+1,
	).Scan(&change, &event, &outbox, &count); err != nil || count != 1 {
		t.Fatal("unique process expiry mutation/evidence not found", err)
	}
	changeID, changeErr := publicid.Parse(change)
	eventID, eventErr := publicid.Parse(event)
	outboxID, outboxErr := publicid.Parse(outbox)
	if errors.Join(changeErr, eventErr, outboxErr) != nil {
		t.Fatal("process evidence IDs invalid")
	}
	ids, err := oidcauth.NewMutationIDs(oidcauth.MutationIDParams{
		ChangeID: changeID, AuditEventID: eventID, OutboxEventID: outboxID,
	})
	if err != nil {
		t.Fatal(err)
	}
	command, err := oidcauth.NewExpiryCommand(snapshot, ids)
	if err != nil {
		t.Fatal(err)
	}
	return command
}
