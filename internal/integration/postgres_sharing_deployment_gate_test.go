//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func assertDeviceSharingDeploymentPreflight(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	source, err := os.ReadFile("../../scripts/qualification/check-device-sharing-database.sql")
	if err != nil {
		t.Fatal("read deployable sharing gate", err)
	}
	if _, err := admin.Exec(ctx, string(source)); err != nil {
		t.Fatal("sharing deployment preflight", err)
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, `REVOKE EXECUTE ON FUNCTION mesh_ops.create_resource_share_offer_v1(
        BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID,
        BIGINT, BIGINT, BYTEA, UUID, UUID, JSONB, JSONB, BYTEA, BYTEA,
        BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ
    ) FROM mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	gate := strings.ReplaceAll(strings.ReplaceAll(string(source), "BEGIN READ ONLY;", ""), "ROLLBACK;", "")
	_, err = transaction.Exec(ctx, gate)
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || postgresError.Code != "P0001" || postgresError.Message != "Device sharing function profile failed: create_resource_share_offer_v1" {
		t.Fatal("deployment gate failed to catch a missing runtime offer grant", err)
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, string(source)); err != nil {
		t.Fatal("gate did not recover after rollback", err)
	}
}
