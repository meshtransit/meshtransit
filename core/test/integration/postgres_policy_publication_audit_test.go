//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
)

// policyChangeSummaryWant is the change summary a policy.published event must
// carry. A nil want only checks that the event names its revision and has a
// summary.
type policyChangeSummaryWant struct {
	Baseline  string                 `json:"baseline"`
	Added     int                    `json:"added"`
	Removed   int                    `json:"removed"`
	Changed   int                    `json:"changed"`
	Unchanged int                    `json:"unchanged"`
	Rules     []policyRuleChangeWant `json:"rules"`
	Truncated bool                   `json:"truncated"`
}

type policyRuleChangeWant struct {
	Change          string `json:"change"`
	RuleID          string `json:"rule_id"`
	DestinationKind string `json:"destination_kind"`
	DestinationID   string `json:"destination_id"`
}

// assertPolicyPublicationChangeSummary reads the sealed policy.published event
// of one release and checks its revision and what it says changed.
func assertPolicyPublicationChangeSummary(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	releaseID string,
	policyRevision int64,
	want *policyChangeSummaryWant,
) {
	t.Helper()
	var encoded []byte
	if err := admin.QueryRow(ctx, `SELECT payload::TEXT
FROM mesh_audit.audit_event
WHERE target_kind = 'policy_release' AND target_public_id = $1::UUID
  AND action = 'policy.published'`, releaseID).Scan(&encoded); err != nil {
		t.Fatalf("query policy.published event of release %s: %v", releaseID, err)
	}
	var payload struct {
		PolicyRevision int64                    `json:"policy_revision"`
		ChangeSummary  *policyChangeSummaryWant `json:"change_summary"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("decode policy.published payload: %v", err)
	}
	if payload.PolicyRevision != policyRevision || payload.ChangeSummary == nil {
		t.Fatalf("policy.published payload = %s, want policy_revision %d and a change_summary",
			encoded, policyRevision)
	}
	if want == nil {
		return
	}
	if want.Rules == nil {
		want.Rules = []policyRuleChangeWant{}
	}
	if !reflect.DeepEqual(*payload.ChangeSummary, *want) {
		t.Fatalf("change_summary = %+v, want %+v", *payload.ChangeSummary, *want)
	}
}

// assertPolicyReleaseFingerprintGuards checks, in transactions it rolls
// back, that a release's fingerprints can only be written once, by the
// transaction that published it, in a valid frame; that they are read only
// in their own Network; that runtime cannot reach the table; and that rows
// never change.
func assertPolicyReleaseFingerprintGuards(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	releaseID string,
	wantRules int,
) {
	t.Helper()
	inTransaction := func(_ string, workspaceID, networkID int64, run func(pgx.Tx) error) error {
		t.Helper()
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = transaction.Rollback(ctx) }()
		setIntegrationScope(ctx, t, transaction, workspaceID, networkID)
		return run(transaction)
	}
	var stored []byte
	var ruleCount int
	if err := inTransaction("read", 103, 203, func(transaction pgx.Tx) error {
		return transaction.QueryRow(ctx, `SELECT mesh_ops.read_policy_release_rule_fingerprints_v1($1::UUID),
    (SELECT rule_count FROM mesh.policy_release_rule_fingerprint AS stored
     JOIN mesh.policy_release AS release ON release.id = stored.policy_release_id
     WHERE release.public_id = $1::UUID)`, releaseID).Scan(&stored, &ruleCount)
	}); err != nil || len(stored) != 5+49*wantRules || ruleCount != wantRules {
		t.Fatalf("stored fingerprints of %s = %d bytes, %d rules, error %v; want %d rules",
			releaseID, len(stored), ruleCount, err, wantRules)
	}
	var otherNetwork []byte
	if err := inTransaction("read elsewhere", 103, 204, func(transaction pgx.Tx) error {
		return transaction.QueryRow(ctx, `SELECT mesh_ops.read_policy_release_rule_fingerprints_v1($1::UUID)`,
			releaseID).Scan(&otherNetwork)
	}); err != nil || otherNetwork != nil {
		t.Fatalf("another Network read %d bytes of the fingerprints, error %v", len(otherNetwork), err)
	}
	record := func(frame []byte) func(pgx.Tx) error {
		return func(transaction pgx.Tx) error {
			_, err := transaction.Exec(ctx,
				`SELECT mesh_ops.record_policy_release_rule_fingerprints_v1($1::UUID, $2::BYTEA)`, releaseID, frame)
			return err
		}
	}
	for name, frame := range map[string][]byte{
		"a release published earlier": {1, 0, 0, 0, 0},
		"an unknown format":           {2, 0, 0, 0, 0},
		"a count the bytes lack":      {1, 0, 0, 0, 1},
		"no frame":                    {},
	} {
		assertPostgreSQLCode(t, inTransaction(name, 103, 203, record(frame)), "23514")
	}
	assertPostgreSQLCode(t, inTransaction("runtime read", 103, 203, func(transaction pgx.Tx) error {
		if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			return err
		}
		_, err := transaction.Exec(ctx, `SELECT count(*) FROM mesh.policy_release_rule_fingerprint`)
		return err
	}), "42501")
	if err := inTransaction("update", 103, 203, func(transaction pgx.Tx) error {
		_, err := transaction.Exec(ctx, `UPDATE mesh.policy_release_rule_fingerprint AS stored
SET fingerprints = stored.fingerprints
FROM mesh.policy_release AS release
WHERE release.id = stored.policy_release_id AND release.public_id = $1::UUID`, releaseID)
		return err
	}); err == nil {
		t.Fatal("stored fingerprints could be updated")
	}
}

// assertJSONBTextForms checks the jsonb text forms the publication payload
// bound relies on (TestJSONBTextLengthMatchesPostgreSQLOutput) against the
// real server, since the audit_event CHECK measures payload::TEXT.
func assertJSONBTextForms(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	tests := map[string]string{
		`{}`:                           `{}`,
		`{"a":1}`:                      `{"a": 1}`,
		`{"a":[1,2],"b":{"c":true}}`:   `{"a": [1, 2], "b": {"c": true}}`,
		`{"a":"x:,y","b":"q\"u:o,te"}`: `{"a": "x:,y", "b": "q\"u:o,te"}`,
		`{"a":"back\\","b":[]}`:        `{"a": "back\\", "b": []}`,
	}
	for input, want := range tests {
		var got string
		if err := admin.QueryRow(ctx, `SELECT $1::JSONB::TEXT`, input).Scan(&got); err != nil || got != want {
			t.Fatalf("%s::jsonb::text = %q, error %v; want %q", input, got, err, want)
		}
	}
}
