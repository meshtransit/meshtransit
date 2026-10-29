package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/kubeaudit"
)

const testAuditID = "01890f00-0000-7000-8000-000000000301"

// The writer's answer is taken only in full: the count asked, known
// outcomes, an audit_id exactly on a recorded one.
func TestDecodeOperationAnswers(t *testing.T) {
	t.Parallel()
	got, err := decodeOperationAnswers(`{"answers": [{"outcome": "accepted", "audit_id": "`+testAuditID+
		`"}, {"outcome": "conflict", "audit_id": null}, {"outcome": "duplicate", "audit_id": "`+testAuditID+`"}]}`, 3)
	if err != nil || got[0].Outcome != kubeaudit.OutcomeAccepted || got[0].AuditID.String() != testAuditID ||
		got[1].Outcome != kubeaudit.OutcomeConflict || got[1].AuditID.IsValid() ||
		got[2].Outcome != kubeaudit.OutcomeDuplicate {
		t.Fatalf("answers %+v, %v", got, err)
	}
	for name, answer := range map[string]string{
		"too few":          `{"answers": [{"outcome": "conflict", "audit_id": null}]}`,
		"unknown outcome":  `{"answers": [{"outcome": "stale", "audit_id": null}, {"outcome": "invalid", "audit_id": null}]}`,
		"refused with ID":  `{"answers": [{"outcome": "gateway", "audit_id": "` + testAuditID + `"}, {"outcome": "invalid", "audit_id": null}]}`,
		"accepted no ID":   `{"answers": [{"outcome": "accepted", "audit_id": null}, {"outcome": "invalid", "audit_id": null}]}`,
		"bad ID":           `{"answers": [{"outcome": "accepted", "audit_id": "x"}, {"outcome": "invalid", "audit_id": null}]}`,
		"unknown field":    `{"answers": [], "more": 1}`,
		"not an answer":    `[]`,
		"trailing content": `{"answers": []} {}`,
	} {
		if _, err := decodeOperationAnswers(answer, 2); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// Only SQLSTATE classes 22 and 23 are a row's data, through any wrapping.
func TestClassifyOperationError(t *testing.T) {
	t.Parallel()
	for code, data := range map[string]bool{
		"22023": true, "23514": true, "23505": true, "25001": false, "40001": false, "57014": false, "08006": false,
	} {
		err := fmt.Errorf("wrapped: %w", classifyOperationError(&pgconn.PgError{Code: code}))
		var refused kubeaudit.DataError
		if errors.As(err, &refused) != data {
			t.Errorf("%s: data = %t", code, !data)
		}
	}
	if errors.As(classifyOperationError(errors.New("conn closed")), new(kubeaudit.DataError)) {
		t.Error("a connection error was data")
	}
}
