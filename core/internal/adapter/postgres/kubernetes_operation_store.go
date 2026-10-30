package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/kubeaudit"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schemas 245 (K1b0) and 261 (K2): gateways' Kubernetes operations, with the
// access profile that let each through, outcomes, and denials with samples.
const (
	recordKubernetesOperationsSQL        = `SELECT mesh_ops.record_kubernetes_operations_v2($1::JSONB)::TEXT`
	recordKubernetesOperationOutcomesSQL = `SELECT mesh_ops.record_kubernetes_operation_outcomes_v2($1::JSONB,
    $2::JSONB)::TEXT`
	kubernetesOperationsGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.record_kubernetes_operations_v2(jsonb)'), 'EXECUTE'), FALSE)`
	// maximumKubernetesOperationAnswer fits 1,000 answers of an outcome and
	// a UUID.
	maximumKubernetesOperationAnswer = 128 << 10
	// kubernetesOperationCommitTimeout bounds a COMMIT a session ending
	// never cancels: a lost synchronous standby must not hold the writer
	// forever. An unclear COMMIT is safe: the gateway sends the intent
	// again and dedupe answers the first audit_id (review b0b2 M3).
	kubernetesOperationCommitTimeout = 10 * time.Second
)

// ErrInvalidKubernetesOperationStore reports a store or input that cannot
// be used.
var ErrInvalidKubernetesOperationStore = errors.New("postgres: invalid Kubernetes operation store")

// KubernetesOperationStore records gateways' Kubernetes operations
// (kubeaudit.Store) as the runtime role.
type KubernetesOperationStore struct {
	database outboxDatabase
}

// NewKubernetesOperationStore binds the store to a runtime pool.
func NewKubernetesOperationStore(pool *Pool) (*KubernetesOperationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.outboxDatabase == nil {
		return nil, ErrInvalidKubernetesOperationStore
	}
	return &KubernetesOperationStore{database: pool.outboxDatabase}, nil
}

var _ kubeaudit.Store = (*KubernetesOperationStore)(nil)

// Granted reports whether this role may record operations: Core offers
// gateway.audit1 only then (design §3.1).
func (store *KubernetesOperationStore) Granted(ctx context.Context) (bool, error) {
	var granted bool
	if err := store.database.QueryRow(ctx, kubernetesOperationsGrantedSQL).Scan(&granted); err != nil {
		return false, fmt.Errorf("check Kubernetes operation writer: %w", err)
	}
	return granted, nil
}

// Record writes rows in one READ COMMITTED transaction with synchronous
// commit and answers each in order. Its COMMIT is never cancelled, only
// bounded: a cancelled wait for a synchronous replica leaves the
// transaction committed locally while the driver reports it failed (design
// §5). A row's data failing the whole transaction is a kubeaudit.DataError.
func (store *KubernetesOperationStore) Record(ctx context.Context, rows []kubeaudit.Row) (
	[]kubeaudit.StoredAnswer, error,
) {
	if store == nil || len(rows) == 0 || len(rows) > kubeaudit.MaximumRows {
		return nil, ErrInvalidKubernetesOperationStore
	}
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("begin Kubernetes operations: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback(context.WithoutCancel(ctx))
		}
	}()
	// The schema's dedupe needs READ COMMITTED whatever the database's
	// default (review b0b2 M2).
	if err := transaction.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
		return nil, fmt.Errorf("set Kubernetes operation isolation: %w", err)
	}
	if err := transaction.Exec(ctx, `SET LOCAL synchronous_commit = on`); err != nil {
		return nil, fmt.Errorf("set synchronous commit: %w", err)
	}
	// The audit_ids are issued here, after any wait for a connection: the
	// schema refuses one more than 5 s from its clock (review b0b2 M-b).
	issued, err := issueAuditIDs(rows)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(operationRows(issued))
	if err != nil {
		return nil, fmt.Errorf("encode Kubernetes operations: %w", err)
	}
	var answer string
	if err := transaction.QueryRow(ctx, recordKubernetesOperationsSQL, string(encoded)).Scan(&answer); err != nil {
		return nil, fmt.Errorf("record Kubernetes operations: %w", classifyOperationError(err))
	}
	commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), kubernetesOperationCommitTimeout)
	defer cancel()
	if err := transaction.Commit(commitCtx); err != nil {
		return nil, fmt.Errorf("commit Kubernetes operations: %w", classifyOperationError(err))
	}
	committed = true
	return decodeOperationAnswers(answer, len(rows))
}

// issueAuditIDs returns a copy of rows, each with a new audit_id.
func issueAuditIDs(rows []kubeaudit.Row) ([]kubeaudit.Row, error) {
	issued := slices.Clone(rows)
	for index := range issued {
		id, err := publicid.New()
		if err != nil {
			return nil, fmt.Errorf("issue Kubernetes operation audit_id: %w", err)
		}
		issued[index].AuditID = id
	}
	return issued, nil
}

// classifyOperationError marks a failure a row's data caused (SQLSTATE
// classes 22, 23).
func classifyOperationError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && len(postgresError.Code) == 5 &&
		(postgresError.Code[:2] == "22" || postgresError.Code[:2] == "23") {
		return kubeaudit.DataError{Err: err}
	}
	return err
}

type operationRow struct {
	Gateway         string   `json:"gateway"`
	IntentID        string   `json:"intent_id"`
	Digest          string   `json:"digest"`
	AuditID         string   `json:"audit_id"`
	Peer            string   `json:"peer"`
	OwnerKind       string   `json:"owner_kind"`
	OwnerRef        string   `json:"owner_ref"`
	NetworkRevision string   `json:"network_revision"`
	Class           string   `json:"class"`
	Groups          []string `json:"groups"`
	Verb            string   `json:"verb"`
	APIGroup        string   `json:"api_group"`
	Resource        string   `json:"resource"`
	Subresource     string   `json:"subresource"`
	Namespace       string   `json:"namespace"`
	Name            string   `json:"name"`
	Impersonated    string   `json:"impersonated"`
	TokenID         string   `json:"token_id"`
	ObservedMs      string   `json:"observed_ms"`
	ClockSkew       bool     `json:"clock_skew"`
	// Profile is the scope hash in hex, absent for a whole grant.
	Profile       string `json:"profile,omitempty"`
	ReportAllowed bool   `json:"report_allowed"`
}

func operationRows(rows []kubeaudit.Row) []operationRow {
	encoded := make([]operationRow, len(rows))
	for index, row := range rows {
		digest := row.Intent.Digest()
		groups := row.Intent.Groups
		if groups == nil {
			groups = []string{}
		}
		encoded[index] = operationRow{
			Gateway: gatewayKey(row.Gateway), IntentID: hex.EncodeToString(row.Intent.ID[:]),
			Digest: hex.EncodeToString(digest[:]), AuditID: row.AuditID.String(), Peer: row.Intent.Peer.String(),
			OwnerKind: row.Owner.Kind, OwnerRef: row.Owner.Ref, NetworkRevision: fmt.Sprint(row.NetworkRevision),
			Class: string(row.Intent.Class), Groups: groups, Verb: row.Intent.Verb, APIGroup: row.Intent.APIGroup,
			Resource: row.Intent.Resource, Subresource: row.Intent.Subresource, Namespace: row.Intent.Namespace,
			Name: row.Intent.Name, Impersonated: row.Intent.Impersonated,
			TokenID: hex.EncodeToString(row.Intent.TokenID), ObservedMs: fmt.Sprint(row.Intent.ObservedAt.UnixMilli()),
			ClockSkew: row.ClockSkew, Profile: hex.EncodeToString(row.Intent.Profile),
			ReportAllowed: row.Intent.ReportAllowed,
		}
	}
	return encoded
}

// denialSampleRow is a denial's sample as record_kubernetes_operation_outcomes_v2
// reads it; the scope hash in hex.
type denialSampleRow struct {
	Verb        string `json:"verb"`
	APIGroup    string `json:"api_group"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource"`
	Namespace   string `json:"namespace"`
	Scope       string `json:"scope"`
}

// gatewayKey is how the schema names a gateway: hex machine key
// fingerprint ':' hex node key.
func gatewayKey(gateway kubeaudit.Gateway) string {
	return hex.EncodeToString(gateway.MachineFingerprint[:]) + ":" + hex.EncodeToString(gateway.NodeKey[:])
}

// decodeOperationAnswers reads the writer's answer: exactly want answers,
// each a known outcome, with an audit_id exactly when recorded.
func decodeOperationAnswers(encoded string, want int) ([]kubeaudit.StoredAnswer, error) {
	invalid := errors.New("postgres: an unexpected Kubernetes operation answer")
	var record struct {
		Answers []struct {
			Outcome string  `json:"outcome"`
			AuditID *string `json:"audit_id"`
		} `json:"answers"`
	}
	if decodeStrictJSON(encoded, maximumKubernetesOperationAnswer, &record) != nil || len(record.Answers) != want {
		return nil, invalid
	}
	answers := make([]kubeaudit.StoredAnswer, want)
	for index, got := range record.Answers {
		outcome := kubeaudit.Outcome(got.Outcome)
		switch outcome {
		case kubeaudit.OutcomeAccepted, kubeaudit.OutcomeDuplicate, kubeaudit.OutcomeConflict,
			kubeaudit.OutcomeInvalid, kubeaudit.OutcomeGateway, kubeaudit.OutcomeDevice:
		default:
			return nil, invalid
		}
		if outcome.Recorded() != (got.AuditID != nil) {
			return nil, invalid
		}
		answers[index].Outcome = outcome
		if got.AuditID != nil {
			id, err := publicid.Parse(*got.AuditID)
			if err != nil {
				return nil, invalid
			}
			answers[index].AuditID = id
		}
	}
	return answers, nil
}

// RecordReports writes gateways' finished operations and denials, each
// under its gateway; rows out of form or of an unknown gateway are skipped.
// It answers how many of each were written.
func (store *KubernetesOperationStore) RecordReports(ctx context.Context, reports []kubeaudit.Reports) (
	int, int, error,
) {
	type finished struct {
		Gateway  string `json:"gateway"`
		AuditID  string `json:"audit_id"`
		Status   string `json:"status"`
		Duration string `json:"duration_ms"`
	}
	type denials struct {
		Gateway string           `json:"gateway"`
		Peer    string           `json:"peer,omitempty"`
		Reason  string           `json:"reason"`
		Count   string           `json:"count"`
		First   string           `json:"first_ms"`
		Last    string           `json:"last_ms"`
		Sample  *denialSampleRow `json:"sample,omitempty"`
	}
	outcomes, refusals := []finished{}, []denials{}
	for _, report := range reports {
		key := gatewayKey(report.Gateway)
		for _, done := range report.Finished {
			outcomes = append(outcomes, finished{Gateway: key, AuditID: done.AuditID.String(),
				Status: fmt.Sprint(done.Status), Duration: fmt.Sprint(done.Duration.Milliseconds())})
		}
		for _, denied := range report.Denials {
			entry := denials{Gateway: key, Reason: string(denied.Reason), Count: fmt.Sprint(denied.Count),
				First: fmt.Sprint(denied.First.UnixMilli()), Last: fmt.Sprint(denied.Last.UnixMilli())}
			if denied.Peer.IsValid() {
				entry.Peer = denied.Peer.String()
			}
			if sample := denied.Sample; sample != nil {
				entry.Sample = &denialSampleRow{Verb: sample.Verb, APIGroup: sample.APIGroup, Resource: sample.Resource,
					Subresource: sample.Subresource, Namespace: sample.Namespace,
					Scope: hex.EncodeToString(sample.Scope[:])}
			}
			refusals = append(refusals, entry)
		}
	}
	if len(outcomes) > 10000 || len(refusals) > 2560 {
		return 0, 0, ErrInvalidKubernetesOperationStore
	}
	encodedOutcomes, err := json.Marshal(outcomes)
	if err != nil {
		return 0, 0, err
	}
	encodedDenials, err := json.Marshal(refusals)
	if err != nil {
		return 0, 0, err
	}
	var answer string
	if err := store.database.QueryRow(ctx, recordKubernetesOperationOutcomesSQL, string(encodedOutcomes),
		string(encodedDenials)).Scan(&answer); err != nil {
		return 0, 0, fmt.Errorf("record Kubernetes operation outcomes: %w", err)
	}
	var written struct {
		Outcomes *int `json:"outcomes"`
		Denials  *int `json:"denials"`
	}
	if decodeStrictJSON(answer, 4096, &written) != nil || written.Outcomes == nil || written.Denials == nil {
		return 0, 0, errors.New("postgres: an unexpected Kubernetes outcome answer")
	}
	return *written.Outcomes, *written.Denials, nil
}
