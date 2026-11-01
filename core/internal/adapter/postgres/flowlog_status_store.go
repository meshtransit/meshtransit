package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"meshtransit.net/core/internal/domain/connectionlog"
)

// Schema 270: the receiver's reports and the ticket gate (connection logs
// design §16e, C67–C71).
const (
	reportFlowlogStatusSQL = `SELECT mesh_ops.flowlog_report_status_v1($1::BYTEA, $2::INTEGER[], $3::BYTEA[],
    $4::TEXT[], $5::TIMESTAMPTZ, $6::JSONB)::TEXT`
	readFlowlogGateSQL = `SELECT gate.fresh, gate.accepting, gate.newest, gate.checked_at
FROM mesh_ops.flowlog_receiver_gate_v1($1::INTEGER, $2::BYTEA) AS gate`
	// flowlogStatusTimeout bounds a report's statement (C68): it never holds
	// a receiver connection long.
	flowlogStatusTimeout = "2s"
)

var (
	// ErrFlowlogReportStaleClock reports a report whose time is ahead of the
	// database's by more than the allowed skew: nothing was written.
	ErrFlowlogReportStaleClock = errors.New("postgres: connection log report from the future")
	// ErrFlowlogTooManyReceivers reports a new receiver instance past the
	// instances one deployment keeps.
	ErrFlowlogTooManyReceivers = errors.New("postgres: too many connection log receiver instances")
)

type flowlogStatusEntry struct {
	Workspace     string     `json:"workspace"`
	Network       string     `json:"network"`
	TestedETag    *string    `json:"tested_etag"`
	TestResult    string     `json:"test_result"`
	TestedAt      *time.Time `json:"tested_at"`
	DeliveredAt   *time.Time `json:"delivered_at"`
	DeliveryError string     `json:"delivery_error"`
	Lost          int64      `json:"lost"`
	Overflow      int64      `json:"overflow"`
}

// ReportStatus writes one receiver report the API validated, its Networks
// sorted by Network ID.
func (store *FlowlogReceiverStore) ReportStatus(ctx context.Context, report connectionlog.ReceiverReport,
) (_ connectionlog.ReceiverReportResult, resultErr error) {
	if store == nil || store.database == nil || ctx == nil || report.ReportedAt.IsZero() ||
		len(report.Networks) > connectionlog.MaxReceiverReportNetworks {
		return connectionlog.ReceiverReportResult{}, ErrFlowlogReceiver
	}
	entries, err := flowlogStatusEntries(report.Networks)
	if err != nil {
		return connectionlog.ReceiverReportResult{}, err
	}
	versions := make([]int32, 0, len(report.AcceptedVersions))
	for _, version := range report.AcceptedVersions {
		if version < 1 || version > math.MaxInt32 {
			return connectionlog.ReceiverReportResult{}, ErrFlowlogReceiver
		}
		versions = append(versions, int32(version))
	}
	fingerprints := make([][]byte, 0, len(report.NoiseFingerprints))
	for _, fingerprint := range report.NoiseFingerprints {
		fingerprints = append(fingerprints, append([]byte(nil), fingerprint[:]...))
	}
	sealing := append(make([]string, 0, len(report.SealingKeyIDs)), report.SealingKeyIDs...)
	startedAt := time.Now()
	defer func() {
		if store.metrics != nil {
			store.metrics.observeOperation(postgresOperationFlowlogReceiver, time.Since(startedAt), resultErr)
		}
	}()
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return connectionlog.ReceiverReportResult{}, errors.Join(ErrFlowlogReceiver, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if err := transaction.Exec(ctx, configureFlowlogReadSQL, flowlogStatusTimeout); err != nil {
		return connectionlog.ReceiverReportResult{}, errors.Join(ErrFlowlogReceiver, err)
	}
	var document string
	if err := transaction.QueryRow(ctx, reportFlowlogStatusSQL, report.Instance[:], versions, fingerprints, sealing,
		report.ReportedAt, string(entries)).Scan(&document); err != nil {
		return connectionlog.ReceiverReportResult{}, errors.Join(ErrFlowlogReceiver, err)
	}
	var answer struct {
		Result    string `json:"result"`
		Written   int    `json:"written"`
		Throttled int    `json:"throttled"`
		Dropped   int    `json:"dropped"`
	}
	if decodeStrictJSON(document, maxFlowlogDocument, &answer) != nil {
		return connectionlog.ReceiverReportResult{}, ErrFlowlogReceiver
	}
	switch answer.Result {
	case connectionlog.ReceiverReportStaleClock:
		return connectionlog.ReceiverReportResult{}, ErrFlowlogReportStaleClock
	case connectionlog.ReceiverReportTooManyInstances:
		return connectionlog.ReceiverReportResult{}, ErrFlowlogTooManyReceivers
	case connectionlog.ReceiverReportOK:
	default:
		return connectionlog.ReceiverReportResult{}, ErrFlowlogReceiver
	}
	if answer.Written < 0 || answer.Throttled < 0 || answer.Dropped < 0 ||
		answer.Written+answer.Throttled+answer.Dropped != len(report.Networks) {
		return connectionlog.ReceiverReportResult{}, ErrFlowlogReceiver
	}
	if err := transaction.Commit(ctx); err != nil {
		return connectionlog.ReceiverReportResult{}, errors.Join(ErrFlowlogReceiver, err)
	}
	return connectionlog.ReceiverReportResult{
		Outcome: answer.Result, Written: answer.Written, Throttled: answer.Throttled, Dropped: answer.Dropped,
	}, nil
}

func flowlogStatusEntries(networks []connectionlog.ReceiverNetworkStatus) ([]byte, error) {
	entries := make([]flowlogStatusEntry, 0, len(networks))
	for _, status := range networks {
		entry := flowlogStatusEntry{
			Workspace: status.Workspace.String(), Network: status.Network.String(), TestResult: status.TestResult,
			DeliveryError: status.DeliveryError, Lost: clampCount(status.Lost), Overflow: clampCount(status.Overflow),
		}
		switch len(status.TestedETag) {
		case 0:
		case connectionlog.ReceiverStatusTestedETagBytes:
			tag := hex.EncodeToString(status.TestedETag)
			entry.TestedETag = &tag
		default:
			return nil, ErrFlowlogReceiver
		}
		if !status.TestedAt.IsZero() {
			at := status.TestedAt.UTC()
			entry.TestedAt = &at
		}
		if !status.LastDeliveredAt.IsZero() {
			at := status.LastDeliveredAt.UTC()
			entry.DeliveredAt = &at
		}
		entries = append(entries, entry)
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return nil, errors.Join(ErrFlowlogReceiver, err)
	}
	return encoded, nil
}

func clampCount(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

// FlowlogGateStore reads the ticket gate for Control (C71), on the runtime
// pool: one small read per replica every 30 seconds.
type FlowlogGateStore struct {
	database resourceAuthorityDatabase
}

// NewFlowlogGateStore accepts only a runtime-authenticated pool.
func NewFlowlogGateStore(pool *Pool) (*FlowlogGateStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil {
		return nil, ErrFlowlogReceiver
	}
	return &FlowlogGateStore{database: pool.resourceAuthorityDatabase}, nil
}

// ReadReceiverGate reads the receivers that accept version and hold the
// Noise key whose SHA-256 is fingerprint.
func (store *FlowlogGateStore) ReadReceiverGate(ctx context.Context, version int, fingerprint [32]byte,
) (connectionlog.ReceiverGate, error) {
	if store == nil || store.database == nil || ctx == nil || version < 1 || version > math.MaxInt32 {
		return connectionlog.ReceiverGate{}, ErrFlowlogReceiver
	}
	transaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return connectionlog.ReceiverGate{}, errors.Join(ErrFlowlogReceiver, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if err := transaction.Exec(ctx, configureFlowlogReadSQL, flowlogStatusTimeout); err != nil {
		return connectionlog.ReceiverGate{}, errors.Join(ErrFlowlogReceiver, err)
	}
	var gate connectionlog.ReceiverGate
	var newest *time.Time
	if err := transaction.QueryRow(ctx, readFlowlogGateSQL, int32(version), fingerprint[:]).Scan(&gate.Fresh,
		&gate.Accepting, &newest, &gate.CheckedAt); err != nil {
		return connectionlog.ReceiverGate{}, errors.Join(ErrFlowlogReceiver, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return connectionlog.ReceiverGate{}, errors.Join(ErrFlowlogReceiver, err)
	}
	if gate.Fresh < 0 || gate.Accepting < 0 || gate.Accepting > gate.Fresh {
		return connectionlog.ReceiverGate{}, ErrFlowlogReceiver
	}
	if newest != nil {
		gate.Newest = newest.UTC()
	}
	gate.CheckedAt = gate.CheckedAt.UTC()
	return gate, nil
}
