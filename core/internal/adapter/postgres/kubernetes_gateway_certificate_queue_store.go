package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/kubeca/certqueue"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	enqueueKubernetesGatewayCertificateSQL = `SELECT mesh_ops.enqueue_kubernetes_gateway_certificate_v1(
    $1::BYTEA,$2::BYTEA,$3::UUID,$4::BYTEA,$5::BYTEA,$6::BYTEA,$7::TEXT,$8::BYTEA,$9::BYTEA,$10::BYTEA)::TEXT`
	readKubernetesGatewayCertificateSQL = `SELECT mesh_ops.read_kubernetes_gateway_certificate_v1(
    $1::UUID,$2::UUID)::TEXT`
	abandonKubernetesGatewayCertificateSQL = `SELECT mesh_ops.abandon_kubernetes_gateway_certificate_v1(
    $1::UUID,$2::UUID)::TEXT`
	readKubernetesCASigningStateSQL = `SELECT mesh_ops.read_kubernetes_ca_signing_state_v1()::TEXT`

	// A result holds a leaf and an intermediate of at most 4 KiB each,
	// hex encoded, and a few fields.
	gatewayCertificateMaximumResult = 64 << 10
)

// ErrKubernetesGatewayCertificateQueueStore classifies a failed or
// unreadable queue operation.
var ErrKubernetesGatewayCertificateQueueStore = errors.New("postgres Kubernetes gateway certificate queue")

// KubernetesGatewayCertificateQueueStore is control's view of the
// certificate queue (schemas 240, 241): it queues a gateway's request for
// the keys its session proved, reads and abandons it, and reads whether a
// worker can sign. It never signs; the tokens it passes are never logged.
type KubernetesGatewayCertificateQueueStore struct {
	database registrationTransactionDatabase
	options  RegistrationTransactionOptions
}

var _ certqueue.Store = (*KubernetesGatewayCertificateQueueStore)(nil)

// NewKubernetesGatewayCertificateQueueStore uses the runtime pool's
// registration transactions, as gateway key rotations do.
func NewKubernetesGatewayCertificateQueueStore(pool *Pool,
	options RegistrationTransactionOptions,
) (*KubernetesGatewayCertificateQueueStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.registrationTransactionDatabase == nil ||
		!validRegistrationTransactionOptions(options) {
		return nil, certqueue.ErrInvalid
	}
	return &KubernetesGatewayCertificateQueueStore{database: pool.registrationTransactionDatabase, options: options}, nil
}

// Enqueue queues request for the keys the session proved: the transaction
// is marked with the proof, as the database serves a gateway only then.
func (store *KubernetesGatewayCertificateQueueStore) Enqueue(ctx context.Context,
	request certqueue.Request,
) (certqueue.Stored, error) {
	if ctx == nil || store == nil || store.database == nil || !request.ID.IsValid() || len(request.CSR) == 0 ||
		request.Renewal() == (len(request.RenewalProof) == 0) {
		return certqueue.Stored{}, certqueue.ErrInvalid
	}
	var token, handshake, serial, proof any
	if request.Renewal() {
		handshake, serial, proof = request.HandshakeHash[:], request.RenewalSerial[:], request.RenewalProof
	} else {
		token = request.Token
	}
	var encoded *string
	err := store.run(ctx, true, func(tx registrationDatabaseTransaction) error {
		if _, err := tx.Exec(ctx, markSessionProvenSQL, request.MachineFingerprint[:], request.NodeKey[:]); err != nil {
			return err
		}
		return tx.QueryRow(ctx, enqueueKubernetesGatewayCertificateSQL, request.MachineFingerprint[:],
			request.NodeKey[:], request.ID.String(), request.RequestID[:], request.CSR, request.PublicKeySHA256[:],
			token, handshake, serial, proof).Scan(&encoded)
	})
	if err != nil {
		return certqueue.Stored{}, queueDatabaseError(err)
	}
	// NULL: the request was removed between the read and the revival
	// (review a3b SQL L1); the gateway sends it again.
	stored, found, err := decodeQueuedCertificate(encoded)
	if err != nil || !found {
		return certqueue.Stored{}, ErrKubernetesGatewayCertificateQueueStore
	}
	return stored, nil
}

// Read reads a request back; false once it was removed.
func (store *KubernetesGatewayCertificateQueueStore) Read(ctx context.Context, device,
	request publicid.ID,
) (certqueue.Stored, bool, error) {
	return store.one(ctx, false, readKubernetesGatewayCertificateSQL, device, request)
}

// Abandon gives up waiting for a request no worker claimed yet.
func (store *KubernetesGatewayCertificateQueueStore) Abandon(ctx context.Context, device,
	request publicid.ID,
) (certqueue.Stored, bool, error) {
	return store.one(ctx, true, abandonKubernetesGatewayCertificateSQL, device, request)
}

func (store *KubernetesGatewayCertificateQueueStore) one(ctx context.Context, commit bool, statement string,
	device, request publicid.ID,
) (certqueue.Stored, bool, error) {
	if ctx == nil || store == nil || store.database == nil || !device.IsValid() || !request.IsValid() {
		return certqueue.Stored{}, false, certqueue.ErrInvalid
	}
	var encoded *string
	if err := store.run(ctx, commit, func(tx registrationDatabaseTransaction) error {
		return tx.QueryRow(ctx, statement, device.String(), request.String()).Scan(&encoded)
	}); err != nil {
		return certqueue.Stored{}, false, queueDatabaseError(err)
	}
	return decodeQueuedCertificate(encoded)
}

// SigningState reads whether a worker can sign now.
func (store *KubernetesGatewayCertificateQueueStore) SigningState(ctx context.Context) (certqueue.SigningState,
	error,
) {
	if ctx == nil || store == nil || store.database == nil {
		return certqueue.SigningState{}, certqueue.ErrInvalid
	}
	var encoded string
	if err := store.run(ctx, false, func(tx registrationDatabaseTransaction) error {
		return tx.QueryRow(ctx, readKubernetesCASigningStateSQL).Scan(&encoded)
	}); err != nil {
		return certqueue.SigningState{}, queueDatabaseError(err)
	}
	var record struct {
		SignerReady      *bool `json:"signer_ready"`
		RestoreSuspected *bool `json:"restore_suspected"`
		Checked          *bool `json:"checked"`
	}
	if err := decodeStrictJSON(encoded, 256, &record); err != nil || record.SignerReady == nil ||
		record.RestoreSuspected == nil || record.Checked == nil {
		return certqueue.SigningState{}, ErrKubernetesGatewayCertificateQueueStore
	}
	return certqueue.SigningState{
		SignerReady: *record.SignerReady, RestoreSuspected: *record.RestoreSuspected,
		Checked: *record.Checked,
	}, nil
}

// run runs work in a registration transaction with the store's timeouts,
// committed when commit, else rolled back.
func (store *KubernetesGatewayCertificateQueueStore) run(ctx context.Context, commit bool,
	work func(registrationDatabaseTransaction) error,
) (resultErr error) {
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackRegistrationSetup(tx))
		}
	}()
	if _, err := tx.Exec(ctx, configureRegistrationTransactionSQL, postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return err
	}
	if err := work(tx); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	closed = true
	return tx.Commit(ctx)
}

func queueDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "P0002" {
		// The session's keys are no longer a proven gateway's.
		return certqueue.ErrNotProven
	}
	return errors.Join(ErrKubernetesGatewayCertificateQueueStore, err)
}

// queuedCertificateRecord is what enqueue, read and abandon return: a
// request as kubernetes_gateway_certificate_result_internal_v1 encodes it,
// or an answer to queueing that queued nothing.
type queuedCertificateRecord struct {
	Outcome           string     `json:"outcome"`
	RequestID         *string    `json:"request_id"`
	DeviceID          *string    `json:"device_id"`
	Reason            *string    `json:"reason"`
	RetryAfterMS      *int64     `json:"retry_after_ms"`
	Certificate       *string    `json:"certificate"`
	Chain             []string   `json:"chain"`
	IssuerFingerprint *string    `json:"issuer_fingerprint"`
	RootFingerprint   *string    `json:"root_fingerprint"`
	NotAfter          *time.Time `json:"not_after"`
	RenewAt           *time.Time `json:"renew_at"`
	NetworkRevision   *int64     `json:"network_revision"`
}

func decodeQueuedCertificate(encoded *string) (certqueue.Stored, bool, error) {
	if encoded == nil {
		return certqueue.Stored{}, false, nil
	}
	var record queuedCertificateRecord
	if err := decodeStrictJSON(*encoded, gatewayCertificateMaximumResult, &record); err != nil {
		return certqueue.Stored{}, false, ErrKubernetesGatewayCertificateQueueStore
	}
	stored := certqueue.Stored{State: certqueue.State(record.Outcome)}
	if record.Reason != nil {
		stored.Reason = *record.Reason
	}
	if record.RetryAfterMS != nil {
		if *record.RetryAfterMS < 0 || *record.RetryAfterMS > int64(time.Hour/time.Millisecond) {
			return certqueue.Stored{}, false, ErrKubernetesGatewayCertificateQueueStore
		}
		stored.RetryAfter = time.Duration(*record.RetryAfterMS) * time.Millisecond
	}
	switch stored.State {
	case certqueue.StateLimited, certqueue.StateConflict:
		return stored, true, nil
	case certqueue.StateRefused:
		if stored.Reason == "" {
			return certqueue.Stored{}, false, ErrKubernetesGatewayCertificateQueueStore
		}
		if record.RequestID == nil {
			return stored, true, nil // refused before anything was queued
		}
	case certqueue.StatePending, certqueue.StateClaimed, certqueue.StateIssued, certqueue.StateAbandoned:
	default:
		return certqueue.Stored{}, false, ErrKubernetesGatewayCertificateQueueStore
	}
	if record.RequestID == nil || record.DeviceID == nil {
		return certqueue.Stored{}, false, ErrKubernetesGatewayCertificateQueueStore
	}
	request, requestErr := publicid.Parse(*record.RequestID)
	device, deviceErr := publicid.Parse(*record.DeviceID)
	if requestErr != nil || deviceErr != nil {
		return certqueue.Stored{}, false, ErrKubernetesGatewayCertificateQueueStore
	}
	stored.Request, stored.Device = request, device
	if stored.State != certqueue.StateIssued {
		return stored, true, nil
	}
	if err := decodeIssuedCertificate(record, &stored); err != nil {
		return certqueue.Stored{}, false, err
	}
	return stored, true, nil
}

func decodeIssuedCertificate(record queuedCertificateRecord, stored *certqueue.Stored) error {
	// Issued before schema 241, a request names no revision: 0 (review a3b
	// SQL L5).
	if record.Certificate == nil || record.IssuerFingerprint == nil || record.RootFingerprint == nil ||
		record.NotAfter == nil || record.RenewAt == nil ||
		record.NetworkRevision != nil && *record.NetworkRevision < 1 || len(record.Chain) == 0 {
		return ErrKubernetesGatewayCertificateQueueStore
	}
	certificate, certificateErr := hex.DecodeString(*record.Certificate)
	issuer, issuerErr := hex.DecodeString(*record.IssuerFingerprint)
	root, rootErr := hex.DecodeString(*record.RootFingerprint)
	if errors.Join(certificateErr, issuerErr, rootErr) != nil || len(certificate) == 0 || len(issuer) != 32 ||
		len(root) != 32 {
		return ErrKubernetesGatewayCertificateQueueStore
	}
	chain := make([][]byte, 0, len(record.Chain))
	for _, encoded := range record.Chain {
		intermediate, err := hex.DecodeString(encoded)
		if err != nil || len(intermediate) == 0 {
			return ErrKubernetesGatewayCertificateQueueStore
		}
		chain = append(chain, intermediate)
	}
	stored.Certificate, stored.Chain, stored.IssuerFingerprint, stored.RootFingerprint = certificate, chain, issuer, root
	stored.NotAfter, stored.RenewAt = record.NotAfter.UTC(), record.RenewAt.UTC()
	if record.NetworkRevision != nil {
		if revision := *record.NetworkRevision; revision > 0 {
			stored.NetworkRevision = uint64(revision)
		}
	}
	return nil
}
