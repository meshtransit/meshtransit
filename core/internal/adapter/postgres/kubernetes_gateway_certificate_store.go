package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/signing"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	claimKubernetesGatewayCertificatesSQL = `SELECT mesh_ops.claim_kubernetes_gateway_certificates_v1(
    $1::UUID,$2::INTEGER,$3::INTEGER)::TEXT`
	issueKubernetesGatewayCertificateSQL = `SELECT mesh_ops.issue_kubernetes_gateway_certificate_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::UUID,$7::BIGINT,$8::BYTEA,$9::BYTEA,$10::BYTEA,$11::TIMESTAMPTZ,
    $12::TIMESTAMPTZ,$13::TIMESTAMPTZ,$14::TEXT,$15::TIMESTAMPTZ,$16::TEXT,$17::BIGINT)::TEXT`
	appendKubernetesGatewayCertificateEvidenceSQL = `SELECT mesh_ops.append_kubernetes_gateway_certificate_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB,$9::BIGINT)`
	refuseKubernetesGatewayCertificateSQL = `SELECT mesh_ops.refuse_kubernetes_gateway_certificate_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::TEXT)::TEXT`
	releaseKubernetesGatewayCertificateSQL = `SELECT mesh_ops.release_kubernetes_gateway_certificate_v1(
    $1::UUID,$2::UUID,$3::UUID)::TEXT`
	pruneKubernetesGatewayCertificatesSQL = `SELECT mesh_ops.prune_kubernetes_gateway_certificates_v1(
    $1::UUID,$2::INTEGER)::TEXT`
	readKubernetesGatewayCertificateFleetSQL = `SELECT mesh_ops.read_kubernetes_gateway_certificate_fleet_v1(
    $1::UUID,$2::BIGINT,$3::INTEGER,$4::INTEGER)::TEXT`
	recordKubernetesGatewayCertificateClaimsSQL = `SELECT mesh_ops.record_kubernetes_gateway_certificate_token_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::TEXT,$5::TIMESTAMPTZ,$6::TEXT,$7::BIGINT)::TEXT`

	gatewayCertificateAggregateKind = "kubernetes_gateway_certificate"
	// A claim holds at most 64 requests of a few KiB each, hex encoded.
	gatewayCertificateMaximumClaim = 8 << 20
	gatewayCertificateMaximumBatch = 64
	// A fleet page holds at most 1,000 rows of five short values.
	gatewayCertificateMaximumFleet     = 1000
	gatewayCertificateMaximumFleetText = 128 << 10
)

// KubernetesGatewayCertificateStore is the signing worker's view of the
// certificate queue and ledger (schema 240): claims with a lease, issues
// with their sealed audit events, refusals, releases and pruning. It never
// sees a key in the clear; the tokens it reads are never logged.
type KubernetesGatewayCertificateStore struct {
	database outboxDatabase
	cas      *KubernetesClusterCAStore
}

// NewKubernetesGatewayCertificateStore accepts the worker pool only.
func NewKubernetesGatewayCertificateStore(pool *Pool) (*KubernetesGatewayCertificateStore, error) {
	cas, err := NewKubernetesClusterCAStore(pool)
	if err != nil {
		return nil, err
	}
	return &KubernetesGatewayCertificateStore{database: pool.outboxDatabase, cas: cas}, nil
}

func (store *KubernetesGatewayCertificateStore) valid(ctx context.Context, installation deployment.ID) bool {
	return store != nil && store.cas.valid(ctx, installation)
}

// Claim claims up to limit pending requests for lease.
func (store *KubernetesGatewayCertificateStore) Claim(ctx context.Context, installation deployment.ID, limit int,
	lease time.Duration,
) (signing.Batch, error) {
	if !store.valid(ctx, installation) || limit < 1 || limit > gatewayCertificateMaximumBatch ||
		lease < 5*time.Second || lease > 2*time.Minute {
		return signing.Batch{}, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.cas.queryText(ctx, claimKubernetesGatewayCertificatesSQL, installation.String(), limit,
		int(lease/time.Second))
	if err != nil {
		return signing.Batch{}, err
	}
	var record struct {
		Outcome         string                          `json:"outcome"`
		Now             time.Time                       `json:"now"`
		Pending         int64                           `json:"pending"`
		RefusedAttempts int64                           `json:"refused_attempts"`
		Suffix          *string                         `json:"suffix"`
		Requests        []gatewayCertificateClaimRecord `json:"requests"`
	}
	if err := decodeStrictJSON(encoded, gatewayCertificateMaximumClaim, &record); err != nil || record.Now.IsZero() ||
		record.Pending < 0 || record.Requests == nil || len(record.Requests) > limit {
		return signing.Batch{}, ErrKubernetesClusterCAStore
	}
	if record.RefusedAttempts < 0 {
		return signing.Batch{}, ErrKubernetesClusterCAStore
	}
	batch := signing.Batch{Now: record.Now, Pending: record.Pending, RefusedAttempts: record.RefusedAttempts}
	switch record.Outcome {
	case "suspected", "unchecked":
		if len(record.Requests) != 0 {
			return signing.Batch{}, ErrKubernetesClusterCAStore
		}
		batch.Suspected, batch.Unchecked = record.Outcome == "suspected", record.Outcome == "unchecked"
		return batch, nil
	case "claimed":
	default:
		return signing.Batch{}, ErrKubernetesClusterCAStore
	}
	if record.Suffix != nil {
		batch.Suffix = *record.Suffix
	}
	batch.Claims = make([]signing.Claim, 0, len(record.Requests))
	for _, item := range record.Requests {
		claim, err := item.decode()
		if err == nil {
			batch.Claims = append(batch.Claims, claim)
			continue
		}
		// One request this build cannot read is given back alone; the
		// others are signed (review a3a L4).
		id, idErr := publicid.Parse(item.ID)
		token, tokenErr := signing.ParseClaimToken(item.ClaimToken)
		if idErr != nil || tokenErr != nil {
			return signing.Batch{}, err
		}
		if _, err := store.Refuse(ctx, installation, id, token, "invalid"); err != nil {
			return signing.Batch{}, err
		}
	}
	return batch, nil
}

// gatewayCertificateClaimRecord is one claimed request as
// kubernetes_gateway_certificate_claim_internal_v1 encodes it.
type gatewayCertificateClaimRecord struct {
	ID              string  `json:"id"`
	ClaimToken      string  `json:"claim_token"`
	RequestID       string  `json:"request_id"`
	WorkspaceID     string  `json:"workspace_id"`
	NetworkID       string  `json:"network_id"`
	DeviceID        string  `json:"device_id"`
	ClusterID       string  `json:"cluster_id"`
	ClusterName     string  `json:"cluster_name"`
	WorkspaceCode   *string `json:"workspace_code"`
	NetworkCode     *string `json:"network_code"`
	CSR             string  `json:"csr"`
	PublicKeySHA256 string  `json:"public_key_sha256"`
	Proof           string  `json:"proof"`
	Token           *string `json:"token"`
	Verified        *struct {
		JTI          string    `json:"jti"`
		ExpiresAt    time.Time `json:"expires_at"`
		PodName      string    `json:"pod_name"`
		TrustVersion int64     `json:"trust_version"`
	} `json:"verified"`
	HandshakeHash    *string    `json:"handshake_hash"`
	RenewalProof     *string    `json:"renewal_proof"`
	RenewalPublicKey *string    `json:"renewal_public_key"`
	RenewalSerial    *string    `json:"renewal_serial"`
	RenewalNotAfter  *time.Time `json:"renewal_not_after"`
	Trust            *struct {
		Version        int64   `json:"version"`
		Issuer         string  `json:"issuer"`
		JWKS           string  `json:"jwks"`
		Namespace      string  `json:"namespace"`
		ServiceAccount string  `json:"service_account"`
		PodName        *string `json:"pod_name"`
	} `json:"trust"`
	Intermediate *struct {
		ID              string                 `json:"id"`
		Version         int64                  `json:"version"`
		Certificate     string                 `json:"certificate"`
		SealedKey       *string                `json:"sealed_key"`
		ClusterDNSName  string                 `json:"cluster_dns_name"`
		NotAfter        time.Time              `json:"not_after"`
		RootID          string                 `json:"root_id"`
		RootCertificate string                 `json:"root_certificate"`
		DataKey         clusterCADataKeyRecord `json:"data_key"`
	} `json:"intermediate"`
}

func (record gatewayCertificateClaimRecord) decode() (signing.Claim, error) {
	id, idErr := publicid.Parse(record.ID)
	token, tokenErr := signing.ParseClaimToken(record.ClaimToken)
	requestID, requestErr := hex.DecodeString(record.RequestID)
	scope, scopeErr := parseClusterCAScope(record.WorkspaceID, record.NetworkID)
	device, deviceErr := publicid.Parse(record.DeviceID)
	cluster, clusterErr := publicid.Parse(record.ClusterID)
	csr, csrErr := hex.DecodeString(record.CSR)
	digest, digestErr := hex.DecodeString(record.PublicKeySHA256)
	if errors.Join(idErr, tokenErr, requestErr, scopeErr, deviceErr, clusterErr, csrErr, digestErr) != nil ||
		len(requestID) != 16 || len(csr) == 0 || len(digest) != sha256.Size || record.ClusterName == "" {
		return signing.Claim{}, ErrKubernetesClusterCAStore
	}
	claim := signing.Claim{
		ID: id, ClaimToken: token, RequestID: [16]byte(requestID), Scope: scope, DeviceID: device,
		ClusterID: cluster, ClusterName: record.ClusterName, CSR: csr, PublicKeySHA256: [sha256.Size]byte(digest),
	}
	if record.WorkspaceCode != nil && record.NetworkCode != nil {
		claim.WorkspaceCode, claim.NetworkCode = *record.WorkspaceCode, *record.NetworkCode
	}
	switch {
	case record.Proof == "token" && (record.Token == nil) != (record.Verified == nil) && record.HandshakeHash == nil &&
		record.RenewalProof == nil:
		claim.Proof = signing.ProofToken
		if record.Token != nil {
			claim.Token = *record.Token
		} else {
			// A worker checked the token at an earlier claim (§14 R-M1).
			verified := signing.VerifiedToken{
				Use: signing.TokenUse{
					JTI:       record.Verified.JTI,
					ExpiresAt: record.Verified.ExpiresAt, PodName: record.Verified.PodName,
				},
				TrustVersion: record.Verified.TrustVersion,
			}
			if !verified.Valid() {
				return signing.Claim{}, ErrKubernetesClusterCAStore
			}
			claim.Verified = &verified
		}
		trust, err := record.decodeTrust()
		if err != nil {
			return signing.Claim{}, err
		}
		claim.Trust = trust
	case record.Proof == "renewal" && record.Token == nil && record.HandshakeHash != nil && record.RenewalProof != nil:
		hash, hashErr := hex.DecodeString(*record.HandshakeHash)
		proof, proofErr := hex.DecodeString(*record.RenewalProof)
		if hashErr != nil || proofErr != nil || len(hash) != 32 || len(proof) == 0 {
			return signing.Claim{}, ErrKubernetesClusterCAStore
		}
		claim.Proof, claim.HandshakeHash, claim.RenewalProof = signing.ProofRenewal, [32]byte(hash), proof
		// The renewed certificate may be gone (pruned): the worker refuses.
		if record.RenewalPublicKey != nil && record.RenewalNotAfter != nil && record.RenewalSerial != nil {
			key, keyErr := hex.DecodeString(*record.RenewalPublicKey)
			serial, serialErr := hex.DecodeString(*record.RenewalSerial)
			if keyErr != nil || serialErr != nil || len(key) == 0 || len(serial) != len(claim.RenewalSerial) {
				return signing.Claim{}, ErrKubernetesClusterCAStore
			}
			claim.RenewalPublicKey, claim.RenewalNotAfter = key, *record.RenewalNotAfter
			claim.RenewalSerial = [16]byte(serial)
		}
	default:
		return signing.Claim{}, ErrKubernetesClusterCAStore
	}
	intermediate, err := record.decodeIntermediate()
	if err != nil {
		return signing.Claim{}, err
	}
	claim.Intermediate = intermediate
	return claim, nil
}

func (record gatewayCertificateClaimRecord) decodeTrust() (*signing.Trust, error) {
	if record.Trust == nil {
		return nil, nil
	}
	// encode(..., 'base64') breaks lines every 76 characters.
	jwks, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(record.Trust.JWKS, "\n", ""))
	if err != nil {
		return nil, ErrKubernetesClusterCAStore
	}
	trust := &signing.Trust{
		Version: record.Trust.Version, Issuer: record.Trust.Issuer, JWKS: jwks, Namespace: record.Trust.Namespace,
		ServiceAccount: record.Trust.ServiceAccount,
	}
	if record.Trust.PodName != nil {
		trust.PodName = *record.Trust.PodName
	}
	return trust, nil
}

func (record gatewayCertificateClaimRecord) decodeIntermediate() (*signing.Intermediate, error) {
	stored := record.Intermediate
	if stored == nil {
		return nil, nil
	}
	id, idErr := publicid.Parse(stored.ID)
	root, rootErr := publicid.Parse(stored.RootID)
	certificate, certificateErr := hex.DecodeString(stored.Certificate)
	rootCertificate, rootCertificateErr := hex.DecodeString(stored.RootCertificate)
	dataKey, dataKeyErr := decodeClusterCADataKey(stored.DataKey)
	if errors.Join(idErr, rootErr, certificateErr, rootCertificateErr, dataKeyErr) != nil || stored.Version < 1 ||
		stored.SealedKey == nil || len(certificate) == 0 || len(rootCertificate) == 0 ||
		!kubeca.ValidDNSName(stored.ClusterDNSName) || stored.NotAfter.IsZero() {
		return nil, ErrKubernetesClusterCAStore
	}
	sealed, err := hex.DecodeString(*stored.SealedKey)
	if err != nil || len(sealed) == 0 {
		return nil, ErrKubernetesClusterCAStore
	}
	return &signing.Intermediate{
		ID: id, Version: stored.Version, Certificate: certificate, SealedKey: sealed,
		ClusterDNSName: stored.ClusterDNSName, NotAfter: stored.NotAfter, RootID: root,
		RootCertificate: rootCertificate, DataKey: dataKey,
	}, nil
}

// Issue issues a held request with its signed certificate and the
// certificate's sealed audit event, in one transaction.
func (store *KubernetesGatewayCertificateStore) Issue(ctx context.Context, installation deployment.ID,
	issue signing.Issue,
) (signing.Outcome, signing.Reason, error) {
	if !store.valid(ctx, installation) || !validIssue(issue) {
		return "", "", ErrInvalidKubernetesClusterCAStore
	}
	// A deadlock or lock timeout (40P01, 55P03) against another writer of
	// the Network redoes the whole transaction.
	settled, err := retryReadConflict(ctx, func() (certificateOutcome, error) {
		outcome, reason, err := store.issueOnce(ctx, installation, issue)
		return certificateOutcome{Outcome: string(outcome), Reason: string(reason)}, err
	})
	return signing.Outcome(settled.Outcome), signing.Reason(settled.Reason), err
}

func validIssue(issue signing.Issue) bool {
	valid := issue.Request.IsValid() && !issue.ClaimToken.IsZero() && issue.ID.IsValid() && issue.CA.IsValid() &&
		issue.CAVersion >= 1 && len(issue.Serial) == 16 && len(issue.Certificate) > 0 && len(issue.PublicKey) > 0 &&
		issue.NotAfter.After(issue.NotBefore) && issue.RenewAt.After(issue.NotBefore) &&
		issue.RenewAt.Before(issue.NotAfter)
	if issue.Token != nil {
		valid = valid && issue.Token.JTI != "" && issue.Token.PodName != "" && !issue.Token.ExpiresAt.IsZero() &&
			issue.TrustVersion >= 1
	}
	return valid
}

func (store *KubernetesGatewayCertificateStore) issueOnce(ctx context.Context, installation deployment.ID,
	issue signing.Issue,
) (outcome signing.Outcome, reason signing.Reason, resultErr error) {
	change, err := freshPublicID()
	if err != nil {
		return "", "", errors.Join(ErrKubernetesClusterCAStore, err)
	}
	var jti, pod, expires, trustVersion any
	if issue.Token != nil {
		jti, pod, expires, trustVersion = issue.Token.JTI, issue.Token.PodName, issue.Token.ExpiresAt, issue.TrustVersion
	}
	err = store.cas.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		var encoded string
		if err := transaction.QueryRow(ctx, issueKubernetesGatewayCertificateSQL, installation.String(),
			issue.Request.String(), issue.ClaimToken.String(), change.String(), issue.ID.String(), issue.CA.String(),
			issue.CAVersion, issue.Serial, issue.Certificate, issue.PublicKey, issue.NotBefore, issue.NotAfter,
			issue.RenewAt, jti, expires, pod, trustVersion).Scan(&encoded); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		settled, err := decodeCertificateOutcome(encoded)
		if err != nil {
			return false, err
		}
		if settled.Outcome != "changed" {
			// Refused, requeued, given back or lost: what the database
			// decided commits; nothing was issued.
			outcome, reason = signing.Outcome(settled.Outcome), signing.Reason(settled.Reason)
			return true, nil
		}
		proof, err := decodeCAProof(encoded, gatewayCertificateAggregateKind, issue.ID, kubeca.Operator{})
		if err != nil {
			return false, err
		}
		if err := appendCertificateEvidence(ctx, transaction, proof, change); err != nil {
			return false, err
		}
		outcome = signing.OutcomeIssued
		return true, nil
	})
	return outcome, reason, err
}

// certificateOutcome is the outcome a settling function returned.
type certificateOutcome struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

// decodeCertificateOutcome reads the outcome of issue, refuse or release;
// the proof of an issue is decoded apart.
func decodeCertificateOutcome(encoded string) (certificateOutcome, error) {
	var head map[string]any
	if err := decodeStrictJSON(encoded, 16384, &head); err != nil {
		return certificateOutcome{}, ErrKubernetesClusterCAStore
	}
	outcome, _ := head["outcome"].(string)
	reason, _ := head["reason"].(string)
	switch outcome {
	case "changed":
		return certificateOutcome{Outcome: outcome}, nil
	case "refused":
		if len(head) == 2 && reason != "" {
			return certificateOutcome{Outcome: outcome, Reason: reason}, nil
		}
	case "requeued", "released", "suspected", "lost", "recorded":
		if len(head) == 1 {
			return certificateOutcome{Outcome: outcome}, nil
		}
	}
	return certificateOutcome{}, ErrKubernetesClusterCAStore
}

func appendCertificateEvidence(ctx context.Context, transaction outboxTransaction, proof caProof,
	change publicid.ID,
) error {
	auditEvent, auditErr := freshPublicID()
	outbox, outboxErr := freshPublicID()
	if auditErr != nil || outboxErr != nil {
		return errors.Join(ErrKubernetesClusterCAStore, auditErr, outboxErr)
	}
	hash, previous, err := hashCAEvent(proof, change, auditEvent)
	if err != nil {
		return err
	}
	var sequence int64
	if err := transaction.QueryRow(ctx, appendKubernetesGatewayCertificateEvidenceSQL, proof.RowID, proof.StreamID,
		proof.Sequence, previous, hash[:], auditEvent.String(), outbox.String(), proof.Payload,
		proof.NetworkRevision).Scan(&sequence); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	if sequence != proof.Sequence {
		return ErrKubernetesClusterCAStore
	}
	return nil
}

// Refuse ends a held request as refused for reason.
func (store *KubernetesGatewayCertificateStore) Refuse(ctx context.Context, installation deployment.ID,
	request publicid.ID, claimToken signing.ClaimToken, reason signing.Reason,
) (signing.Outcome, error) {
	if !store.valid(ctx, installation) || !request.IsValid() || claimToken.IsZero() || reason == "" {
		return "", ErrInvalidKubernetesClusterCAStore
	}
	return store.settle(ctx, refuseKubernetesGatewayCertificateSQL, installation.String(), request.String(),
		claimToken.String(), string(reason))
}

// Release gives a held request back to wait again.
func (store *KubernetesGatewayCertificateStore) Release(ctx context.Context, installation deployment.ID,
	request publicid.ID, claimToken signing.ClaimToken,
) (signing.Outcome, error) {
	if !store.valid(ctx, installation) || !request.IsValid() || claimToken.IsZero() {
		return "", ErrInvalidKubernetesClusterCAStore
	}
	return store.settle(ctx, releaseKubernetesGatewayCertificateSQL, installation.String(), request.String(),
		claimToken.String())
}

func (store *KubernetesGatewayCertificateStore) settle(ctx context.Context, statement string,
	arguments ...any,
) (signing.Outcome, error) {
	encoded, err := store.cas.queryText(ctx, statement, arguments...)
	if err != nil {
		return "", err
	}
	settled, err := decodeCertificateOutcome(encoded)
	if err != nil || settled.Outcome == "changed" {
		return "", ErrKubernetesClusterCAStore
	}
	return signing.Outcome(settled.Outcome), nil
}

// RecordToken replaces a held request's pod token with the claims the worker
// checked in it (schema 241, §14 R-M1).
func (store *KubernetesGatewayCertificateStore) RecordToken(ctx context.Context, installation deployment.ID,
	request publicid.ID, claimToken signing.ClaimToken, verified signing.VerifiedToken,
) (signing.Outcome, error) {
	if !store.valid(ctx, installation) || !request.IsValid() || claimToken.IsZero() || !verified.Valid() {
		return "", ErrInvalidKubernetesClusterCAStore
	}
	outcome, err := store.settle(ctx, recordKubernetesGatewayCertificateClaimsSQL, installation.String(),
		request.String(), claimToken.String(), verified.Use.JTI, verified.Use.ExpiresAt, verified.Use.PodName,
		verified.TrustVersion)
	if err == nil && outcome != signing.OutcomeRecorded && outcome != signing.OutcomeLost {
		return "", ErrKubernetesClusterCAStore
	}
	return outcome, err
}

// Prune removes the installation's ended or abandoned requests older than
// ten minutes and ledger rows older than 13 months, at most limit of each.
func (store *KubernetesGatewayCertificateStore) Prune(ctx context.Context, installation deployment.ID,
	limit int,
) (int, int, error) {
	if !store.valid(ctx, installation) || limit < 1 || limit > 10000 {
		return 0, 0, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.cas.queryText(ctx, pruneKubernetesGatewayCertificatesSQL, installation.String(), limit)
	if err != nil {
		return 0, 0, err
	}
	var record struct {
		Requests     *int `json:"requests"`
		Certificates *int `json:"certificates"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil || record.Requests == nil ||
		record.Certificates == nil {
		return 0, 0, ErrKubernetesClusterCAStore
	}
	return *record.Requests, *record.Certificates, nil
}

// Fleet reads up to limit active gateway Devices of active clusters after
// (cluster, ordinal): when each one's latest certificate expires and
// whether it asked lately (schema 243, a4d).
func (store *KubernetesGatewayCertificateStore) Fleet(ctx context.Context, installation deployment.ID,
	afterCluster int64, afterOrdinal, limit int,
) ([]signing.FleetRow, error) {
	if !store.valid(ctx, installation) || afterCluster < 0 || afterOrdinal < 0 || afterOrdinal > 63 || limit < 1 ||
		limit > gatewayCertificateMaximumFleet {
		return nil, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.cas.queryText(ctx, readKubernetesGatewayCertificateFleetSQL, installation.String(),
		afterCluster, afterOrdinal, limit)
	if err != nil {
		return nil, err
	}
	var record struct {
		Rows *[][5]json.RawMessage `json:"rows"`
	}
	if err := decodeStrictJSON(encoded, gatewayCertificateMaximumFleetText, &record); err != nil ||
		record.Rows == nil || len(*record.Rows) > limit {
		return nil, ErrKubernetesClusterCAStore
	}
	rows := make([]signing.FleetRow, 0, len(*record.Rows))
	for _, raw := range *record.Rows {
		row, ok := decodeFleetRow(raw)
		if !ok || row.Cluster < afterCluster || row.Cluster == afterCluster && row.Ordinal <= afterOrdinal {
			return nil, ErrKubernetesClusterCAStore
		}
		rows = append(rows, row)
		afterCluster, afterOrdinal = row.Cluster, row.Ordinal
	}
	return rows, nil
}

// decodeFleetRow reads [cluster, ordinal, not_after_ms|null, asking,
// unserved].
func decodeFleetRow(raw [5]json.RawMessage) (signing.FleetRow, bool) {
	var (
		row      signing.FleetRow
		notAfter *int64
	)
	if json.Unmarshal(raw[0], &row.Cluster) != nil || json.Unmarshal(raw[1], &row.Ordinal) != nil ||
		json.Unmarshal(raw[2], &notAfter) != nil || json.Unmarshal(raw[3], &row.Asking) != nil ||
		json.Unmarshal(raw[4], &row.Unserved) != nil || row.Unserved && !row.Asking ||
		row.Cluster < 1 || row.Ordinal < 0 || row.Ordinal > 63 || notAfter != nil && *notAfter <= 0 {
		return signing.FleetRow{}, false
	}
	if notAfter != nil {
		row.NotAfter = time.UnixMilli(*notAfter)
	}
	return row, true
}

// Beat records the signing worker's heartbeat, as the CA store does.
func (store *KubernetesGatewayCertificateStore) Beat(ctx context.Context, installation deployment.ID,
	instance publicid.ID, ready bool, version, custody string, capabilities []string,
) (time.Time, error) {
	if store == nil {
		return time.Time{}, ErrInvalidKubernetesClusterCAStore
	}
	return store.cas.Beat(ctx, installation, instance, ready, version, custody, capabilities)
}

var _ signing.Store = (*KubernetesGatewayCertificateStore)(nil)
