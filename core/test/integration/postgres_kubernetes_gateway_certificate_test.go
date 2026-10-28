//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/adapter/kubecustody"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/certqueue"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/domain/kubeca/signing"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/mtcp"
)

// certificateAsk is one gateway certificate request as control queues it.
type certificateAsk struct {
	publicID  publicid.ID
	id        [16]byte
	key       *ecdsa.PrivateKey
	token     *string
	handshake []byte
	serial    []byte
	proof     []byte
}

func (ask certificateAsk) csr(t *testing.T) ([]byte, [sha256.Size]byte) {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ask.key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&ask.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return csr, sha256.Sum256(spki)
}

func newCertificateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// renewalAsk is a renewal of certificate with proof, under a handshake of
// its own.
func renewalAsk(t *testing.T, id byte, certificate *x509.Certificate, proof []byte) certificateAsk {
	t.Helper()
	handshake := sha256.Sum256([]byte{id})
	return certificateAsk{
		publicID: mustPublicID(t), id: [16]byte{id}, key: newCertificateKey(t), handshake: handshake[:],
		serial: certificate.SerialNumber.FillBytes(make([]byte, 16)), proof: proof,
	}
}

func tokenAsk(t *testing.T, id byte, key *ecdsa.PrivateKey, token string) certificateAsk {
	t.Helper()
	return certificateAsk{publicID: mustPublicID(t), id: [16]byte{id}, key: key, token: &token}
}

// enqueueCertificate queues ask for the session keys proved, as control
// does, and returns what the database answered.
func enqueueCertificate(ctx context.Context, t *testing.T, runtime *pgx.Conn, keys replicaKeys, ask certificateAsk,
	csr []byte, digest [sha256.Size]byte,
) map[string]any {
	t.Helper()
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.mark_session_proven_v1($1, $2)`, fingerprintOf(keys),
		nodeKeyOf(keys)); err != nil {
		t.Fatal(err)
	}
	var encoded string
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.enqueue_kubernetes_gateway_certificate_v1(
    $1, $2, $3::UUID, $4, $5, $6, $7, $8, $9, $10)::TEXT`, fingerprintOf(keys), nodeKeyOf(keys),
		ask.publicID.String(), ask.id[:], csr, digest[:], ask.token, ask.handshake, ask.serial, ask.proof,
	).Scan(&encoded); err != nil {
		t.Fatalf("enqueue a certificate request: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return decodeCertificateAnswer(t, encoded)
}

func readCertificate(ctx context.Context, t *testing.T, runtime *pgx.Conn, deviceID string, request any) map[string]any {
	t.Helper()
	var encoded *string
	if err := runtime.QueryRow(ctx, `SELECT mesh_ops.read_kubernetes_gateway_certificate_v1($1::UUID, $2::UUID)::TEXT`,
		deviceID, request).Scan(&encoded); err != nil {
		t.Fatalf("read a certificate request: %v", err)
	}
	if encoded == nil {
		return nil
	}
	return decodeCertificateAnswer(t, *encoded)
}

func decodeCertificateAnswer(t *testing.T, encoded string) map[string]any {
	t.Helper()
	var answer map[string]any
	if err := json.Unmarshal([]byte(encoded), &answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

// assertGatewayCertificates: a gateway's certificate request is queued by
// control for the keys its session proved, claimed with a lease and issued
// by the worker after it checked the pod token or the renewal signature
// again; the database enforces one token use per key, the limits, the CA
// still active, and stops it all while a restore is suspected.
func assertGatewayCertificates(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool, fixture clusterCAFixture, keys replicaKeys, deviceID string,
) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesGatewayCertificateStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := kubecustody.NewFile(kubeca.DataKey(filledIntegrationKey(0x39)),
		[]kubeca.DataKey{kubeca.DataKey(filledIntegrationKey(0x38))})
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := dnsname.ParseSuffix("mesh.internal")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := signing.New(signing.Options{
		DeploymentID: fixture.installation, Suffix: suffix, Version: "integration", BatchSize: 8,
		OperationTimeout: 20 * time.Second, MaximumPerSecond: 100,
	}, store, func(context.Context) (kubeca.Custody, string, error) { return custody, "file", nil },
		func(raw string, trust signing.Trust, now time.Time) (signing.TokenUse, error) {
			if len(raw) < 4 || raw[:4] != "pod-" {
				return signing.TokenUse{}, errors.New("refused")
			}
			return signing.TokenUse{JTI: raw, ExpiresAt: now.Add(10 * time.Minute), PodName: trust.PodName}, nil
		}, mtcp.VerifyKubeCertRenewal, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	root, intermediate := activeClusterCAs(ctx, t, fixture)

	// Nothing is signed while the lifecycle worker has not checked the
	// restore tripwire for 10 minutes (schema 241, a3 §14 R-M9).
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_ca_guard
SET checked_at = pg_catalog.clock_timestamp() - INTERVAL '11 minutes'`); err != nil {
		t.Fatal(err)
	}
	if batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second); err != nil || !batch.Unchecked ||
		len(batch.Claims) != 0 {
		t.Fatalf("a claim before the tripwire was checked = %+v, %v", batch, err)
	}
	if err := fixture.store.StampGuard(ctx, fixture.installation, 1); err != nil {
		t.Fatal(err)
	}

	// A token request waits; asking again with the same id finds it; with
	// another key it conflicts.
	first := tokenAsk(t, 1, newCertificateKey(t), "pod-token-1")
	csr, digest := first.csr(t)
	if answer := enqueueCertificate(ctx, t, runtime, keys, first, csr, digest); answer["outcome"] != "pending" ||
		answer["request_id"] != first.publicID.String() {
		t.Fatalf("a first request: %v", answer)
	}
	again := first
	again.publicID = mustPublicID(t)
	if answer := enqueueCertificate(ctx, t, runtime, keys, again, csr, digest); answer["outcome"] != "pending" ||
		answer["request_id"] != first.publicID.String() {
		t.Fatalf("the same request again: %v", answer)
	}
	otherCSR, otherDigest := tokenAsk(t, 1, newCertificateKey(t), "pod-token-1").csr(t)
	if answer := enqueueCertificate(ctx, t, runtime, keys, again, otherCSR, otherDigest); answer["outcome"] != "conflict" {
		t.Fatalf("the same id for another key: %v", answer)
	}

	// The worker signs it under the cluster's intermediate, for its name.
	if handled := worker.Pass(ctx); handled != 1 || worker.Snapshot().Issued != 1 {
		t.Fatalf("Pass() = %d, %+v", handled, worker.Snapshot())
	}
	issued := readCertificate(ctx, t, runtime, deviceID, first.publicID.String())
	certificate := assertIssuedCertificate(t, issued, fixture, root, intermediate)
	certificateID := ledgerCertificateID(ctx, t, admin, first.publicID)
	assertCAEvents(ctx, t, admin, "kubernetes_gateway_certificate", certificateID, "system.reconcile",
		"kubernetes_gateway.certificate_issued")
	if answer := enqueueCertificate(ctx, t, runtime, keys, again, csr, digest); answer["outcome"] != "issued" ||
		answer["certificate"] != issued["certificate"] {
		t.Fatalf("an issued request asked again: %v", answer)
	}
	var uses int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_token_use
WHERE purpose = 'cert' AND jti = 'pod-token-1'`).Scan(&uses); err != nil || uses != 1 {
		t.Fatalf("token uses = %d, %v", uses, err)
	}

	// The same token for the same key under another id is used up.
	reused := tokenAsk(t, 2, first.key, "pod-token-1")
	reusedCSR, reusedDigest := reused.csr(t)
	enqueueCertificate(ctx, t, runtime, keys, reused, reusedCSR, reusedDigest)
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, reused.publicID.String()); answer["outcome"] != "refused" ||
		answer["reason"] != "token_used" {
		t.Fatalf("a token used twice for a key: %v", answer)
	}

	// A renewal is signed by the key of the certificate it renews.
	assertCertificateRenewal(ctx, t, runtime, worker, keys, deviceID, first, certificate)

	assertCertificateLimits(ctx, t, admin, runtime, worker, keys, deviceID, certificate)
	assertCertificateQueue(ctx, t, admin, runtime, runtimePool, store, worker, fixture, keys, certificate)
	assertMapKubernetesCAs(ctx, t, admin, runtime, fixture, root, intermediate)
	assertCertificateLeases(ctx, t, admin, runtime, store, fixture, keys)
	assertCertificatePrivileges(ctx, t, admin)
	assertCertificatePruning(ctx, t, admin, store, fixture, first.publicID)
	assertCertificateCAChange(ctx, t, admin, runtime, store, worker, fixture, keys, intermediate)
	assertCertificateRestoreGuard(ctx, t, runtime, store, fixture, keys)
}

// activeClusterCAs returns the fixture cluster's active root and
// intermediate.
func activeClusterCAs(ctx context.Context, t *testing.T, fixture clusterCAFixture) (kubeca.StoredCA, kubeca.StoredCA) {
	t.Helper()
	var root, intermediate kubeca.StoredCA
	for _, ca := range findCluster(t, fixture.read(ctx, t), fixture.cluster).CAs {
		switch {
		case ca.Kind == kubeca.KindRoot && ca.State == kubeca.StateActive:
			root = ca
		case ca.Kind == kubeca.KindIntermediate && ca.State == kubeca.StateActive:
			intermediate = ca
		}
	}
	if !root.ID.IsValid() || intermediate.IssuerID != root.ID {
		t.Fatalf("the cluster has no active root and intermediate")
	}
	return root, intermediate
}

func assertIssuedCertificate(t *testing.T, issued map[string]any, fixture clusterCAFixture, root,
	intermediate kubeca.StoredCA,
) *x509.Certificate {
	t.Helper()
	leaf, leafErr := hex.DecodeString(stringField(issued, "certificate"))
	chain, _ := issued["chain"].([]any)
	if issued["outcome"] != "issued" || leafErr != nil || len(chain) != 1 ||
		chain[0] != hex.EncodeToString(intermediate.Certificate) {
		t.Fatalf("issued = %v", issued)
	}
	rootFingerprint, intermediateFingerprint := sha256.Sum256(root.Certificate), sha256.Sum256(intermediate.Certificate)
	if issued["root_fingerprint"] != hex.EncodeToString(rootFingerprint[:]) ||
		issued["issuer_fingerprint"] != hex.EncodeToString(intermediateFingerprint[:]) {
		t.Fatalf("fingerprints = %v, %v", issued["root_fingerprint"], issued["issuer_fingerprint"])
	}
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	rootCertificate, _ := x509.ParseCertificate(root.Certificate)
	intermediateCertificate, _ := x509.ParseCertificate(intermediate.Certificate)
	roots.AddCert(rootCertificate)
	intermediates.AddCert(intermediateCertificate)
	if _, err := certificate.Verify(x509.VerifyOptions{
		DNSName: fixture.dnsName, Roots: roots, Intermediates: intermediates,
	}); err != nil {
		t.Fatalf("the issued certificate does not verify for %s: %v", fixture.dnsName, err)
	}
	renewAt, err := time.Parse(time.RFC3339Nano, stringField(issued, "renew_at"))
	if err != nil || !renewAt.After(certificate.NotBefore) || !renewAt.Before(certificate.NotAfter) {
		t.Fatalf("renew at %v, %v", issued["renew_at"], err)
	}
	return certificate
}

func stringField(answer map[string]any, name string) string {
	value, _ := answer[name].(string)
	return value
}

func ledgerCertificateID(ctx context.Context, t *testing.T, admin *pgx.Conn, request publicid.ID) publicid.ID {
	t.Helper()
	var text string
	if err := admin.QueryRow(ctx, `SELECT public_id::TEXT FROM mesh.kubernetes_gateway_certificate
WHERE request_public_id = $1::UUID`, request.String()).Scan(&text); err != nil {
		t.Fatalf("the ledger has no certificate for the request: %v", err)
	}
	id, err := publicid.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertCertificateRenewal(ctx context.Context, t *testing.T, runtime *pgx.Conn, worker *signing.Worker,
	keys replicaKeys, deviceID string, current certificateAsk, certificate *x509.Certificate,
) {
	t.Helper()
	handshake := sha256.Sum256([]byte("handshake"))
	renewal := certificateAsk{
		publicID: mustPublicID(t), id: [16]byte{3}, key: newCertificateKey(t), handshake: handshake[:],
		serial: certificate.SerialNumber.FillBytes(make([]byte, 16)),
	}
	csr, digest := renewal.csr(t)
	proof, err := mtcp.SignKubeCertRenewal(current.key, handshake, renewal.id, [16]byte(renewal.serial), csr)
	if err != nil {
		t.Fatal(err)
	}
	renewal.proof = proof
	enqueueCertificate(ctx, t, runtime, keys, renewal, csr, digest)
	// One signed by a key the gateway never held is refused.
	forged := renewal
	forged.publicID, forged.id = mustPublicID(t), [16]byte{4}
	forgedCSR, forgedDigest := forged.csr(t)
	if forged.proof, err = mtcp.SignKubeCertRenewal(newCertificateKey(t), handshake, forged.id,
		[16]byte(forged.serial), forgedCSR); err != nil {
		t.Fatal(err)
	}
	enqueueCertificate(ctx, t, runtime, keys, forged, forgedCSR, forgedDigest)
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, renewal.publicID.String()); answer["outcome"] != "issued" {
		t.Fatalf("a renewal: %v", answer)
	}
	if answer := readCertificate(ctx, t, runtime, deviceID, forged.publicID.String()); answer["outcome"] != "refused" ||
		answer["reason"] != "proof" {
		t.Fatalf("a forged renewal: %v", answer)
	}
	// A serial the Device does not hold is refused when queued.
	unknown := renewal
	unknown.publicID, unknown.id, unknown.serial = mustPublicID(t), [16]byte{5}, make([]byte, 16)
	if answer := enqueueCertificate(ctx, t, runtime, keys, unknown, csr, digest); answer["outcome"] != "refused" ||
		answer["reason"] != "renewal_unknown" {
		t.Fatalf("a renewal of an unknown certificate: %v", answer)
	}
}

// assertCertificateLimits: two requests in flight per Device, twelve issued
// per Device and hour. A token request supersedes the Device's others, so
// the requests in flight are renewals (their proofs are refused later).
func assertCertificateLimits(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, worker *signing.Worker,
	keys replicaKeys, deviceID string, certificate *x509.Certificate,
) {
	t.Helper()
	ask := func(id byte) map[string]any {
		request := tokenAsk(t, id, newCertificateKey(t), fmt.Sprintf("pod-limit-%d", id))
		csr, digest := request.csr(t)
		return enqueueCertificate(ctx, t, runtime, keys, request, csr, digest)
	}
	renew := func(id byte) map[string]any {
		request := renewalAsk(t, id, certificate, []byte("not-a-signature"))
		csr, digest := request.csr(t)
		return enqueueCertificate(ctx, t, runtime, keys, request, csr, digest)
	}
	renew(10)
	renew(11)
	if answer := renew(12); answer["outcome"] != "limited" || answer["retry_after_ms"] != float64(2000) {
		t.Fatalf("a third request in flight: %v", answer)
	}
	worker.Pass(ctx)
	var issued int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.kubernetes_gateway_certificate
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, deviceID).Scan(&issued); err != nil {
		t.Fatal(err)
	}
	for id := byte(13); issued < 12; id++ {
		if answer := ask(id); answer["outcome"] != "pending" {
			t.Fatalf("request %d: %v", id, answer)
		}
		worker.Pass(ctx)
		issued++
	}
	answer := ask(40)
	retry, _ := answer["retry_after_ms"].(float64)
	if answer["outcome"] != "limited" || retry < 1000 || retry > float64(time.Hour/time.Millisecond) {
		t.Fatalf("a thirteenth certificate within the hour: %v", answer)
	}
	// Later tests start from an empty hour.
	if _, err := admin.Exec(ctx, `ALTER TABLE mesh.kubernetes_gateway_certificate DISABLE TRIGGER kubernetes_gateway_certificate_guard;
UPDATE mesh.kubernetes_gateway_certificate SET issued_at = issued_at - INTERVAL '2 hours';
ALTER TABLE mesh.kubernetes_gateway_certificate ENABLE TRIGGER kubernetes_gateway_certificate_guard`); err != nil {
		t.Fatal(err)
	}
}

// assertCertificateLeases: a claim holds a request for its lease; one that
// runs out waits again, and after three leases is refused. Two workers
// never claim the same request.
func assertCertificateLeases(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	store *postgresadapter.KubernetesGatewayCertificateStore, fixture clusterCAFixture, keys replicaKeys,
) {
	t.Helper()
	request := tokenAsk(t, 50, newCertificateKey(t), "pod-lease")
	csr, digest := request.csr(t)
	enqueueCertificate(ctx, t, runtime, keys, request, csr, digest)
	expire := func() {
		t.Helper()
		if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_certificate_request
SET claim_expires_at = pg_catalog.clock_timestamp() - INTERVAL '1 second'
WHERE public_id = $1::UUID AND state = 'claimed'`, request.publicID.String()); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 1; attempt <= 3; attempt++ {
		batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second)
		if err != nil || len(batch.Claims) != 1 || batch.Claims[0].ID != request.publicID ||
			batch.Claims[0].Proof != signing.ProofToken || batch.Claims[0].Trust == nil ||
			!batch.Claims[0].Trust.Complete() || batch.Claims[0].Intermediate == nil || batch.Suffix != "mesh.internal" {
			t.Fatalf("claim %d = %+v, %v", attempt, batch, err)
		}
		// Held: another worker claims nothing.
		if other, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second); err != nil || len(other.Claims) != 0 {
			t.Fatalf("a second worker claimed %d, %v", len(other.Claims), err)
		}
		expire()
	}
	if batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second); err != nil || len(batch.Claims) != 0 {
		t.Fatalf("a request after three leases was claimed: %d, %v", len(batch.Claims), err)
	}
	var state, reason string
	if err := admin.QueryRow(ctx, `SELECT state, reason FROM mesh_ops.kubernetes_gateway_certificate_request
WHERE public_id = $1::UUID`, request.publicID.String()).Scan(&state, &reason); err != nil || state != "refused" ||
		reason != "attempts" {
		t.Fatalf("after three leases: %s %s, %v", state, reason, err)
	}
	// A claim that ran out settles nothing.
	held := tokenAsk(t, 51, newCertificateKey(t), "pod-lease-2")
	heldCSR, heldDigest := held.csr(t)
	enqueueCertificate(ctx, t, runtime, keys, held, heldCSR, heldDigest)
	batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second)
	if err != nil || len(batch.Claims) != 1 {
		t.Fatalf("claim = %+v, %v", batch, err)
	}
	if outcome, err := store.Refuse(ctx, fixture.installation, held.publicID, signing.ClaimToken{1}, "csr"); err != nil ||
		outcome != signing.OutcomeLost {
		t.Fatalf("a refusal with another claim's token = %s, %v", outcome, err)
	}
	if outcome, err := store.Release(ctx, fixture.installation, held.publicID, batch.Claims[0].ClaimToken); err != nil ||
		outcome != signing.OutcomeReleased {
		t.Fatalf("Release() = %s, %v", outcome, err)
	}
	if outcome, err := store.Refuse(ctx, fixture.installation, held.publicID, batch.Claims[0].ClaimToken, "csr"); err != nil ||
		outcome != signing.OutcomeLost {
		t.Fatalf("a refusal after the release = %s, %v", outcome, err)
	}
	// Control gives up waiting: an unclaimed request is abandoned, and
	// asking again with the same id makes it wait again.
	var abandoned string
	deviceID := deviceOfRequest(ctx, t, admin, held.publicID)
	if err := runtime.QueryRow(ctx, `SELECT mesh_ops.abandon_kubernetes_gateway_certificate_v1($1::UUID, $2::UUID)::TEXT`,
		deviceID, held.publicID.String()).Scan(&abandoned); err != nil ||
		decodeCertificateAnswer(t, abandoned)["outcome"] != "abandoned" {
		t.Fatalf("abandon = %s, %v", abandoned, err)
	}
	if answer := enqueueCertificate(ctx, t, runtime, keys, held, heldCSR, heldDigest); answer["outcome"] != "pending" {
		t.Fatalf("an abandoned request asked again: %v", answer)
	}
	if outcome, err := store.Release(ctx, fixture.installation, held.publicID, batch.Claims[0].ClaimToken); err != nil ||
		outcome != signing.OutcomeLost {
		t.Fatalf("a stale release = %s, %v", outcome, err)
	}
	if err := runtime.QueryRow(ctx, `SELECT mesh_ops.abandon_kubernetes_gateway_certificate_v1($1::UUID, $2::UUID)::TEXT`,
		deviceID, held.publicID.String()).Scan(&abandoned); err != nil {
		t.Fatal(err)
	}
}

func deviceOfRequest(ctx context.Context, t *testing.T, admin *pgx.Conn, request publicid.ID) string {
	t.Helper()
	var device string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT FROM mesh_ops.kubernetes_gateway_certificate_request AS request
JOIN mesh.device AS device ON device.id = request.device_id WHERE request.public_id = $1::UUID`,
		request.String()).Scan(&device); err != nil {
		t.Fatal(err)
	}
	return device
}

// assertCertificatePrivileges: control queues, reads and abandons; only the
// worker claims, signs and issues.
func assertCertificatePrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	for _, check := range []struct {
		role, function string
		allowed        bool
	}{
		{"mesh_runtime", "mesh_ops.enqueue_kubernetes_gateway_certificate_v1(BYTEA, BYTEA, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, BYTEA, BYTEA)", true},
		{"mesh_worker", "mesh_ops.enqueue_kubernetes_gateway_certificate_v1(BYTEA, BYTEA, UUID, BYTEA, BYTEA, BYTEA, TEXT, BYTEA, BYTEA, BYTEA)", false},
		{"mesh_runtime", "mesh_ops.claim_kubernetes_gateway_certificates_v1(UUID, INTEGER, INTEGER)", false},
		{"mesh_worker", "mesh_ops.claim_kubernetes_gateway_certificates_v1(UUID, INTEGER, INTEGER)", true},
		{"mesh_runtime", "mesh_ops.issue_kubernetes_gateway_certificate_v1(UUID, UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, TIMESTAMPTZ, TEXT, BIGINT)", false},
		{"mesh_runtime", "mesh_ops.mark_kubernetes_ca_restored_v1(UUID, TEXT, TEXT)", false},
		{"mesh_observer", "mesh_ops.read_kubernetes_gateway_certificate_v1(UUID, UUID)", false},
		// Schema 241: control reads whether anyone signs; only the worker
		// records token claims and stamps the guard.
		{"mesh_runtime", "mesh_ops.read_kubernetes_ca_signing_state_v1()", true},
		{"mesh_worker", "mesh_ops.read_kubernetes_ca_signing_state_v1()", false},
		{"mesh_observer", "mesh_ops.read_kubernetes_ca_signing_state_v1()", false},
		{"mesh_runtime", "mesh_ops.record_kubernetes_gateway_certificate_token_v1(UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TEXT, BIGINT)", false},
		{"mesh_worker", "mesh_ops.record_kubernetes_gateway_certificate_token_v1(UUID, UUID, UUID, TEXT, TIMESTAMPTZ, TEXT, BIGINT)", true},
		{"mesh_runtime", "mesh_ops.stamp_kubernetes_ca_guard_v1(UUID, BIGINT)", false},
		{"mesh_worker", "mesh_ops.stamp_kubernetes_ca_guard_v1(UUID, BIGINT)", true},
	} {
		var allowed bool
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege($1, $2, 'EXECUTE')`, check.role,
			check.function).Scan(&allowed); err != nil || allowed != check.allowed {
			t.Errorf("%s on %s: %v, %v", check.role, check.function, allowed, err)
		}
	}
	for _, table := range []string{
		"mesh.kubernetes_gateway_certificate", "mesh_ops.kubernetes_gateway_certificate_request",
		"mesh_ops.kubernetes_ca_guard",
	} {
		for _, role := range []string{"mesh_runtime", "mesh_worker", "mesh_observer"} {
			var allowed bool
			if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege($1, $2, 'SELECT')`, role,
				table).Scan(&allowed); err != nil || allowed {
				t.Errorf("%s reads %s: %v, %v", role, table, allowed, err)
			}
		}
	}
	// The ledger is kept as issued.
	if _, err := admin.Exec(ctx, `UPDATE mesh.kubernetes_gateway_certificate SET pod_name = pod_name`); err == nil {
		t.Error("a certificate row was changed")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM mesh.kubernetes_gateway_certificate`); err == nil {
		t.Error("a young certificate row was deleted")
	}
}

// assertCertificatePruning: requests go after ten minutes.
func assertCertificatePruning(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.KubernetesGatewayCertificateStore, fixture clusterCAFixture, request publicid.ID,
) {
	t.Helper()
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_certificate_request
SET created_at = created_at - INTERVAL '11 minutes' WHERE public_id = $1::UUID`, request.String()); err != nil {
		t.Fatal(err)
	}
	requests, _, err := store.Prune(ctx, fixture.installation, 1000)
	if err != nil || requests < 1 {
		t.Fatalf("Prune() = %d, %v", requests, err)
	}
	var left int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_certificate_request
WHERE public_id = $1::UUID`, request.String()).Scan(&left); err != nil || left != 0 {
		t.Fatalf("a request older than ten minutes is kept: %d, %v", left, err)
	}
}

// assertCertificateCAChange: an intermediate that changed between the
// claim and the issue gets the request signed again, and a worker change
// to a CA advances the Network revision once.
func assertCertificateCAChange(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	store *postgresadapter.KubernetesGatewayCertificateStore, worker *signing.Worker, fixture clusterCAFixture,
	keys replicaKeys, intermediate kubeca.StoredCA,
) {
	t.Helper()
	request := tokenAsk(t, 60, newCertificateKey(t), "pod-ca-change")
	csr, digest := request.csr(t)
	enqueueCertificate(ctx, t, runtime, keys, request, csr, digest)
	batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second)
	if err != nil || len(batch.Claims) != 1 {
		t.Fatalf("claim = %+v, %v", batch, err)
	}
	revision := func() int64 {
		t.Helper()
		var value int64
		if err := admin.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_revision AS revision
JOIN mesh.network AS network ON network.id = revision.network_id WHERE network.public_id = $1::UUID`,
			fixture.scope.NetworkID().String()).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := revision()
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{
		move(intermediate.ID, intermediate.Version, kubeca.StateRetiring, kubeca.ReasonAdmin),
	}})
	if after := revision(); after != before+1 {
		t.Fatalf("a CA change moved the revision from %d to %d", before, after)
	}
	claim := batch.Claims[0]
	issue := signedIssue(ctx, t, claim, batch.Now, fixture)
	if outcome, err := store.RecordToken(ctx, fixture.installation, claim.ID, claim.ClaimToken,
		signing.VerifiedToken{Use: *issue.Token, TrustVersion: issue.TrustVersion}); err != nil ||
		outcome != signing.OutcomeRecorded {
		t.Fatalf("RecordToken() = %s, %v", outcome, err)
	}
	if outcome, _, err := store.Issue(ctx, fixture.installation, issue); err != nil || outcome != signing.OutcomeRequeued {
		t.Fatalf("an issue after the CA changed = %s, %v", outcome, err)
	}
	// Signed again: the cluster has no active intermediate now.
	worker.Pass(ctx)
	deviceID := deviceOfRequest(ctx, t, admin, request.publicID)
	if answer := readCertificate(ctx, t, runtime, deviceID, request.publicID.String()); answer["outcome"] != "refused" ||
		answer["reason"] != "no_ca" {
		t.Fatalf("a request without an active intermediate: %v", answer)
	}
}

// signedIssue signs a claim as the worker would, for tests that settle it
// by hand.
func signedIssue(ctx context.Context, t *testing.T, claim signing.Claim, now time.Time,
	fixture clusterCAFixture,
) signing.Issue {
	t.Helper()
	custody, err := kubecustody.NewFile(kubeca.DataKey(filledIntegrationKey(0x39)),
		[]kubeca.DataKey{kubeca.DataKey(filledIntegrationKey(0x38))})
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := custody.OpenDataKey(ctx, fixture.scope.NetworkID().String(), claim.Intermediate.DataKey.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(claim.Intermediate.RootCertificate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := kubeca.OpenIntermediate(dataKey, claim.Intermediate.Certificate, claim.Intermediate.SealedKey,
		fixture.installation.String(), claim.ClusterID.String(), claim.Intermediate.ID.String(), root)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.SignReplica(kubeca.ReplicaRequest{CSR: claim.CSR, ClusterDNSName: fixture.dnsName, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(issued.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	return signing.Issue{
		Request: claim.ID, ClaimToken: claim.ClaimToken, ID: mustPublicID(t), CA: claim.Intermediate.ID,
		CAVersion: claim.Intermediate.Version, Serial: issued.Serial.FillBytes(make([]byte, 16)),
		Certificate: issued.Certificate, PublicKey: certificate.RawSubjectPublicKeyInfo, NotBefore: issued.NotBefore,
		NotAfter: issued.NotAfter, RenewAt: now.Add(12 * time.Hour),
		Token: &signing.TokenUse{
			JTI: claim.Token, ExpiresAt: now.Add(10 * time.Minute).Truncate(time.Second), PodName: claim.Trust.PodName,
		},
		TrustVersion: claim.Trust.Version,
	}
}

// assertCertificateRestoreGuard: once a restore is marked nothing is
// claimed or issued, until reconcile retired every intermediate and cleared
// the guard.
func assertCertificateRestoreGuard(ctx context.Context, t *testing.T, runtime *pgx.Conn,
	store *postgresadapter.KubernetesGatewayCertificateStore, fixture clusterCAFixture, keys replicaKeys,
) {
	t.Helper()
	guard, err := fixture.store.ReadGuard(ctx, fixture.installation)
	if err != nil || guard.Suspected || guard.Generation != 1 || guard.CertificateMark < 1 || guard.CAMark < 1 {
		t.Fatalf("ReadGuard() = %+v, %v", guard, err)
	}
	request := tokenAsk(t, 70, newCertificateKey(t), "pod-restore")
	csr, digest := request.csr(t)
	enqueueCertificate(ctx, t, runtime, keys, request, csr, digest)
	batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second)
	if err != nil || len(batch.Claims) != 1 {
		t.Fatalf("claim = %+v, %v", batch, err)
	}
	operator := kubeca.Operator{Name: "soc@example.com", ChangeRef: "INC-12"}
	if err := lifecycle.MarkRestored(ctx, fixture.store, fixture.installation, operator); err != nil {
		t.Fatal(err)
	}
	if batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second); err != nil || !batch.Suspected ||
		len(batch.Claims) != 0 {
		t.Fatalf("a claim while a restore is suspected = %+v, %v", batch, err)
	}
	issue := signing.Issue{
		Request: batch.Claims[0].ID, ClaimToken: batch.Claims[0].ClaimToken, ID: mustPublicID(t),
		CA: mustPublicID(t), CAVersion: 1, Serial: make([]byte, 16), Certificate: []byte{1}, PublicKey: []byte{1},
		NotBefore: batch.Now, NotAfter: batch.Now.Add(time.Hour), RenewAt: batch.Now.Add(time.Minute),
		Token:        &signing.TokenUse{JTI: "pod-restore", ExpiresAt: batch.Now.Add(time.Minute), PodName: "p"},
		TrustVersion: 1,
	}
	if outcome, _, err := store.Issue(ctx, fixture.installation, issue); err != nil || outcome != signing.OutcomeSuspected {
		t.Fatalf("an issue while a restore is suspected = %s, %v", outcome, err)
	}
	// The worker changes no CA meanwhile, whatever it read before.
	left, err := fixture.store.ListActiveIntermediates(ctx, fixture.installation, 256)
	if err != nil || len(left) == 0 {
		t.Fatalf("ListActiveIntermediates() = %d, %v", len(left), err)
	}
	stopped := fixture
	stopped.scope = left[0].Scope
	stopped.refused(ctx, t, "a worker CA change while a restore is suspected", kubeca.Changes{Steps: []kubeca.Step{
		move(left[0].CA, left[0].Version, kubeca.StateRetiring, kubeca.ReasonScheduled),
	}})
	// Clearing the guard needs every intermediate retired.
	if _, err := fixture.store.ClearRestore(ctx, fixture.installation, 1, operator); !errors.Is(err,
		postgresadapter.ErrKubernetesCAIntermediatesActive) {
		t.Fatalf("ClearRestore() with active intermediates = %v", err)
	}
	retired, err := lifecycle.ReconcileAfterRestore(ctx, fixture.store, fixture.installation, operator)
	if err != nil {
		t.Fatalf("ReconcileAfterRestore() = %d, %v", retired, err)
	}
	if left, err := fixture.store.ListActiveIntermediates(ctx, fixture.installation, 256); err != nil || len(left) != 0 {
		t.Fatalf("intermediates left active: %d, %v", len(left), err)
	}
	if guard, err := fixture.store.ReadGuard(ctx, fixture.installation); err != nil || guard.Suspected ||
		guard.Generation < time.Now().Add(-time.Hour).UnixMilli() {
		t.Fatalf("the guard after reconcile = %+v, %v", guard, err)
	}
}

// assertCertificateQueue: schema 241 (a3 §14) and control's store. A pod's
// token request supersedes its Device's unfinished requests (R-M2); the
// worker erases a token once it checked it (R-M1); abandoned requests make
// room 30 seconds later (R-M2); control queues, reads back and learns
// whether anyone signs (R-H3).
func assertCertificateQueue(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, store *postgresadapter.KubernetesGatewayCertificateStore,
	worker *signing.Worker, fixture clusterCAFixture, keys replicaKeys, certificate *x509.Certificate,
) {
	t.Helper()
	enqueue := func(ask certificateAsk) map[string]any {
		t.Helper()
		csr, digest := ask.csr(t)
		return enqueueCertificate(ctx, t, runtime, keys, ask, csr, digest)
	}
	older := renewalAsk(t, 80, certificate, []byte("not-a-signature"))
	enqueue(older)
	pod := tokenAsk(t, 81, newCertificateKey(t), "pod-queue")
	if answer := enqueue(pod); answer["outcome"] != "pending" {
		t.Fatalf("a pod's token request: %v", answer)
	}
	deviceID := deviceOfRequest(ctx, t, admin, pod.publicID)
	if answer := readCertificate(ctx, t, runtime, deviceID, older.publicID.String()); answer["outcome"] != "refused" ||
		answer["reason"] != "superseded" {
		t.Fatalf("a request the pod's token request superseded: %v", answer)
	}

	// The first claim carries the token; once checked, its claims replace
	// it in the database and later claims carry those.
	batch, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second)
	if err != nil || len(batch.Claims) != 1 || batch.Claims[0].Token != "pod-queue" || batch.Claims[0].Verified != nil {
		t.Fatalf("claim = %+v, %v", batch, err)
	}
	claim := batch.Claims[0]
	verified := signing.VerifiedToken{Use: signing.TokenUse{JTI: "pod-queue",
		ExpiresAt: batch.Now.Add(10 * time.Minute).Truncate(time.Second), PodName: claim.Trust.PodName},
		TrustVersion: claim.Trust.Version}
	if outcome, err := store.RecordToken(ctx, fixture.installation, claim.ID, claim.ClaimToken, verified); err != nil ||
		outcome != signing.OutcomeRecorded {
		t.Fatalf("RecordToken() = %s, %v", outcome, err)
	}
	var tokenLeft bool
	var jti string
	if err := admin.QueryRow(ctx, `SELECT token IS NOT NULL, token_jti FROM mesh_ops.kubernetes_gateway_certificate_request
WHERE public_id = $1::UUID`, pod.publicID.String()).Scan(&tokenLeft, &jti); err != nil || tokenLeft ||
		jti != "pod-queue" {
		t.Fatalf("after the token was checked: token kept %v, jti %q, %v", tokenLeft, jti, err)
	}
	if outcome, err := store.RecordToken(ctx, fixture.installation, claim.ID, signing.ClaimToken{1}, verified); err != nil ||
		outcome != signing.OutcomeLost {
		t.Fatalf("RecordToken() with another claim's token = %s, %v", outcome, err)
	}
	if _, err := store.Release(ctx, fixture.installation, claim.ID, claim.ClaimToken); err != nil {
		t.Fatal(err)
	}
	batch, err = store.Claim(ctx, fixture.installation, 8, 30*time.Second)
	if err != nil || len(batch.Claims) != 1 || batch.Claims[0].Token != "" || batch.Claims[0].Verified == nil ||
		*batch.Claims[0].Verified != verified {
		t.Fatalf("a claim after the token was checked = %+v, %v", batch, err)
	}
	if _, err := store.Release(ctx, fixture.installation, claim.ID, batch.Claims[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, pod.publicID.String()); answer["outcome"] != "issued" ||
		answer["network_revision"] == nil || answer["device_id"] != deviceID {
		t.Fatalf("a request whose token was checked earlier: %v", answer)
	}

	// A claimed request a pod's new token request superseded is lost to
	// the worker holding it.
	stale := tokenAsk(t, 85, newCertificateKey(t), "pod-stale")
	enqueue(stale)
	held, err := store.Claim(ctx, fixture.installation, 8, 30*time.Second)
	if err != nil || len(held.Claims) != 1 || held.Claims[0].ID != stale.publicID {
		t.Fatalf("claim = %+v, %v", held, err)
	}
	enqueue(tokenAsk(t, 86, newCertificateKey(t), "pod-restarted"))
	if outcome, err := store.RecordToken(ctx, fixture.installation, stale.publicID, held.Claims[0].ClaimToken,
		signing.VerifiedToken{Use: signing.TokenUse{JTI: "pod-stale", ExpiresAt: held.Now.Add(time.Minute).Truncate(time.Second),
			PodName: held.Claims[0].Trust.PodName}, TrustVersion: held.Claims[0].Trust.Version}); err != nil ||
		outcome != signing.OutcomeLost {
		t.Fatalf("RecordToken() on a superseded request = %s, %v", outcome, err)
	}
	worker.Pass(ctx)

	// Abandoned requests hold room for 30 seconds only.
	first, second := renewalAsk(t, 82, certificate, []byte("not-a-signature")),
		renewalAsk(t, 83, certificate, []byte("not-a-signature"))
	enqueue(first)
	enqueue(second)
	third := renewalAsk(t, 84, certificate, []byte("not-a-signature"))
	if answer := enqueue(third); answer["outcome"] != "limited" {
		t.Fatalf("a third request in flight: %v", answer)
	}
	for _, ask := range []certificateAsk{first, second} {
		var abandoned string
		if err := runtime.QueryRow(ctx, `SELECT mesh_ops.abandon_kubernetes_gateway_certificate_v1($1::UUID, $2::UUID)::TEXT`,
			deviceID, ask.publicID.String()).Scan(&abandoned); err != nil {
			t.Fatal(err)
		}
	}
	if answer := enqueue(third); answer["outcome"] != "limited" {
		t.Fatalf("a request while two were just abandoned: %v", answer)
	}
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_certificate_request
SET updated_at = updated_at - INTERVAL '31 seconds' WHERE public_id = ANY($1::UUID[])`,
		[]string{first.publicID.String(), second.publicID.String()}); err != nil {
		t.Fatal(err)
	}
	if answer := enqueue(third); answer["outcome"] != "pending" {
		t.Fatalf("a request once the abandoned ones made room: %v", answer)
	}
	worker.Pass(ctx)
	assertGuardStamp(ctx, t, admin, fixture)

	assertCertificateQueueStore(ctx, t, runtimePool, worker, keys)
}

// assertCertificateQueueStore: control's store queues for the keys the
// session proved, reads the request back as the worker settles it, and
// reads whether a worker signs.
func assertCertificateQueueStore(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	worker *signing.Worker, keys replicaKeys,
) {
	t.Helper()
	queue, err := postgresadapter.NewKubernetesGatewayCertificateQueueStore(runtimePool,
		postgresadapter.RegistrationTransactionOptions{StatementTimeout: 5 * time.Second, LockTimeout: time.Second,
			IdleTimeout: 10 * time.Second, AddressCandidateLimit: 256})
	if err != nil {
		t.Fatal(err)
	}
	if state, err := queue.SigningState(ctx); err != nil || !state.Ready() {
		t.Fatalf("SigningState() = %+v, %v", state, err)
	}
	ask := tokenAsk(t, 90, newCertificateKey(t), "pod-control")
	csr, digest := ask.csr(t)
	request := certqueue.Request{
		ID: ask.publicID, MachineFingerprint: [32]byte(fingerprintOf(keys)), NodeKey: [32]byte(nodeKeyOf(keys)),
		RequestID: ask.id, CSR: csr, PublicKeySHA256: digest, Token: *ask.token,
	}
	stored, err := queue.Enqueue(ctx, request)
	if err != nil || stored.State != certqueue.StatePending || stored.Request != ask.publicID || !stored.Device.IsValid() {
		t.Fatalf("Enqueue() = %+v, %v", stored, err)
	}
	worker.Pass(ctx)
	issued, found, err := queue.Read(ctx, stored.Device, stored.Request)
	if err != nil || !found || issued.State != certqueue.StateIssued || len(issued.Certificate) == 0 ||
		len(issued.Chain) != 1 || len(issued.RootFingerprint) != 32 || len(issued.IssuerFingerprint) != 32 ||
		issued.NetworkRevision < 1 || !issued.RenewAt.Before(issued.NotAfter) {
		t.Fatalf("Read() = %+v, %v, %v", issued, found, err)
	}
	// About a third into its 24 hours (a3 §14 R-H1).
	if life := issued.NotAfter.Sub(issued.RenewAt); life < 14*time.Hour || life > 17*time.Hour+time.Minute {
		t.Fatalf("renews %v before it expires", life)
	}
	if _, found, err := queue.Abandon(ctx, stored.Device, mustPublicID(t)); err != nil || found {
		t.Fatalf("Abandon() of an unknown request = %v, %v", found, err)
	}
	// Keys that are not the gateway's current ones queue nothing.
	request.ID, request.NodeKey = mustPublicID(t), [32]byte{9}
	if refused, err := queue.Enqueue(ctx, request); err != nil || refused.State != certqueue.StateRefused ||
		refused.Reason != "revoked" || refused.Request.IsValid() {
		t.Fatalf("Enqueue() with another node key = %+v, %v", refused, err)
	}
}

// assertGuardStamp: the stamp holds for the guard's generation only, never
// while a restore is suspected; claims sweep leases that ran out even then
// (review a3b SQL M1).
func assertGuardStamp(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture) {
	t.Helper()
	checked := func() time.Time {
		t.Helper()
		var at time.Time
		if err := admin.QueryRow(ctx, `SELECT checked_at FROM mesh_ops.kubernetes_ca_guard`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := checked()
	if err := fixture.store.StampGuard(ctx, fixture.installation, 99); err != nil {
		t.Fatal(err)
	}
	if after := checked(); !after.Equal(before) {
		t.Fatalf("a stamp of another generation moved checked_at from %v to %v", before, after)
	}
	if err := fixture.store.StampGuard(ctx, fixture.installation, 1); err != nil {
		t.Fatal(err)
	}
	if after := checked(); !after.After(before) {
		t.Fatalf("the stamp did not move checked_at: %v", after)
	}
}

// assertMapKubernetesCAs: schema 242 names, for the map's Network, each
// active cluster's active root and signing intermediate by SHA-256 of their
// DER, and withholds them all while a restore is suspected (mtcp-v1 §7.10).
func assertMapKubernetesCAs(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, fixture clusterCAFixture,
	root, intermediate kubeca.StoredCA,
) {
	t.Helper()
	var workspaceID, networkID int64
	if err := admin.QueryRow(ctx, `SELECT network.workspace_id, network.id FROM mesh.network AS network
WHERE network.public_id = $1::UUID`, fixture.scope.NetworkID().String()).Scan(&workspaceID, &networkID); err != nil {
		t.Fatal(err)
	}
	read := func() map[string]any {
		t.Helper()
		tx, err := runtime.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', $1::TEXT, TRUE),
    pg_catalog.set_config('mesh.network_id', $2::TEXT, TRUE)`, strconv.FormatInt(workspaceID, 10),
			strconv.FormatInt(networkID, 10)); err != nil {
			t.Fatal(err)
		}
		var encoded string
		if err := tx.QueryRow(ctx, `SELECT mesh_ops.load_map_network_kubernetes_cas_v1(10)::TEXT`).Scan(
			&encoded); err != nil {
			t.Fatalf("read the map's CAs: %v", err)
		}
		return decodeCertificateAnswer(t, encoded)
	}
	answer := read()
	clusters, _ := answer["clusters"].([]any)
	rootPrint, signingPrint := sha256.Sum256(root.Certificate), sha256.Sum256(intermediate.Certificate)
	found := false
	for _, entry := range clusters {
		cluster, _ := entry.(map[string]any)
		if cluster["root"] == hex.EncodeToString(rootPrint[:]) {
			found = cluster["signing"] == hex.EncodeToString(signingPrint[:])
		}
	}
	if answer["withheld"] != false || !found {
		t.Fatalf("the map's CAs: %v", answer)
	}
}
