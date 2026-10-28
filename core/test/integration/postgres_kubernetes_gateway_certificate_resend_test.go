//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/kubeca/signing"
	"meshtransit.net/shared/mtcp"
)

// assertCertificateResends: a renewal sent again on a new session (a new
// handshake hash and proof, a4 design §2 F3). A request still pending keeps
// the hash and proof it was queued with and is signed by them; an abandoned
// one waits again with the new ones, and a proof for another session is
// refused; a request pruned after 10 minutes is queued afresh; one a pod's
// token request superseded answers so when sent again.
func assertCertificateResends(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	store *postgresadapter.KubernetesGatewayCertificateStore, worker *signing.Worker, fixture clusterCAFixture,
	keys replicaKeys, deviceID string, current certificateAsk, certificate *x509.Certificate,
) {
	t.Helper()
	serial := [16]byte(certificate.SerialNumber.FillBytes(make([]byte, 16)))
	// sent is ask sent on the session of handshake label, signed for it by
	// signer.
	sent := func(ask certificateAsk, csr []byte, label string, signer *ecdsa.PrivateKey) certificateAsk {
		t.Helper()
		handshake := sha256.Sum256([]byte(label))
		proof, err := mtcp.SignKubeCertRenewal(signer, handshake, ask.id, serial, csr)
		if err != nil {
			t.Fatal(err)
		}
		ask.publicID, ask.handshake, ask.proof, ask.serial = mustPublicID(t), handshake[:], proof, serial[:]
		return ask
	}
	stored := func(request string) ([]byte, []byte) {
		t.Helper()
		var handshake, proof []byte
		if err := admin.QueryRow(ctx, `SELECT handshake_hash, renewal_proof
FROM mesh_ops.kubernetes_gateway_certificate_request WHERE public_id = $1::UUID`, request).Scan(&handshake,
			&proof); err != nil {
			t.Fatal(err)
		}
		return handshake, proof
	}
	enqueue := func(ask certificateAsk, csr []byte) map[string]any {
		t.Helper()
		spki, err := x509.MarshalPKIXPublicKey(&ask.key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return enqueueCertificate(ctx, t, runtime, keys, ask, csr, sha256.Sum256(spki))
	}
	newAsk := func(id byte) (certificateAsk, []byte) {
		t.Helper()
		ask := certificateAsk{id: [16]byte{id}, key: newCertificateKey(t)}
		csr, _ := ask.csr(t)
		return ask, csr
	}

	// Pending: the resend joins the request, which keeps its first hash and
	// proof and is signed by them.
	pending, csr := newAsk(100)
	first := sent(pending, csr, "session-a", current.key)
	if answer := enqueue(first, csr); answer["outcome"] != "pending" {
		t.Fatalf("a renewal: %v", answer)
	}
	resent := sent(pending, csr, "session-b", current.key)
	if answer := enqueue(resent, csr); answer["outcome"] != "pending" ||
		answer["request_id"] != first.publicID.String() {
		t.Fatalf("a pending renewal sent again on a new session: %v", answer)
	}
	if handshake, proof := stored(first.publicID.String()); !bytes.Equal(handshake, first.handshake) ||
		!bytes.Equal(proof, first.proof) {
		t.Fatal("a pending request took the new session's hash or proof")
	}
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, first.publicID.String()); answer["outcome"] != "issued" {
		t.Fatalf("a pending renewal sent again: %v", answer)
	}

	// Abandoned: waits again with the new session's hash and proof.
	abandoned, csr := newAsk(101)
	first = sent(abandoned, csr, "session-c", current.key)
	enqueue(first, csr)
	abandon := func(request string) {
		t.Helper()
		var answer string
		if err := runtime.QueryRow(ctx, `SELECT mesh_ops.abandon_kubernetes_gateway_certificate_v1($1::UUID, $2::UUID)::TEXT`,
			deviceID, request).Scan(&answer); err != nil {
			t.Fatal(err)
		}
	}
	abandon(first.publicID.String())
	resent = sent(abandoned, csr, "session-d", current.key)
	if answer := enqueue(resent, csr); answer["outcome"] != "pending" ||
		answer["request_id"] != first.publicID.String() {
		t.Fatalf("an abandoned renewal sent again: %v", answer)
	}
	if handshake, proof := stored(first.publicID.String()); !bytes.Equal(handshake, resent.handshake) ||
		!bytes.Equal(proof, resent.proof) {
		t.Fatal("an abandoned request kept the old session's hash or proof")
	}
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, first.publicID.String()); answer["outcome"] != "issued" {
		t.Fatalf("an abandoned renewal sent again: %v", answer)
	}

	// Abandoned, then sent again with the old session's proof: the worker
	// checks it against the new hash and refuses it.
	replayed, csr := newAsk(102)
	first = sent(replayed, csr, "session-e", current.key)
	enqueue(first, csr)
	abandon(first.publicID.String())
	stale := sent(replayed, csr, "session-f", current.key)
	stale.proof = first.proof
	enqueue(stale, csr)
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, first.publicID.String()); answer["outcome"] != "refused" ||
		answer["reason"] != "proof" {
		t.Fatalf("a proof for another session: %v", answer)
	}

	// Pruned after 10 minutes: the same request id is queued afresh.
	pruned, csr := newAsk(103)
	first = sent(pruned, csr, "session-g", current.key)
	enqueue(first, csr)
	worker.Pass(ctx)
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_certificate_request
SET created_at = created_at - INTERVAL '11 minutes' WHERE public_id = $1::UUID`, first.publicID.String()); err != nil {
		t.Fatal(err)
	}
	if removed, _, err := store.Prune(ctx, fixture.installation, 1000); err != nil || removed < 1 {
		t.Fatalf("Prune() = %d, %v", removed, err)
	}
	resent = sent(pruned, csr, "session-h", current.key)
	if answer := enqueue(resent, csr); answer["outcome"] != "pending" ||
		answer["request_id"] != resent.publicID.String() {
		t.Fatalf("a pruned renewal sent again: %v", answer)
	}
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, resent.publicID.String()); answer["outcome"] != "issued" {
		t.Fatalf("a pruned renewal sent again: %v", answer)
	}

	// Superseded by the pod's token request: answers so when sent again.
	superseded, csr := newAsk(104)
	first = sent(superseded, csr, "session-i", current.key)
	enqueue(first, csr)
	pod := tokenAsk(t, 105, newCertificateKey(t), "pod-resend")
	podCSR, podDigest := pod.csr(t)
	enqueueCertificate(ctx, t, runtime, keys, pod, podCSR, podDigest)
	resent = sent(superseded, csr, "session-j", current.key)
	if answer := enqueue(resent, csr); answer["outcome"] != "refused" || answer["reason"] != "superseded" ||
		answer["request_id"] != first.publicID.String() {
		t.Fatalf("a superseded renewal sent again: %v", answer)
	}
	worker.Pass(ctx)
	if answer := readCertificate(ctx, t, runtime, deviceID, pod.publicID.String()); answer["outcome"] != "issued" {
		t.Fatalf("the pod's token request: %v", answer)
	}
}
