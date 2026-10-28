package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	createKubernetesClusterCASQL = `SELECT mesh_ops.create_kubernetes_cluster_ca_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::UUID,$7::TEXT,$8::UUID,$9::TEXT,$10::TEXT,$11::UUID,$12::BYTEA,
    $13::TEXT,$14::TIMESTAMPTZ,$15::TIMESTAMPTZ,$16::BYTEA,$17::TEXT,$18::TEXT)::TEXT`
	moveKubernetesClusterCASQL = `SELECT mesh_ops.move_kubernetes_cluster_ca_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::BIGINT,$7::TEXT,$8::TEXT,$9::TEXT,$10::TEXT)::TEXT`
	appendKubernetesCAEvidenceSQL = `SELECT mesh_ops.append_kubernetes_ca_evidence_v1(
    $1::TEXT,$2::UUID,$3::BIGINT,$4::BIGINT,$5::BYTEA,$6::BYTEA,$7::UUID,$8::UUID,$9::JSONB,$10::BIGINT)`
	scheduleKubernetesClusterCASQL = `SELECT mesh_ops.schedule_kubernetes_cluster_ca_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::TIMESTAMPTZ,$6::BOOLEAN)::TEXT`

	clusterCAAggregateKind  = "kubernetes_cluster_ca"
	caDataKeyAggregateKind  = "kubernetes_ca_data_key"
	clusterCAMaximumPayload = 4096
)

// clusterCAChange applies changes to one Network in its transaction.
type clusterCAChange struct {
	ctx          context.Context
	transaction  outboxTransaction
	installation deployment.ID
	scope        network.Scope
	operator     kubeca.Operator
}

// validCreation checks a creation is of a known tier and that what it
// stores beside the certificate is what the certificate says (review a2a
// L6): its validity, its tier and the one name it may sign for.
func validCreation(creation *kubeca.Creation) bool {
	tier := creation.Kind == kubeca.KindRoot && !creation.IssuerID.IsValid() &&
		(creation.State == kubeca.StateActive || creation.State == kubeca.StateNext) ||
		creation.Kind == kubeca.KindIntermediate && creation.IssuerID.IsValid() && creation.State == kubeca.StateActive
	if !tier || !creation.Cluster.IsValid() || !creation.ID.IsValid() || !creation.DataKeyID.IsValid() ||
		!creation.Reason.CreatesCA() || len(creation.Certificate) == 0 || len(creation.SealedKey) == 0 ||
		!kubeca.ValidDNSName(creation.ClusterDNSName) {
		return false
	}
	certificate, err := x509.ParseCertificate(creation.Certificate)
	pathLength := 0
	if creation.Kind == kubeca.KindRoot {
		pathLength = 1
	}
	return err == nil && certificate.IsCA && certificate.MaxPathLen == pathLength &&
		len(certificate.PermittedDNSDomains) == 1 && certificate.PermittedDNSDomains[0] == creation.ClusterDNSName &&
		certificate.NotBefore.Equal(creation.NotBefore) && certificate.NotAfter.Equal(creation.NotAfter)
}

func (apply clusterCAChange) step(step kubeca.Step) error {
	if (step.Create == nil) == (step.Move == nil) {
		return ErrInvalidKubernetesClusterCAStore
	}
	change, err := freshPublicID()
	if err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	actor, changeRef := operatorArguments(apply.operator)
	var encoded string
	var ca publicid.ID
	if creation := step.Create; creation != nil {
		if !validCreation(creation) {
			return ErrInvalidKubernetesClusterCAStore
		}
		var issuer any
		if creation.IssuerID.IsValid() {
			issuer = creation.IssuerID.String()
		}
		ca = creation.ID
		err = apply.transaction.QueryRow(apply.ctx, createKubernetesClusterCASQL, apply.installation.String(),
			apply.scope.WorkspaceID().String(), apply.scope.NetworkID().String(), creation.Cluster.String(),
			creation.ID.String(), change.String(), creation.Kind.String(), issuer, string(creation.State),
			string(creation.Reason), creation.DataKeyID.String(), creation.Certificate, creation.ClusterDNSName,
			creation.NotBefore, creation.NotAfter, creation.SealedKey, actor, changeRef).Scan(&encoded)
	} else {
		move := step.Move
		if !move.CA.IsValid() || move.Version < 1 || !move.Reason.MovesCA() ||
			move.To != kubeca.StateActive && move.To != kubeca.StateRetiring && move.To != kubeca.StateRetired {
			return ErrInvalidKubernetesClusterCAStore
		}
		ca = move.CA
		err = apply.transaction.QueryRow(apply.ctx, moveKubernetesClusterCASQL, apply.installation.String(),
			apply.scope.WorkspaceID().String(), apply.scope.NetworkID().String(), move.CA.String(), change.String(),
			move.Version, string(move.To), string(move.Reason), actor, changeRef).Scan(&encoded)
	}
	if err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	proof, err := decodeCAProof(encoded, clusterCAAggregateKind, ca, apply.operator)
	if err != nil {
		return err
	}
	return apply.evidence(proof, change)
}

// evidence appends the sealed audit event of the change the last call
// made.
func (apply clusterCAChange) evidence(proof caProof, change publicid.ID) error {
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
	if err := apply.transaction.QueryRow(apply.ctx, appendKubernetesCAEvidenceSQL, proof.Aggregate, proof.RowID,
		proof.StreamID, proof.Sequence, previous, hash[:], auditEvent.String(), outbox.String(), proof.Payload,
		proof.NetworkRevision).Scan(&sequence); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	if sequence != proof.Sequence {
		return ErrKubernetesClusterCAStore
	}
	return nil
}

func (apply clusterCAChange) schedule(schedule kubeca.Schedule) error {
	if !schedule.Cluster.IsValid() || schedule.Done && (schedule.Failed || !schedule.At.IsZero()) ||
		!schedule.Done && schedule.At.IsZero() {
		return ErrInvalidKubernetesClusterCAStore
	}
	var at any
	if !schedule.Done {
		at = schedule.At
	}
	var encoded string
	if err := apply.transaction.QueryRow(apply.ctx, scheduleKubernetesClusterCASQL, apply.installation.String(),
		apply.scope.WorkspaceID().String(), apply.scope.NetworkID().String(), schedule.Cluster.String(), at,
		schedule.Failed).Scan(&encoded); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	var record struct {
		Outcome      string     `json:"outcome"`
		NextActionAt *time.Time `json:"next_action_at"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil {
		return ErrKubernetesClusterCAStore
	}
	switch {
	case record.Outcome == "busy":
		return ErrKubernetesClusterCABusy
	case schedule.Done && record.Outcome == "done" && record.NextActionAt == nil,
		!schedule.Done && record.Outcome == "scheduled" && record.NextActionAt != nil:
		return nil
	}
	return ErrKubernetesClusterCAStore
}

// caProof is the head of the Network's audit stream and the payload of the
// CA or data key row a change made.
type caProof struct {
	Outcome         string `json:"outcome"`
	Aggregate       string `json:"aggregate"`
	Action          string `json:"action"`
	Permission      string `json:"permission"`
	RowID           string `json:"row_id"`
	Version         int64  `json:"version"`
	NetworkRevision int64  `json:"network_revision"`
	SemanticHash    string `json:"semantic_hash"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	Payload         string `json:"payload"`
}

var caProofActions = map[string][]string{
	clusterCAAggregateKind: {
		"kubernetes_cluster.ca_created", "kubernetes_cluster.ca_activated", "kubernetes_cluster.ca_retiring",
		"kubernetes_cluster.ca_retired",
	},
	caDataKeyAggregateKind: {
		"kubernetes_ca_data_key.created", "kubernetes_ca_data_key.rewrapped", "kubernetes_ca_data_key.retired",
	},
	gatewayCertificateAggregateKind: {"kubernetes_gateway.certificate_issued"},
}

func knownCAAction(aggregate, action string) bool {
	for _, known := range caProofActions[aggregate] {
		if known == action {
			return true
		}
	}
	return false
}

// decodeCAProof checks a proof is for the row asked about, of the kind
// asked about, by whom it was asked.
func decodeCAProof(encoded, aggregate string, row publicid.ID, operator kubeca.Operator) (caProof, error) {
	var proof caProof
	if err := decodeStrictJSON(encoded, 16384, &proof); err != nil {
		return caProof{}, ErrKubernetesClusterCAStore
	}
	switch proof.Outcome {
	case "busy", "stale":
		if proof != (caProof{Outcome: proof.Outcome}) {
			return caProof{}, ErrKubernetesClusterCAStore
		}
		if proof.Outcome == "busy" {
			return caProof{}, ErrKubernetesClusterCABusy
		}
		return caProof{}, ErrKubernetesClusterCAStale
	case "changed":
	default:
		return caProof{}, ErrKubernetesClusterCAStore
	}
	permission := enforcementLedgerPermission
	if !operator.IsWorker() {
		permission = caOperatorPermission
	}
	semantic, semanticErr := hex.DecodeString(proof.SemanticHash)
	previous, previousErr := hex.DecodeString(proof.PreviousHash)
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	if proof.Aggregate != aggregate || !knownCAAction(aggregate, proof.Action) || proof.Permission != permission ||
		proof.RowID != row.String() || proof.Version < 1 || proof.NetworkRevision < 1 || semanticErr != nil ||
		len(semantic) != sha256.Size || previousErr != nil || len(previous) != sha256.Size || proof.StreamID < 1 ||
		proof.Sequence < 1 || len(proof.Payload) == 0 || len(proof.Payload) > clusterCAMaximumPayload ||
		!json.Valid([]byte(proof.Payload)) || [sha256.Size]byte(semantic) != payloadHash {
		return caProof{}, ErrKubernetesClusterCAStore
	}
	return proof, nil
}

// caOperatorPermission marks an operator's change in the audit trail.
const caOperatorPermission = "system.operator"

// hashCAEvent binds the event to the stream head the database returned, as
// for gateway key events: no actor principal or correlation, the payload's
// semantic hash; an operator's name is in the payload.
func hashCAEvent(proof caProof, change, event publicid.ID) ([sha256.Size]byte, []byte, error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return [sha256.Size]byte{}, nil, ErrKubernetesClusterCAStore
	}
	aggregate, err := publicid.Parse(proof.RowID)
	if err != nil {
		return [sha256.Size]byte{}, nil, ErrKubernetesClusterCAStore
	}
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [sha256.Size]byte(previous), EventID: event, ChangeID: change,
		AggregateKind: proof.Aggregate, AggregateID: aggregate, AggregateVersion: proof.Version,
		NetworkRevision: proof.NetworkRevision, Action: proof.Action, Permission: proof.Permission,
		AfterSemanticHash: payloadHash, AuditPayloadHash: payloadHash,
		OutboxEventClass: proof.Action, OutboxPayloadHash: payloadHash,
	})
	if err != nil {
		return [sha256.Size]byte{}, nil, errors.Join(ErrKubernetesClusterCAStore, err)
	}
	return hash, previous, nil
}
