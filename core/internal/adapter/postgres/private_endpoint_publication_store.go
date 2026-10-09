package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing/endpointpublication"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var (
	// ErrInvalidPrivateEndpointPublicationStore reports an unsafe worker dependency or input.
	ErrInvalidPrivateEndpointPublicationStore = errors.New("invalid postgres private endpoint publication store")
	// ErrReadPrivateEndpointPublication classifies authoritative snapshot read failure.
	ErrReadPrivateEndpointPublication = errors.New("read postgres private endpoint publication")
	// ErrConfirmPrivateEndpointPublication classifies atomic readiness publication failure.
	ErrConfirmPrivateEndpointPublication = errors.New("confirm postgres private endpoint publication")
	// ErrStagePrivateEndpointPublication classifies durable route-intent staging failure.
	ErrStagePrivateEndpointPublication = errors.New("stage postgres private endpoint publication")
	// ErrFinalizePrivateEndpointWithdrawal classifies atomic expiry/invalidation failure.
	ErrFinalizePrivateEndpointWithdrawal = errors.New("finalize postgres private endpoint withdrawal")
)

// PrivateEndpointPublicationStore owns worker-only publication functions. It
// has no direct table write capability.
type PrivateEndpointPublicationStore struct {
	database outboxDatabase
}

// StagePublication durably records the exact desired-route hash before the
// first external gateway effect. Replays of the same hash are idempotent.
func (store *PrivateEndpointPublicationStore) StagePublication(
	ctx context.Context,
	snapshot endpointpublication.Snapshot,
	routeHash [sha256.Size]byte,
	reconcilerID string,
) error {
	if ctx == nil || store == nil || store.database == nil || !snapshot.IsValid() ||
		routeHash == ([sha256.Size]byte{}) || !validPublicationReconcilerID(reconcilerID) {
		return ErrInvalidPrivateEndpointPublicationStore
	}
	intentID, err := freshPublicID()
	if err != nil {
		return errors.Join(ErrStagePrivateEndpointPublication, err)
	}
	var storedHash []byte
	if err := store.database.QueryRow(
		ctx, stagePrivateEndpointPublicationSQL,
		snapshot.DeploymentID.String(), snapshot.EndpointID.String(),
		snapshot.EndpointVersion, snapshot.EndpointGeneration,
		intentID.String(), routeHash[:], reconcilerID, snapshot.SnapshotAt,
	).Scan(&storedHash); err != nil || len(storedHash) != sha256.Size ||
		!equalHashBytes(routeHash, storedHash) {
		return errors.Join(ErrStagePrivateEndpointPublication, err)
	}
	return nil
}

// NewPrivateEndpointPublicationStore constructs the adapter from the dedicated worker pool.
func NewPrivateEndpointPublicationStore(pool *Pool) (*PrivateEndpointPublicationStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidPrivateEndpointPublicationStore
	}
	return &PrivateEndpointPublicationStore{database: pool.outboxDatabase}, nil
}

// ListPublicationCandidates reads bounded hints; exact authority is reread separately.
func (store *PrivateEndpointPublicationStore) ListPublicationCandidates(
	ctx context.Context,
	deploymentID deployment.ID,
	limit int,
) ([]endpointpublication.Candidate, error) {
	return store.listCandidates(ctx, deploymentID, limit, listPrivateEndpointPublicationsSQL)
}

// ListWithdrawalCandidates reads bounded expiry/invalidation hints.
func (store *PrivateEndpointPublicationStore) ListWithdrawalCandidates(
	ctx context.Context,
	deploymentID deployment.ID,
	limit int,
) ([]endpointpublication.Candidate, error) {
	return store.listCandidates(ctx, deploymentID, limit, listPrivateEndpointWithdrawalsSQL)
}

func (store *PrivateEndpointPublicationStore) listCandidates(
	ctx context.Context,
	deploymentID deployment.ID,
	limit int,
	query string,
) ([]endpointpublication.Candidate, error) {
	if ctx == nil || store == nil || store.database == nil || !deploymentID.IsValid() ||
		limit < 1 || limit > 128 {
		return nil, ErrInvalidPrivateEndpointPublicationStore
	}
	var encoded []byte
	if err := store.database.QueryRow(ctx, query, deploymentID.String(), limit).Scan(&encoded); err != nil {
		return nil, errors.Join(ErrReadPrivateEndpointPublication, err)
	}
	var records []candidateRecord
	if err := json.Unmarshal(encoded, &records); err != nil || len(records) > limit {
		return nil, ErrReadPrivateEndpointPublication
	}
	result := make([]endpointpublication.Candidate, len(records))
	for index, record := range records {
		id, err := sharing.ParsePrivateEndpointID(record.EndpointID)
		candidate := endpointpublication.Candidate{EndpointID: id, Generation: record.EndpointGeneration}
		if err != nil || !candidate.IsValid() {
			return nil, ErrReadPrivateEndpointPublication
		}
		result[index] = candidate
	}
	return result, nil
}

// ReadPublicationSnapshot reads the exact gateway and optimistic concurrency vector.
func (store *PrivateEndpointPublicationStore) ReadPublicationSnapshot(
	ctx context.Context,
	deploymentID deployment.ID,
	endpointID sharing.PrivateEndpointID,
) (endpointpublication.Snapshot, error) {
	if ctx == nil || store == nil || store.database == nil || !deploymentID.IsValid() || !endpointID.IsValid() {
		return endpointpublication.Snapshot{}, ErrInvalidPrivateEndpointPublicationStore
	}
	var encoded []byte
	if err := store.database.QueryRow(
		ctx, readPrivateEndpointPublicationSQL, deploymentID.String(), endpointID.String(),
	).Scan(&encoded); err != nil {
		return endpointpublication.Snapshot{}, errors.Join(ErrReadPrivateEndpointPublication, err)
	}
	snapshot, err := decodePublicationSnapshot(encoded)
	if err != nil || snapshot.DeploymentID != deploymentID || snapshot.EndpointID != endpointID {
		return endpointpublication.Snapshot{}, ErrReadPrivateEndpointPublication
	}
	return snapshot, nil
}

// ReadWithdrawalSnapshot reads exact DB-selected terminal authority.
func (store *PrivateEndpointPublicationStore) ReadWithdrawalSnapshot(
	ctx context.Context,
	deploymentID deployment.ID,
	endpointID sharing.PrivateEndpointID,
) (endpointpublication.WithdrawalSnapshot, error) {
	if ctx == nil || store == nil || store.database == nil || !deploymentID.IsValid() || !endpointID.IsValid() {
		return endpointpublication.WithdrawalSnapshot{}, ErrInvalidPrivateEndpointPublicationStore
	}
	var encoded []byte
	if err := store.database.QueryRow(
		ctx, readPrivateEndpointWithdrawalSQL, deploymentID.String(), endpointID.String(),
	).Scan(&encoded); err != nil {
		return endpointpublication.WithdrawalSnapshot{}, errors.Join(ErrReadPrivateEndpointPublication, err)
	}
	snapshot, err := decodeWithdrawalSnapshot(encoded)
	if err != nil || snapshot.DeploymentID != deploymentID || snapshot.EndpointID != endpointID {
		return endpointpublication.WithdrawalSnapshot{}, ErrReadPrivateEndpointPublication
	}
	return snapshot, nil
}

// ConfirmPublication atomically records route readiness, DNS and both evidence streams.
func (store *PrivateEndpointPublicationStore) ConfirmPublication(
	ctx context.Context,
	snapshot endpointpublication.Snapshot,
	routeHash [sha256.Size]byte,
	reconcilerID string,
) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !snapshot.IsValid() ||
		routeHash == ([sha256.Size]byte{}) || !validPublicationReconcilerID(reconcilerID) {
		return ErrInvalidPrivateEndpointPublicationStore
	}
	evidence, err := buildPublicationEvidence(snapshot, routeHash, reconcilerID)
	if err != nil {
		return ErrConfirmPrivateEndpointPublication
	}
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return errors.Join(ErrConfirmPrivateEndpointPublication, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()

	var result publicationResult
	err = transaction.QueryRow(ctx, confirmPrivateEndpointPublicationSQL,
		snapshot.DeploymentID.String(), snapshot.EndpointID.String(), snapshot.EndpointVersion,
		snapshot.EndpointGeneration, snapshot.AliasLeaseVersion, snapshot.ContractVersion,
		snapshot.ImportedResourceVersion, snapshot.ProviderNetworkRevision,
		snapshot.ProviderDNSRevision, snapshot.ProviderRouteRevision, snapshot.ProviderSharingRevision,
		snapshot.ConsumerNetworkRevision, snapshot.ConsumerDNSRevision,
		snapshot.ConsumerRouteRevision, snapshot.ConsumerSharingRevision,
		evidence.changeID.String(), evidence.readinessID.String(), evidence.dnsPublicationID.String(),
		routeHash[:], reconcilerID, snapshot.SnapshotAt,
		snapshot.ProviderStreamID, evidence.provider.eventID.String(), evidence.provider.outboxID.String(),
		snapshot.ProviderStreamSequence, snapshot.ProviderStreamHash[:], evidence.provider.eventHash[:],
		evidence.provider.auditPayload, evidence.provider.outboxPayload,
		snapshot.ConsumerStreamID, evidence.consumer.eventID.String(), evidence.consumer.outboxID.String(),
		snapshot.ConsumerStreamSequence, snapshot.ConsumerStreamHash[:], evidence.consumer.eventHash[:],
		evidence.consumer.auditPayload, evidence.consumer.outboxPayload,
	).Scan(
		&result.providerNetwork, &result.providerDNS, &result.providerRoute, &result.providerSharing,
		&result.consumerNetwork, &result.consumerDNS, &result.consumerRoute, &result.consumerSharing,
		&result.aliasVersion, &result.endpointVersion, &result.readinessVersion, &result.dnsVersion,
	)
	if err != nil || !result.matchesPublication(snapshot) {
		return errors.Join(ErrConfirmPrivateEndpointPublication, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrConfirmPrivateEndpointPublication, err)
	}
	committed = true
	return nil
}

// FinalizeWithdrawal atomically terminalizes authority and removes DNS publication.
func (store *PrivateEndpointPublicationStore) FinalizeWithdrawal(
	ctx context.Context,
	snapshot endpointpublication.WithdrawalSnapshot,
	terminalHash [sha256.Size]byte,
	reconcilerID string,
) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !snapshot.IsValid() ||
		terminalHash == ([sha256.Size]byte{}) || !validPublicationReconcilerID(reconcilerID) {
		return ErrInvalidPrivateEndpointPublicationStore
	}
	evidence, err := buildWithdrawalEvidence(snapshot, terminalHash, reconcilerID)
	if err != nil {
		return ErrFinalizePrivateEndpointWithdrawal
	}
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return errors.Join(ErrFinalizePrivateEndpointWithdrawal, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()

	var result withdrawalResult
	err = transaction.QueryRow(ctx, finalizePrivateEndpointWithdrawalSQL,
		snapshot.DeploymentID.String(), snapshot.EndpointID.String(), snapshot.EndpointVersion,
		snapshot.EndpointGeneration, snapshot.AliasLeaseVersion, snapshot.ContractVersion,
		snapshot.ImportedResourceVersion, snapshot.AccessNameVersion, snapshot.DNSPublicationVersion,
		snapshot.ProviderNetworkRevision, snapshot.ProviderDNSRevision, snapshot.ProviderRouteRevision,
		snapshot.ProviderSharingRevision, snapshot.ConsumerNetworkRevision, snapshot.ConsumerDNSRevision,
		snapshot.ConsumerRouteRevision, snapshot.ConsumerSharingRevision,
		evidence.changeID.String(), snapshot.RouteSnapshotHash[:], terminalHash[:], reconcilerID,
		string(snapshot.Reason), snapshot.ProviderStreamID, evidence.provider.eventID.String(),
		evidence.provider.outboxID.String(), snapshot.ProviderStreamSequence,
		snapshot.ProviderStreamHash[:], evidence.provider.eventHash[:],
		evidence.provider.auditPayload, evidence.provider.outboxPayload,
		snapshot.ConsumerStreamID, evidence.consumer.eventID.String(), evidence.consumer.outboxID.String(),
		snapshot.ConsumerStreamSequence, snapshot.ConsumerStreamHash[:], evidence.consumer.eventHash[:],
		evidence.consumer.auditPayload, evidence.consumer.outboxPayload,
	).Scan(
		&result.providerNetwork, &result.providerDNS, &result.providerRoute, &result.providerSharing,
		&result.consumerNetwork, &result.consumerDNS, &result.consumerRoute, &result.consumerSharing,
		&result.contractVersion, &result.importedVersion, &result.accessNameVersion,
		&result.aliasVersion, &result.endpointVersion, &result.dnsVersion,
	)
	if err != nil || !result.matchesWithdrawal(snapshot) {
		return errors.Join(ErrFinalizePrivateEndpointWithdrawal, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrFinalizePrivateEndpointWithdrawal, err)
	}
	committed = true
	return nil
}

type candidateRecord struct {
	EndpointID         string `json:"endpoint_public_id"`
	EndpointGeneration int64  `json:"endpoint_generation"`
}

type publicationSnapshotRecord struct {
	DeploymentID, EndpointID, TargetDeviceID                   string
	ProviderWorkspaceID, ProviderNetworkID                     string
	ConsumerWorkspaceID, ConsumerNetworkID                     string
	ResourceAlias, AccessName, ConstraintHash                  string
	EndpointVersion, EndpointGeneration, AliasLeaseVersion     int64
	ContractVersion, ImportedResourceVersion, TargetGeneration int64
	TargetAddresses                                            []string
	Traffic                                                    []endpointpublication.TrafficConstraint
	ExpiresAt, SnapshotAt                                      time.Time
	ProviderNetworkRevision, ProviderDNSRevision               int64
	ProviderRouteRevision, ProviderSharingRevision             int64
	ConsumerNetworkRevision, ConsumerDNSRevision               int64
	ConsumerRouteRevision, ConsumerSharingRevision             int64
	ProviderStreamID, ProviderStreamSequence                   int64
	ProviderStreamHash                                         string
	ConsumerStreamID, ConsumerStreamSequence                   int64
	ConsumerStreamHash                                         string
}

func (record *publicationSnapshotRecord) UnmarshalJSON(encoded []byte) error {
	type wire struct {
		DeploymentID            string                                  `json:"deployment_public_id"`
		EndpointID              string                                  `json:"endpoint_public_id"`
		EndpointVersion         int64                                   `json:"endpoint_version"`
		EndpointGeneration      int64                                   `json:"endpoint_generation"`
		AliasLeaseVersion       int64                                   `json:"alias_lease_version"`
		ContractVersion         int64                                   `json:"contract_version"`
		ImportedResourceVersion int64                                   `json:"imported_resource_version"`
		TargetDeviceID          string                                  `json:"target_device_id"`
		TargetGeneration        int64                                   `json:"target_generation"`
		TargetAddresses         []string                                `json:"target_addresses"`
		ResourceAlias           string                                  `json:"resource_alias"`
		AccessName              string                                  `json:"access_name"`
		ConstraintHash          string                                  `json:"constraint_hash"`
		ExpiresAt               time.Time                               `json:"expires_at"`
		SnapshotAt              time.Time                               `json:"snapshot_at"`
		ProviderWorkspaceID     string                                  `json:"provider_workspace_public_id"`
		ProviderNetworkID       string                                  `json:"provider_network_public_id"`
		ConsumerWorkspaceID     string                                  `json:"consumer_workspace_public_id"`
		ConsumerNetworkID       string                                  `json:"consumer_network_public_id"`
		Traffic                 []endpointpublication.TrafficConstraint `json:"traffic"`
		ProviderNetworkRevision int64                                   `json:"provider_network_revision"`
		ProviderDNSRevision     int64                                   `json:"provider_dns_revision"`
		ProviderRouteRevision   int64                                   `json:"provider_route_revision"`
		ProviderSharingRevision int64                                   `json:"provider_sharing_revision"`
		ConsumerNetworkRevision int64                                   `json:"consumer_network_revision"`
		ConsumerDNSRevision     int64                                   `json:"consumer_dns_revision"`
		ConsumerRouteRevision   int64                                   `json:"consumer_route_revision"`
		ConsumerSharingRevision int64                                   `json:"consumer_sharing_revision"`
		ProviderStreamID        int64                                   `json:"provider_stream_id"`
		ProviderStreamSequence  int64                                   `json:"provider_stream_sequence"`
		ProviderStreamHash      string                                  `json:"provider_stream_hash"`
		ConsumerStreamID        int64                                   `json:"consumer_stream_id"`
		ConsumerStreamSequence  int64                                   `json:"consumer_stream_sequence"`
		ConsumerStreamHash      string                                  `json:"consumer_stream_hash"`
	}
	var value wire
	if err := json.Unmarshal(encoded, &value); err != nil {
		return err
	}
	*record = publicationSnapshotRecord{
		DeploymentID: value.DeploymentID, EndpointID: value.EndpointID, TargetDeviceID: value.TargetDeviceID,
		ProviderWorkspaceID: value.ProviderWorkspaceID, ProviderNetworkID: value.ProviderNetworkID,
		ConsumerWorkspaceID: value.ConsumerWorkspaceID, ConsumerNetworkID: value.ConsumerNetworkID,
		ResourceAlias: value.ResourceAlias, AccessName: value.AccessName, ConstraintHash: value.ConstraintHash,
		EndpointVersion: value.EndpointVersion, EndpointGeneration: value.EndpointGeneration,
		AliasLeaseVersion: value.AliasLeaseVersion, ContractVersion: value.ContractVersion,
		ImportedResourceVersion: value.ImportedResourceVersion, TargetGeneration: value.TargetGeneration,
		TargetAddresses: value.TargetAddresses, Traffic: value.Traffic,
		ExpiresAt: value.ExpiresAt.UTC(), SnapshotAt: value.SnapshotAt.UTC(),
		ProviderNetworkRevision: value.ProviderNetworkRevision, ProviderDNSRevision: value.ProviderDNSRevision,
		ProviderRouteRevision: value.ProviderRouteRevision, ProviderSharingRevision: value.ProviderSharingRevision,
		ConsumerNetworkRevision: value.ConsumerNetworkRevision, ConsumerDNSRevision: value.ConsumerDNSRevision,
		ConsumerRouteRevision: value.ConsumerRouteRevision, ConsumerSharingRevision: value.ConsumerSharingRevision,
		ProviderStreamID: value.ProviderStreamID, ProviderStreamSequence: value.ProviderStreamSequence,
		ProviderStreamHash: value.ProviderStreamHash, ConsumerStreamID: value.ConsumerStreamID,
		ConsumerStreamSequence: value.ConsumerStreamSequence, ConsumerStreamHash: value.ConsumerStreamHash,
	}
	return nil
}

func decodePublicationSnapshot(encoded []byte) (endpointpublication.Snapshot, error) {
	var record publicationSnapshotRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return endpointpublication.Snapshot{}, err
	}
	deploymentID, e1 := deployment.ParseID(record.DeploymentID)
	endpointID, e2 := sharing.ParsePrivateEndpointID(record.EndpointID)
	providerWorkspace, e3 := workspace.ParseID(record.ProviderWorkspaceID)
	providerNetwork, e4 := network.ParseID(record.ProviderNetworkID)
	consumerWorkspace, e5 := workspace.ParseID(record.ConsumerWorkspaceID)
	consumerNetwork, e6 := network.ParseID(record.ConsumerNetworkID)
	targetDevice, e7 := publicid.Parse(record.TargetDeviceID)
	alias, e8 := netip.ParseAddr(record.ResourceAlias)
	accessName, e9 := sharing.ParseAccessName(record.AccessName)
	constraintHash, e10 := decodePublicationHash(record.ConstraintHash)
	providerHash, e11 := decodePublicationHash(record.ProviderStreamHash)
	consumerHash, e12 := decodePublicationHash(record.ConsumerStreamHash)
	addresses := make([]netip.Addr, len(record.TargetAddresses))
	var addressErr error
	for index, raw := range record.TargetAddresses {
		addresses[index], addressErr = netip.ParseAddr(raw)
		if addressErr != nil || addresses[index].String() != raw {
			break
		}
	}
	if errors.Join(e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, addressErr) != nil {
		return endpointpublication.Snapshot{}, endpointpublication.ErrInvalidSnapshot
	}
	snapshot := endpointpublication.Snapshot{
		DeploymentID: deploymentID, EndpointID: endpointID, EndpointVersion: record.EndpointVersion,
		EndpointGeneration: record.EndpointGeneration, AliasLeaseVersion: record.AliasLeaseVersion,
		ContractVersion: record.ContractVersion, ImportedResourceVersion: record.ImportedResourceVersion,
		ProviderScope:  endpointpublication.Scope{WorkspaceID: providerWorkspace, NetworkID: providerNetwork},
		ConsumerScope:  endpointpublication.Scope{WorkspaceID: consumerWorkspace, NetworkID: consumerNetwork},
		TargetDeviceID: targetDevice, TargetGeneration: record.TargetGeneration, TargetAddresses: addresses,
		ResourceAlias: alias, AccessName: accessName, Traffic: record.Traffic, ConstraintHash: constraintHash,
		ExpiresAt: record.ExpiresAt, SnapshotAt: record.SnapshotAt,
		ProviderNetworkRevision: record.ProviderNetworkRevision, ProviderDNSRevision: record.ProviderDNSRevision,
		ProviderRouteRevision: record.ProviderRouteRevision, ProviderSharingRevision: record.ProviderSharingRevision,
		ConsumerNetworkRevision: record.ConsumerNetworkRevision, ConsumerDNSRevision: record.ConsumerDNSRevision,
		ConsumerRouteRevision: record.ConsumerRouteRevision, ConsumerSharingRevision: record.ConsumerSharingRevision,
		ProviderStreamID: record.ProviderStreamID, ProviderStreamSequence: record.ProviderStreamSequence,
		ProviderStreamHash: providerHash, ConsumerStreamID: record.ConsumerStreamID,
		ConsumerStreamSequence: record.ConsumerStreamSequence, ConsumerStreamHash: consumerHash,
	}
	if !snapshot.IsValid() {
		return endpointpublication.Snapshot{}, endpointpublication.ErrInvalidSnapshot
	}
	return snapshot, nil
}

type withdrawalSnapshotRecord struct {
	DeploymentID            string                               `json:"deployment_public_id"`
	EndpointID              string                               `json:"endpoint_public_id"`
	EndpointVersion         int64                                `json:"endpoint_version"`
	EndpointGeneration      int64                                `json:"endpoint_generation"`
	AliasLeaseVersion       int64                                `json:"alias_lease_version"`
	ContractVersion         int64                                `json:"contract_version"`
	ImportedResourceVersion int64                                `json:"imported_resource_version"`
	AccessNameVersion       int64                                `json:"access_name_version"`
	DNSPublicationVersion   int64                                `json:"dns_publication_version"`
	ResourceAlias           string                               `json:"resource_alias"`
	RouteSnapshotHash       string                               `json:"route_snapshot_hash"`
	RoutePresent            bool                                 `json:"route_present"`
	Reason                  endpointpublication.WithdrawalReason `json:"reason"`
	SnapshotAt              time.Time                            `json:"snapshot_at"`
	ProviderNetworkRevision int64                                `json:"provider_network_revision"`
	ProviderDNSRevision     int64                                `json:"provider_dns_revision"`
	ProviderRouteRevision   int64                                `json:"provider_route_revision"`
	ProviderSharingRevision int64                                `json:"provider_sharing_revision"`
	ConsumerNetworkRevision int64                                `json:"consumer_network_revision"`
	ConsumerDNSRevision     int64                                `json:"consumer_dns_revision"`
	ConsumerRouteRevision   int64                                `json:"consumer_route_revision"`
	ConsumerSharingRevision int64                                `json:"consumer_sharing_revision"`
	ProviderStreamID        int64                                `json:"provider_stream_id"`
	ProviderStreamSequence  int64                                `json:"provider_stream_sequence"`
	ProviderStreamHash      string                               `json:"provider_stream_hash"`
	ConsumerStreamID        int64                                `json:"consumer_stream_id"`
	ConsumerStreamSequence  int64                                `json:"consumer_stream_sequence"`
	ConsumerStreamHash      string                               `json:"consumer_stream_hash"`
}

func decodeWithdrawalSnapshot(encoded []byte) (endpointpublication.WithdrawalSnapshot, error) {
	var record withdrawalSnapshotRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return endpointpublication.WithdrawalSnapshot{}, err
	}
	deploymentID, e1 := deployment.ParseID(record.DeploymentID)
	endpointID, e2 := sharing.ParsePrivateEndpointID(record.EndpointID)
	alias, e3 := netip.ParseAddr(record.ResourceAlias)
	routeHash, e4 := decodePublicationHash(record.RouteSnapshotHash)
	providerHash, e5 := decodePublicationHash(record.ProviderStreamHash)
	consumerHash, e6 := decodePublicationHash(record.ConsumerStreamHash)
	if errors.Join(e1, e2, e3, e4, e5, e6) != nil {
		return endpointpublication.WithdrawalSnapshot{}, endpointpublication.ErrInvalidSnapshot
	}
	snapshot := endpointpublication.WithdrawalSnapshot{
		DeploymentID: deploymentID, EndpointID: endpointID, EndpointVersion: record.EndpointVersion,
		EndpointGeneration: record.EndpointGeneration, AliasLeaseVersion: record.AliasLeaseVersion,
		ContractVersion: record.ContractVersion, ImportedResourceVersion: record.ImportedResourceVersion,
		AccessNameVersion: record.AccessNameVersion, DNSPublicationVersion: record.DNSPublicationVersion,
		ResourceAlias: alias, RouteSnapshotHash: routeHash, RoutePresent: record.RoutePresent,
		Reason: record.Reason, SnapshotAt: record.SnapshotAt.UTC(),
		ProviderNetworkRevision: record.ProviderNetworkRevision, ProviderDNSRevision: record.ProviderDNSRevision,
		ProviderRouteRevision: record.ProviderRouteRevision, ProviderSharingRevision: record.ProviderSharingRevision,
		ConsumerNetworkRevision: record.ConsumerNetworkRevision, ConsumerDNSRevision: record.ConsumerDNSRevision,
		ConsumerRouteRevision: record.ConsumerRouteRevision, ConsumerSharingRevision: record.ConsumerSharingRevision,
		ProviderStreamID: record.ProviderStreamID, ProviderStreamSequence: record.ProviderStreamSequence,
		ProviderStreamHash: providerHash, ConsumerStreamID: record.ConsumerStreamID,
		ConsumerStreamSequence: record.ConsumerStreamSequence, ConsumerStreamHash: consumerHash,
	}
	if !snapshot.IsValid() {
		return endpointpublication.WithdrawalSnapshot{}, endpointpublication.ErrInvalidSnapshot
	}
	return snapshot, nil
}

func decodePublicationHash(value string) ([sha256.Size]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return [sha256.Size]byte{}, endpointpublication.ErrInvalidSnapshot
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result, nil
}

func equalHashBytes(expected [sha256.Size]byte, actual []byte) bool {
	if len(actual) != sha256.Size {
		return false
	}
	var value [sha256.Size]byte
	copy(value[:], actual)
	return value == expected
}

func validPublicationReconcilerID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' ||
			character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}

type evidenceIDs struct {
	changeID, readinessID, dnsPublicationID publicid.ID
	provider, consumer                      streamEvidence
}
type streamEvidence struct {
	eventID, outboxID           publicid.ID
	eventHash                   [sha256.Size]byte
	auditPayload, outboxPayload []byte
}

func freshPublicID() (publicid.ID, error) { return publicid.New() }

func buildPublicationEvidence(snapshot endpointpublication.Snapshot, routeHash [sha256.Size]byte, reconcilerID string) (evidenceIDs, error) {
	ids, err := newEvidenceIDs(true)
	if err != nil {
		return evidenceIDs{}, err
	}
	provider := publicationAuditPayload(snapshot, ids, routeHash, reconcilerID, "provider")
	consumer := publicationAuditPayload(snapshot, ids, routeHash, reconcilerID, "consumer")
	ids.provider, err = buildStreamEvidence(snapshot, ids.changeID, ids.provider, routeHash, [32]byte{}, provider, "private_endpoint.published", "sharing.private_endpoint.published", true)
	if err != nil {
		return evidenceIDs{}, err
	}
	ids.consumer, err = buildStreamEvidence(snapshot, ids.changeID, ids.consumer, routeHash, [32]byte{}, consumer, "private_endpoint.published", "sharing.private_endpoint.published", false)
	return ids, err
}

func buildWithdrawalEvidence(snapshot endpointpublication.WithdrawalSnapshot, terminalHash [sha256.Size]byte, reconcilerID string) (evidenceIDs, error) {
	ids, err := newEvidenceIDs(false)
	if err != nil {
		return evidenceIDs{}, err
	}
	provider := withdrawalAuditPayload(snapshot, terminalHash, reconcilerID, "provider")
	consumer := withdrawalAuditPayload(snapshot, terminalHash, reconcilerID, "consumer")
	action := "private_endpoint." + string(snapshot.Reason)
	ids.provider, err = buildWithdrawalStreamEvidence(snapshot, ids.changeID, ids.provider, terminalHash, provider, action, true)
	if err != nil {
		return evidenceIDs{}, err
	}
	ids.consumer, err = buildWithdrawalStreamEvidence(snapshot, ids.changeID, ids.consumer, terminalHash, consumer, action, false)
	return ids, err
}

func newEvidenceIDs(publication bool) (evidenceIDs, error) {
	count := 5
	if publication {
		count = 7
	}
	values := make([]publicid.ID, count)
	for index := range values {
		id, err := freshPublicID()
		if err != nil {
			return evidenceIDs{}, err
		}
		values[index] = id
	}
	ids := evidenceIDs{changeID: values[0]}
	offset := 1
	if publication {
		ids.readinessID, ids.dnsPublicationID, offset = values[1], values[2], 3
	}
	ids.provider.eventID, ids.provider.outboxID = values[offset], values[offset+1]
	ids.consumer.eventID, ids.consumer.outboxID = values[offset+2], values[offset+3]
	return ids, nil
}

type endpointAuditPayload struct {
	EndpointID         string `json:"endpoint_public_id"`
	ReadinessID        string `json:"readiness_public_id,omitempty"`
	DNSPublicationID   string `json:"dns_publication_public_id,omitempty"`
	AuthoritySide      string `json:"authority_side"`
	ReconcilerID       string `json:"reconciler_id"`
	EndpointGeneration int64  `json:"endpoint_generation"`
	ResourceAlias      string `json:"resource_alias"`
	Reason             string `json:"reason,omitempty"`
	RouteSnapshotHash  string `json:"route_snapshot_hash"`
	TerminalHash       string `json:"terminal_hash,omitempty"`
	NetworkRevision    int64  `json:"network_revision"`
	DNSRevision        int64  `json:"dns_revision"`
	RouteRevision      int64  `json:"route_revision"`
	SharingRevision    int64  `json:"sharing_revision"`
}
type endpointOutboxPayload struct {
	EndpointID      string `json:"endpoint_public_id"`
	Reason          string `json:"reason,omitempty"`
	NetworkRevision int64  `json:"network_revision"`
	DNSRevision     int64  `json:"dns_revision"`
	RouteRevision   int64  `json:"route_revision"`
	Subsystem       string `json:"subsystem"`
	SharingRevision int64  `json:"subsystem_revision"`
}

func publicationAuditPayload(snapshot endpointpublication.Snapshot, ids evidenceIDs, hash [32]byte, reconcilerID, side string) endpointAuditPayload {
	payload := endpointAuditPayload{EndpointID: snapshot.EndpointID.String(), ReadinessID: ids.readinessID.String(), DNSPublicationID: ids.dnsPublicationID.String(), AuthoritySide: side, ReconcilerID: reconcilerID, EndpointGeneration: snapshot.EndpointGeneration, ResourceAlias: postgresAddressText(snapshot.ResourceAlias), RouteSnapshotHash: hex.EncodeToString(hash[:])}
	if side == "provider" {
		payload.NetworkRevision = snapshot.ProviderNetworkRevision + 1
		payload.DNSRevision = snapshot.ProviderDNSRevision
		payload.RouteRevision = snapshot.ProviderRouteRevision + 1
		payload.SharingRevision = snapshot.ProviderSharingRevision + 1
	} else {
		payload.NetworkRevision = snapshot.ConsumerNetworkRevision + 1
		payload.DNSRevision = snapshot.ConsumerDNSRevision + 1
		payload.RouteRevision = snapshot.ConsumerRouteRevision + 1
		payload.SharingRevision = snapshot.ConsumerSharingRevision + 1
	}
	return payload
}

func withdrawalAuditPayload(snapshot endpointpublication.WithdrawalSnapshot, terminalHash [32]byte, reconcilerID, side string) endpointAuditPayload {
	payload := endpointAuditPayload{EndpointID: snapshot.EndpointID.String(), AuthoritySide: side, ReconcilerID: reconcilerID, EndpointGeneration: snapshot.EndpointGeneration, ResourceAlias: postgresAddressText(snapshot.ResourceAlias), Reason: string(snapshot.Reason), RouteSnapshotHash: hex.EncodeToString(snapshot.RouteSnapshotHash[:]), TerminalHash: hex.EncodeToString(terminalHash[:])}
	if side == "provider" {
		payload.NetworkRevision = snapshot.ProviderNetworkRevision + 1
		payload.DNSRevision = snapshot.ProviderDNSRevision
		payload.RouteRevision = snapshot.ProviderRouteRevision + 1
		payload.SharingRevision = snapshot.ProviderSharingRevision + 1
	} else {
		payload.NetworkRevision = snapshot.ConsumerNetworkRevision + 1
		payload.DNSRevision = snapshot.ConsumerDNSRevision + 1
		payload.RouteRevision = snapshot.ConsumerRouteRevision + 1
		payload.SharingRevision = snapshot.ConsumerSharingRevision + 1
	}
	return payload
}

func postgresAddressText(address netip.Addr) string {
	if address.Is4() {
		return address.String() + "/32"
	}
	return address.String() + "/128"
}

func buildStreamEvidence(snapshot endpointpublication.Snapshot, changeID publicid.ID, evidence streamEvidence, afterHash, beforeHash [32]byte, payload endpointAuditPayload, action, eventClass string, provider bool) (streamEvidence, error) {
	auditJSON, err := json.Marshal(payload)
	if err != nil {
		return streamEvidence{}, err
	}
	outbox := endpointOutboxPayload{EndpointID: payload.EndpointID, NetworkRevision: payload.NetworkRevision, DNSRevision: payload.DNSRevision, RouteRevision: payload.RouteRevision, Subsystem: "sharing", SharingRevision: payload.SharingRevision}
	outboxJSON, err := json.Marshal(outbox)
	if err != nil {
		return streamEvidence{}, err
	}
	previous := snapshot.ConsumerStreamHash
	if provider {
		previous = snapshot.ProviderStreamHash
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{PreviousHash: previous, EventID: evidence.eventID, ChangeID: changeID, AggregateKind: "private_endpoint", AggregateID: publicid.ID(snapshot.EndpointID), AggregateVersion: snapshot.EndpointVersion + 1, NetworkRevision: payload.NetworkRevision, Action: action, Permission: "system.reconcile", CorrelationID: publicid.ID(snapshot.EndpointID), BeforeSemanticHash: beforeHash, AfterSemanticHash: afterHash, AuditPayloadHash: sha256.Sum256(auditJSON), OutboxEventClass: eventClass, OutboxPayloadHash: sha256.Sum256(outboxJSON)})
	if err != nil {
		return streamEvidence{}, err
	}
	evidence.eventHash, evidence.auditPayload, evidence.outboxPayload = eventHash, auditJSON, outboxJSON
	return evidence, nil
}

func buildWithdrawalStreamEvidence(snapshot endpointpublication.WithdrawalSnapshot, changeID publicid.ID, evidence streamEvidence, terminalHash [32]byte, payload endpointAuditPayload, action string, provider bool) (streamEvidence, error) {
	auditJSON, err := json.Marshal(payload)
	if err != nil {
		return streamEvidence{}, err
	}
	outbox := endpointOutboxPayload{EndpointID: payload.EndpointID, Reason: payload.Reason, NetworkRevision: payload.NetworkRevision, DNSRevision: payload.DNSRevision, RouteRevision: payload.RouteRevision, Subsystem: "sharing", SharingRevision: payload.SharingRevision}
	outboxJSON, err := json.Marshal(outbox)
	if err != nil {
		return streamEvidence{}, err
	}
	previous := snapshot.ConsumerStreamHash
	if provider {
		previous = snapshot.ProviderStreamHash
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{PreviousHash: previous, EventID: evidence.eventID, ChangeID: changeID, AggregateKind: "private_endpoint", AggregateID: publicid.ID(snapshot.EndpointID), AggregateVersion: snapshot.EndpointVersion + 1, NetworkRevision: payload.NetworkRevision, Action: action, Permission: "system.reconcile", CorrelationID: publicid.ID(snapshot.EndpointID), BeforeSemanticHash: snapshot.RouteSnapshotHash, AfterSemanticHash: terminalHash, AuditPayloadHash: sha256.Sum256(auditJSON), OutboxEventClass: "sharing.private_endpoint.withdrawn", OutboxPayloadHash: sha256.Sum256(outboxJSON)})
	if err != nil {
		return streamEvidence{}, err
	}
	evidence.eventHash, evidence.auditPayload, evidence.outboxPayload = eventHash, auditJSON, outboxJSON
	return evidence, nil
}

type publicationResult struct{ providerNetwork, providerDNS, providerRoute, providerSharing, consumerNetwork, consumerDNS, consumerRoute, consumerSharing, aliasVersion, endpointVersion, readinessVersion, dnsVersion int64 }

func (result publicationResult) matchesPublication(snapshot endpointpublication.Snapshot) bool {
	return result.providerNetwork == snapshot.ProviderNetworkRevision+1 && result.providerDNS == snapshot.ProviderDNSRevision && result.providerRoute == snapshot.ProviderRouteRevision+1 && result.providerSharing == snapshot.ProviderSharingRevision+1 && result.consumerNetwork == snapshot.ConsumerNetworkRevision+1 && result.consumerDNS == snapshot.ConsumerDNSRevision+1 && result.consumerRoute == snapshot.ConsumerRouteRevision+1 && result.consumerSharing == snapshot.ConsumerSharingRevision+1 && result.aliasVersion == 2 && result.endpointVersion == 2 && result.readinessVersion == 1 && result.dnsVersion == 1
}

type withdrawalResult struct{ providerNetwork, providerDNS, providerRoute, providerSharing, consumerNetwork, consumerDNS, consumerRoute, consumerSharing, contractVersion, importedVersion, accessNameVersion, aliasVersion, endpointVersion, dnsVersion int64 }

func (result withdrawalResult) matchesWithdrawal(snapshot endpointpublication.WithdrawalSnapshot) bool {
	expectedDNS := snapshot.DNSPublicationVersion
	if expectedDNS > 0 {
		expectedDNS++
	}
	return result.providerNetwork == snapshot.ProviderNetworkRevision+1 && result.providerDNS == snapshot.ProviderDNSRevision && result.providerRoute == snapshot.ProviderRouteRevision+1 && result.providerSharing == snapshot.ProviderSharingRevision+1 && result.consumerNetwork == snapshot.ConsumerNetworkRevision+1 && result.consumerDNS == snapshot.ConsumerDNSRevision+1 && result.consumerRoute == snapshot.ConsumerRouteRevision+1 && result.consumerSharing == snapshot.ConsumerSharingRevision+1 && result.contractVersion == snapshot.ContractVersion+1 && result.importedVersion == snapshot.ImportedResourceVersion+1 && result.accessNameVersion == snapshot.AccessNameVersion+1 && result.aliasVersion == snapshot.AliasLeaseVersion+1 && result.endpointVersion == snapshot.EndpointVersion+1 && result.dnsVersion == expectedDNS
}

const (
	listPrivateEndpointPublicationsSQL   = `SELECT mesh_ops.list_private_endpoint_publication_candidates_v1($1::UUID,$2::INTEGER)`
	readPrivateEndpointPublicationSQL    = `SELECT mesh_ops.read_private_endpoint_publication_snapshot_v2($1::UUID,$2::UUID)`
	stagePrivateEndpointPublicationSQL   = `SELECT mesh_ops.stage_private_endpoint_route_v1($1::UUID,$2::UUID,$3::BIGINT,$4::BIGINT,$5::UUID,$6::BYTEA,$7::TEXT,$8::TIMESTAMPTZ)`
	listPrivateEndpointWithdrawalsSQL    = `SELECT mesh_ops.list_private_endpoint_withdrawal_candidates_v1($1::UUID,$2::INTEGER)`
	readPrivateEndpointWithdrawalSQL     = `SELECT mesh_ops.read_private_endpoint_withdrawal_snapshot_v1($1::UUID,$2::UUID)`
	confirmPrivateEndpointPublicationSQL = `SELECT * FROM mesh_ops.publish_private_endpoint_v1($1::UUID,$2::UUID,$3::BIGINT,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::BIGINT,$11::BIGINT,$12::BIGINT,$13::BIGINT,$14::BIGINT,$15::BIGINT,$16::UUID,$17::UUID,$18::UUID,$19::BYTEA,$20::TEXT,$21::TIMESTAMPTZ,$22::BIGINT,$23::UUID,$24::UUID,$25::BIGINT,$26::BYTEA,$27::BYTEA,$28::JSONB,$29::JSONB,$30::BIGINT,$31::UUID,$32::UUID,$33::BIGINT,$34::BYTEA,$35::BYTEA,$36::JSONB,$37::JSONB)`
	finalizePrivateEndpointWithdrawalSQL = `SELECT * FROM mesh_ops.finalize_private_endpoint_withdrawal_v1($1::UUID,$2::UUID,$3::BIGINT,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::BIGINT,$11::BIGINT,$12::BIGINT,$13::BIGINT,$14::BIGINT,$15::BIGINT,$16::BIGINT,$17::BIGINT,$18::UUID,$19::BYTEA,$20::BYTEA,$21::TEXT,$22::TEXT,$23::BIGINT,$24::UUID,$25::UUID,$26::BIGINT,$27::BYTEA,$28::BYTEA,$29::JSONB,$30::JSONB,$31::BIGINT,$32::UUID,$33::UUID,$34::BIGINT,$35::BYTEA,$36::BYTEA,$37::JSONB,$38::JSONB)`
)

var _ endpointpublication.Store = (*PrivateEndpointPublicationStore)(nil)
