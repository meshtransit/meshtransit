package endpointpublication

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestWorkerStagesBeforeApplyAndConfirmsAfterGateway(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	timeline := &eventLog{}
	store := &publicationStoreFixture{
		publications: []Candidate{{EndpointID: snapshot.EndpointID, Generation: 1}},
		snapshot:     snapshot, timeline: timeline,
	}
	gateway := &gatewayFixture{timeline: timeline}
	worker := workerFixture(t, store, gateway)
	worker.reconcile(t.Context())

	if got, want := timeline.events(), []string{"list-withdrawals", "list-publications", "read-publication", "stage", "apply", "confirm"}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want ordered %v", got, want)
	}
	telemetry := worker.telemetry.Snapshot()
	if telemetry.PublicationSucceeded != 1 || telemetry.PublicationDeferred != 0 {
		t.Fatalf("telemetry = %+v, want one successful publication", telemetry)
	}
}

func TestWorkerCompensatesWhenPublicationCommitFails(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	store := &publicationStoreFixture{
		publications: []Candidate{{EndpointID: snapshot.EndpointID, Generation: 1}},
		snapshot:     snapshot, confirmErr: errors.New("serialization conflict"),
	}
	gateway := &gatewayFixture{}
	worker := workerFixture(t, store, gateway)
	worker.reconcile(t.Context())

	if got := gateway.events(); !slices.Equal(got, []string{"apply", "withdraw"}) {
		t.Fatalf("gateway events = %v, want apply then compensation withdrawal", got)
	}
	if store.confirmCalls != 1 || worker.telemetry.Snapshot().PublicationDeferred != 1 {
		t.Fatal("commit failure did not defer publication after compensation")
	}
}

func TestWorkerNeverConfirmsFailedGatewayApply(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	store := &publicationStoreFixture{publications: []Candidate{{EndpointID: snapshot.EndpointID, Generation: 1}}, snapshot: snapshot}
	gateway := &gatewayFixture{applyErr: errors.New("gateway unavailable")}
	worker := workerFixture(t, store, gateway)
	worker.reconcile(t.Context())

	if store.confirmCalls != 0 || !slices.Equal(gateway.events(), []string{"apply"}) {
		t.Fatal("failed route application reached readiness publication")
	}
}

func TestWorkerWithdrawsBeforePublishing(t *testing.T) {
	t.Parallel()
	publication := publicationFixture(t)
	withdrawal := withdrawalFixture(t, publication)
	store := &publicationStoreFixture{
		withdrawals:  []Candidate{{EndpointID: withdrawal.EndpointID, Generation: 1}},
		publications: []Candidate{{EndpointID: publication.EndpointID, Generation: 1}},
		snapshot:     publication, withdrawal: withdrawal,
	}
	gateway := &gatewayFixture{}
	worker := workerFixture(t, store, gateway)
	worker.reconcile(t.Context())

	if got := gateway.events(); !slices.Equal(got, []string{"withdraw", "apply"}) {
		t.Fatalf("gateway events = %v, want withdrawal before publication", got)
	}
	telemetry := worker.telemetry.Snapshot()
	if telemetry.WithdrawalSucceeded != 1 || telemetry.PublicationSucceeded != 1 {
		t.Fatalf("telemetry = %+v, want both operations successful", telemetry)
	}
}

func TestWorkerBlocksPublicationWhenWithdrawalListingFails(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	store := &publicationStoreFixture{
		publications:      []Candidate{{EndpointID: snapshot.EndpointID, Generation: 1}},
		snapshot:          snapshot,
		withdrawalListErr: errors.New("authority unavailable"),
	}
	gateway := &gatewayFixture{}
	worker := workerFixture(t, store, gateway)
	worker.reconcile(t.Context())

	if got := store.events(); !slices.Equal(got, []string{"list-withdrawals"}) {
		t.Fatalf("events = %v, want fail-closed withdrawal listing", got)
	}
	if len(gateway.events()) != 0 || worker.telemetry.Snapshot().WithdrawalListErrors != 1 {
		t.Fatal("withdrawal authority failure did not block route publication")
	}
}

func TestWorkerBlocksPublicationWhenWithdrawalIsDeferred(t *testing.T) {
	t.Parallel()
	publication := publicationFixture(t)
	withdrawal := withdrawalFixture(t, publication)
	store := &publicationStoreFixture{
		withdrawals:  []Candidate{{EndpointID: withdrawal.EndpointID, Generation: 1}},
		publications: []Candidate{{EndpointID: publication.EndpointID, Generation: 1}},
		snapshot:     publication, withdrawal: withdrawal,
	}
	gateway := &gatewayFixture{withdrawErr: errors.New("gateway unavailable")}
	worker := workerFixture(t, store, gateway)
	worker.reconcile(t.Context())

	if got := gateway.events(); !slices.Equal(got, []string{"withdraw"}) {
		t.Fatalf("gateway events = %v, want only failed withdrawal", got)
	}
	if store.finalizeCalls != 0 || worker.telemetry.Snapshot().WithdrawalDeferred != 1 {
		t.Fatal("failed gateway withdrawal reached finalization or was not deferred")
	}
}

func TestWorkerFinalizesUnstagedEndpointWithoutGatewayWithdrawal(t *testing.T) {
	t.Parallel()
	publication := publicationFixture(t)
	withdrawal := withdrawalFixture(t, publication)
	withdrawal.RoutePresent = false
	withdrawal.RouteSnapshotHash = [sha256.Size]byte{}
	withdrawal.DNSPublicationVersion = 0
	store := &publicationStoreFixture{
		withdrawals: []Candidate{{EndpointID: withdrawal.EndpointID, Generation: 1}},
		withdrawal:  withdrawal,
	}
	gateway := &gatewayFixture{}
	worker := workerFixture(t, store, gateway)
	worker.reconcile(t.Context())

	if len(gateway.events()) != 0 || store.finalizeCalls != 1 {
		t.Fatal("unstaged endpoint did not terminalize without a gateway effect")
	}
	if worker.telemetry.Snapshot().WithdrawalSucceeded != 1 {
		t.Fatal("unstaged endpoint finalization was not observed as successful")
	}
}

func TestWorkerBackoffBoundsRepeatedFailures(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	store := &publicationStoreFixture{publications: []Candidate{{EndpointID: snapshot.EndpointID, Generation: 1}}, snapshot: snapshot}
	gateway := &gatewayFixture{applyErr: errors.New("gateway unavailable")}
	worker := workerFixture(t, store, gateway)
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	worker.clock = func() time.Time { return now }

	worker.reconcile(t.Context())
	worker.reconcile(t.Context())
	if gateway.applyCalls != 1 {
		t.Fatalf("apply calls during retry delay = %d, want 1", gateway.applyCalls)
	}
	now = now.Add(worker.options.InitialRetryDelay)
	worker.reconcile(t.Context())
	if gateway.applyCalls != 2 {
		t.Fatalf("apply calls after retry delay = %d, want 2", gateway.applyCalls)
	}
}

func TestWorkerPrunesRetryStateOutsideBoundedCandidateSet(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	store := &publicationStoreFixture{snapshot: snapshot}
	worker := workerFixture(t, store, &gatewayFixture{})
	worker.retries[publicationRetryPrefix+snapshot.EndpointID.String()] = retryState{
		failures: 4, next: time.Now().UTC().Add(time.Hour),
	}
	worker.retries[withdrawalRetryPrefix+snapshot.EndpointID.String()] = retryState{
		failures: 4, next: time.Now().UTC().Add(time.Hour),
	}

	worker.reconcile(t.Context())
	if len(worker.retries) != 0 {
		t.Fatalf("retained retry entries = %d, want bounded active set only", len(worker.retries))
	}
}

func TestWorkerLifecycleJoinsOwnedGoroutine(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	store := &publicationStoreFixture{snapshot: snapshot}
	worker := workerFixture(t, store, &gatewayFixture{})
	if err := worker.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := worker.Start(t.Context()); !errors.Is(err, ErrWorkerStarted) {
		t.Fatalf("second Start() error = %v, want ErrWorkerStarted", err)
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case err := <-worker.Done():
		if err != nil {
			t.Fatalf("Done() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker goroutine did not join")
	}
	if worker.telemetry.Snapshot().Running {
		t.Fatal("worker telemetry remained running after join")
	}
}

func TestRouteHashIsDeterministicAndAuthoritySensitive(t *testing.T) {
	t.Parallel()
	snapshot := publicationFixture(t)
	route, err := snapshot.Route()
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	first, err := route.Hash()
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	second, err := route.Hash()
	if err != nil || first != second {
		t.Fatal("route hash is not deterministic")
	}
	route.EndpointGeneration++
	changed, err := route.Hash()
	if err != nil || changed == first {
		t.Fatal("route hash did not bind endpoint generation")
	}
}

type publicationStoreFixture struct {
	mu                sync.Mutex
	publications      []Candidate
	withdrawals       []Candidate
	snapshot          Snapshot
	withdrawal        WithdrawalSnapshot
	confirmErr        error
	confirmCalls      int
	finalizeErr       error
	finalizeCalls     int
	withdrawalListErr error
	orderedEvents     []string
	timeline          *eventLog
}

func (store *publicationStoreFixture) record(value string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.orderedEvents = append(store.orderedEvents, value)
	if store.timeline != nil {
		store.timeline.record(value)
	}
}

func (store *publicationStoreFixture) events() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return slices.Clone(store.orderedEvents)
}

func (store *publicationStoreFixture) ListPublicationCandidates(context.Context, deployment.ID, int) ([]Candidate, error) {
	store.record("list-publications")
	return slices.Clone(store.publications), nil
}
func (store *publicationStoreFixture) ReadPublicationSnapshot(context.Context, deployment.ID, sharing.PrivateEndpointID) (Snapshot, error) {
	store.record("read-publication")
	return store.snapshot, nil
}
func (store *publicationStoreFixture) StagePublication(context.Context, Snapshot, [32]byte, string) error {
	store.record("stage")
	return nil
}
func (store *publicationStoreFixture) ConfirmPublication(context.Context, Snapshot, [32]byte, string) error {
	store.record("confirm")
	store.confirmCalls++
	return store.confirmErr
}
func (store *publicationStoreFixture) ListWithdrawalCandidates(context.Context, deployment.ID, int) ([]Candidate, error) {
	store.record("list-withdrawals")
	return slices.Clone(store.withdrawals), store.withdrawalListErr
}
func (store *publicationStoreFixture) ReadWithdrawalSnapshot(context.Context, deployment.ID, sharing.PrivateEndpointID) (WithdrawalSnapshot, error) {
	store.record("read-withdrawal")
	return store.withdrawal, nil
}
func (store *publicationStoreFixture) FinalizeWithdrawal(context.Context, WithdrawalSnapshot, [32]byte, string) error {
	store.record("finalize")
	store.finalizeCalls++
	return store.finalizeErr
}

type gatewayFixture struct {
	mu          sync.Mutex
	applyErr    error
	withdrawErr error
	applyCalls  int
	ordered     []string
	timeline    *eventLog
}

func (gateway *gatewayFixture) Apply(context.Context, Route, [32]byte) error {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	gateway.applyCalls++
	gateway.ordered = append(gateway.ordered, "apply")
	if gateway.timeline != nil {
		gateway.timeline.record("apply")
	}
	return gateway.applyErr
}
func (gateway *gatewayFixture) Withdraw(context.Context, Withdrawal, [32]byte) error {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	gateway.ordered = append(gateway.ordered, "withdraw")
	if gateway.timeline != nil {
		gateway.timeline.record("withdraw")
	}
	return gateway.withdrawErr
}
func (gateway *gatewayFixture) events() []string {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	return slices.Clone(gateway.ordered)
}

func workerFixture(t *testing.T, store Store, gateway Gateway) *Worker {
	t.Helper()
	snapshot := publicationFixture(t)
	worker, err := New(Options{
		DeploymentID: snapshot.DeploymentID, ReconcilerID: "worker-1", BatchSize: 8,
		PollInterval: time.Second, OperationTimeout: time.Second,
		InitialRetryDelay: time.Second, MaximumRetryDelay: time.Minute,
	}, store, gateway, NewTelemetry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return worker
}

func publicationFixture(t *testing.T) Snapshot {
	t.Helper()
	newID := func() publicid.ID {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	deploymentID, _ := deployment.NewID(newID().Bytes())
	endpointID, _ := sharing.ParsePrivateEndpointID(newID().String())
	providerWorkspace, _ := workspace.NewID(newID().Bytes())
	providerNetwork, _ := network.NewID(newID().Bytes())
	consumerWorkspace, _ := workspace.NewID(newID().Bytes())
	consumerNetwork, _ := network.NewID(newID().Bytes())
	accessName, _ := sharing.ParseAccessName("database.shared.example")
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	oneHash := sha256.Sum256([]byte("constraint"))
	providerHash := sha256.Sum256([]byte("provider"))
	consumerHash := sha256.Sum256([]byte("consumer"))
	return Snapshot{
		DeploymentID: deploymentID, EndpointID: endpointID, EndpointVersion: 1, EndpointGeneration: 1,
		AliasLeaseVersion: 1, ContractVersion: 2, ImportedResourceVersion: 2,
		ProviderScope:  Scope{WorkspaceID: providerWorkspace, NetworkID: providerNetwork},
		ConsumerScope:  Scope{WorkspaceID: consumerWorkspace, NetworkID: consumerNetwork},
		TargetDeviceID: newID(), TargetGeneration: 1,
		TargetAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		ResourceAlias:   netip.MustParseAddr("100.100.0.1"), AccessName: accessName,
		Traffic:        []TrafficConstraint{{Protocol: "tcp", DestinationPortRanges: []PortRange{{First: 443, Last: 443}}}},
		ConstraintHash: oneHash, ExpiresAt: now.Add(time.Hour), SnapshotAt: now,
		ProviderNetworkRevision: 1, ProviderDNSRevision: 1, ProviderRouteRevision: 1, ProviderSharingRevision: 1,
		ConsumerNetworkRevision: 1, ConsumerDNSRevision: 1, ConsumerRouteRevision: 1, ConsumerSharingRevision: 1,
		ProviderStreamID: 1, ProviderStreamSequence: 1, ProviderStreamHash: providerHash,
		ConsumerStreamID: 2, ConsumerStreamSequence: 1, ConsumerStreamHash: consumerHash,
	}
}

func withdrawalFixture(t *testing.T, publication Snapshot) WithdrawalSnapshot {
	t.Helper()
	route, err := publication.Route()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := route.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return WithdrawalSnapshot{
		DeploymentID: publication.DeploymentID, EndpointID: publication.EndpointID,
		EndpointVersion: 2, EndpointGeneration: 1, AliasLeaseVersion: 2,
		ContractVersion: 2, ImportedResourceVersion: 2, AccessNameVersion: 1,
		DNSPublicationVersion: 1, ResourceAlias: publication.ResourceAlias,
		RouteSnapshotHash: hash, RoutePresent: true,
		Reason: WithdrawalExpired, SnapshotAt: publication.ExpiresAt,
		ProviderNetworkRevision: 2, ProviderDNSRevision: 1, ProviderRouteRevision: 2, ProviderSharingRevision: 2,
		ConsumerNetworkRevision: 2, ConsumerDNSRevision: 2, ConsumerRouteRevision: 2, ConsumerSharingRevision: 2,
		ProviderStreamID: 1, ProviderStreamSequence: 2, ProviderStreamHash: publication.ProviderStreamHash,
		ConsumerStreamID: 2, ConsumerStreamSequence: 2, ConsumerStreamHash: publication.ConsumerStreamHash,
	}
}

type eventLog struct {
	mu      sync.Mutex
	ordered []string
}

func (log *eventLog) record(value string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.ordered = append(log.ordered, value)
}

func (log *eventLog) events() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return slices.Clone(log.ordered)
}
