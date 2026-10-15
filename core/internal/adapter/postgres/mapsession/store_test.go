package mapsession

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

func TestStoreLoadsConsistentScopedSnapshot(t *testing.T) {
	store, database, transaction, observer, identity := validStoreFixture(t)

	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !snapshot.IsValid() || snapshot.Scope().WorkspaceID().String() != testWorkspaceID ||
		snapshot.Scope().NetworkID().String() != testNetworkID || snapshot.RecoveryEpoch() != 2 ||
		snapshot.NetworkName().String() != "Development Mesh" ||
		snapshot.NetworkRevision() != 7 || snapshot.PacketPolicy().Revision() != 5 ||
		len(snapshot.Addresses()) != 2 || len(snapshot.AuthorizedPeers()) != 1 {
		t.Fatalf("Load() snapshot = %+v, want complete authority evidence", snapshot)
	}
	rules := snapshot.PacketPolicy().Rules()
	if len(rules) != 1 || rules[0].ID().String() != testRuleID ||
		rules[0].SourceNodeID().String() != testNodeID ||
		rules[0].DestinationNodeID().String() != testPeerNodeID ||
		rules[0].Protocol().String() != "tcp" {
		t.Fatalf("packet policy rules = %+v, want exact compiled rule", rules)
	}
	ports := rules[0].DestinationPortRanges()
	if len(ports) != 2 || ports[0].First() != 80 || ports[0].Last() != 81 ||
		ports[1].First() != 443 || ports[1].Last() != 443 {
		t.Fatalf("packet policy ports = %+v, want [80-81, 443]", ports)
	}
	if database.beginCalls != 1 || !transaction.committed || transaction.rollbackCalls != 0 {
		t.Fatalf(
			"transaction state = (begin=%d committed=%t rollbacks=%d), want (1 true 0)",
			database.beginCalls,
			transaction.committed,
			transaction.rollbackCalls,
		)
	}
	wantQueries := []string{
		configureTransactionSQL,
		resolveScopeSQL,
		setScopeSQL,
		loadSnapshotSQL,
		loadPeerCandidatesSQL,
		loadPacketPolicySQL,
		loadDirectEdgesSQL,
	}
	if !reflect.DeepEqual(transaction.queries, wantQueries) {
		t.Fatalf("queries = %v, want %v", transaction.queries, wantQueries)
	}
	fingerprint := identity.MachineFingerprint()
	nodeKey := identity.NodeKey().Bytes()
	if !reflect.DeepEqual(transaction.arguments[1], []any{fingerprint[:], nodeKey[:]}) ||
		!reflect.DeepEqual(transaction.arguments[3], []any{fingerprint[:], nodeKey[:]}) {
		t.Fatalf("identity arguments were not pinned to the authenticated Node")
	}
	if !reflect.DeepEqual(transaction.arguments[4], []any{fingerprint[:], nodeKey[:], 101}) {
		t.Fatalf("candidate arguments did not bind authenticated keys and limit+1")
	}
	if !reflect.DeepEqual(transaction.arguments[5], []any{int64(701), int64(5), 101}) {
		t.Fatalf("policy arguments did not bind self Node, exact revision, and limit+1")
	}
	candidates := snapshot.PeerCandidates()
	if len(candidates) != 1 || candidates[0].NodeID().String() != testPeerNodeID ||
		candidates[0].NumericNodeID() != 702 || candidates[0].NumericOwnerID() != 11 {
		t.Fatalf("PeerCandidates() = %+v, want one decoded candidate", candidates)
	}
	if observer.calls != 1 || observer.operation != OperationLoad || observer.err != nil {
		t.Fatalf("observer = %+v, want one successful load", observer)
	}
}

func TestStoreMapsUnknownIdentityToUnauthorized(t *testing.T) {
	store, _, transaction, observer, identity := validStoreFixture(t)
	transaction.rows = []databaseRow{errorRow{err: pgx.ErrNoRows}, suspendedRow{}, suspendedRow{}}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, appmapsession.ErrUnauthorized) {
		t.Fatalf("Load() error = %v, want mapsession.ErrUnauthorized", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
	if observer.calls != 1 || !errors.Is(observer.err, appmapsession.ErrUnauthorized) {
		t.Fatalf("observer = %+v, want unauthorized outcome", observer)
	}
}

func TestStoreRejectsMalformedSnapshotEvidence(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	record := validSnapshotRecord(t, identity)
	record.machineKey = []byte{1}
	transaction.rows[2] = snapshotRow{record: record}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
		t.Fatalf("Load() error = %v, want ErrSnapshotEvidence", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
}

func TestStoreReturnsCanceledContextBeforeBeginning(t *testing.T) {
	store, database, _, observer, identity := validStoreFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := store.Load(ctx, identity); !errors.Is(err, context.Canceled) {
		t.Fatalf("Load() error = %v, want context canceled", err)
	}
	if database.beginCalls != 0 {
		t.Fatalf("begin calls = %d, want zero", database.beginCalls)
	}
	if observer.calls != 1 || !errors.Is(observer.err, context.Canceled) {
		t.Fatalf("observer = %+v, want canceled outcome", observer)
	}
}

func TestStoreRejectsMissingTransaction(t *testing.T) {
	observer := &recordingObserver{}
	store, err := newStore(
		&fakeDatabase{},
		Options{
			StatementTimeout:   time.Second,
			IdleTimeout:        2 * time.Second,
			PeerCandidateLimit: 100,
			PolicyRuleLimit:    100,
			RelayDirectory:     relayDirectoryFixture(t),
		},
		observer,
	)
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}

	if _, err := store.Load(t.Context(), validIdentity(t)); !errors.Is(err, ErrLoadSnapshot) {
		t.Fatalf("Load() error = %v, want ErrLoadSnapshot", err)
	}
}

func TestStoreRejectsUnsafeConstruction(t *testing.T) {
	observer := &recordingObserver{}
	validOptions := Options{
		StatementTimeout:   time.Second,
		IdleTimeout:        2 * time.Second,
		PeerCandidateLimit: 100,
		PolicyRuleLimit:    100,
		RelayDirectory:     relayDirectoryFixture(t),
	}
	for _, test := range []struct {
		name     string
		database database
		options  Options
		observer Observer
	}{
		{name: "missing database", options: validOptions, observer: observer},
		{name: "missing observer", database: &fakeDatabase{}, options: validOptions},
		{name: "missing relay directory", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: time.Second, PeerCandidateLimit: 1, PolicyRuleLimit: 1}, observer: observer},
		{name: "zero statement timeout", database: &fakeDatabase{}, options: Options{IdleTimeout: time.Second}, observer: observer},
		{name: "excess idle timeout", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: maximumIdleTimeout + 1}, observer: observer},
		{name: "zero candidate limit", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: time.Second}, observer: observer},
		{name: "excess candidate limit", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: time.Second, PeerCandidateLimit: appmapsession.MaximumPeerCandidates + 1}, observer: observer},
		{name: "zero policy limit", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: time.Second, PeerCandidateLimit: 1}, observer: observer},
		{name: "excess policy limit", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: time.Second, PeerCandidateLimit: 1, PolicyRuleLimit: 10001}, observer: observer},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newStore(test.database, test.options, test.observer); !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("newStore() error = %v, want ErrInvalidStore", err)
			}
		})
	}
}

func TestStoreRejectsMalformedPacketPolicyEvidence(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	record := validPolicyRuleRecord()
	unknownProtocol := "any"
	record.protocol = &unknownProtocol
	transaction.policyRows = &policyRuleRows{records: []policyRuleRecord{record}}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
		t.Fatalf("Load() error = %v, want ErrSnapshotEvidence", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
}

func TestStoreRejectsMissingActivePacketPolicyRelease(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	transaction.policyRows = &policyRuleRows{}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
		t.Fatalf("Load() error = %v, want ErrSnapshotEvidence", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf(
			"transaction committed=%t rollbacks=%d, want false/1",
			transaction.committed,
			transaction.rollbackCalls,
		)
	}
}

func TestStoreLoadsExplicitEmptyPacketPolicyReleaseAsDefaultDeny(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	transaction.policyRows = &policyRuleRows{records: []policyRuleRecord{{policyRevision: 5}}}

	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !snapshot.IsValid() || len(snapshot.PacketPolicy().Rules()) != 0 ||
		len(snapshot.AuthorizedPeers()) != 0 {
		t.Fatalf("Load() snapshot = %+v, want valid explicit default-deny release", snapshot)
	}
	if !transaction.committed || transaction.rollbackCalls != 0 {
		t.Fatalf(
			"transaction committed=%t rollbacks=%d, want true/0",
			transaction.committed,
			transaction.rollbackCalls,
		)
	}
}

func TestStoreFailsClosedWhenPolicyRuleBoundIsExceeded(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	store.options.PolicyRuleLimit = 1
	first := validPolicyRuleRecord()
	second := validPolicyRuleRecord()
	secondRuleID := "01890f00-0000-7000-8000-000000000802"
	second.ruleID = &secondRuleID
	transaction.policyRows = &policyRuleRows{records: []policyRuleRecord{first, second}}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, appmapsession.ErrPacketPolicyLimit) {
		t.Fatalf("Load() error = %v, want ErrPacketPolicyLimit", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
}

func TestStoreFailsClosedWhenPeerCandidateBoundIsExceeded(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	store.options.PeerCandidateLimit = 1
	transaction.candidateRows = &peerCandidateRows{records: []peerCandidateRecord{
		validPeerCandidateRecord(2),
		validPeerCandidateRecord(3),
	}}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, appmapsession.ErrPeerCandidateLimit) {
		t.Fatalf("Load() error = %v, want ErrPeerCandidateLimit", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
}

// Schema 161: only a revocation proven for exactly the authenticated keys is
// reported as revoked; any other missing authority stays unauthorized.
func TestStoreTellsARevokedDeviceApart(t *testing.T) {
	for _, test := range []struct {
		name    string
		revoked bool
	}{{name: "revoked", revoked: true}, {name: "no authority", revoked: false}} {
		t.Run(test.name, func(t *testing.T) {
			store, _, transaction, _, identity := validStoreFixture(t)
			transaction.rows = []databaseRow{errorRow{err: pgx.ErrNoRows}, suspendedRow{suspended: false},
				suspendedRow{suspended: test.revoked}}
			_, err := store.Load(t.Context(), identity)
			if !errors.Is(err, appmapsession.ErrUnauthorized) || errors.Is(err, appmapsession.ErrRevoked) != test.revoked {
				t.Fatalf("Load() error = %v, want unauthorized, revoked=%t", err, test.revoked)
			}
			fingerprint := identity.MachineFingerprint()
			nodeKey := identity.NodeKey().Bytes()
			last := len(transaction.queries) - 1
			if transaction.queries[last] != mapSessionRevokedSQL ||
				!reflect.DeepEqual(transaction.arguments[last], []any{fingerprint[:], nodeKey[:]}) {
				t.Fatal("revocation read was not pinned to the authenticated keys")
			}
		})
	}
}

// A failed revocation read is never proof: it must not reach the node as
// REVOKED (or as EXPIRED), only as a load failure the node retries.
func TestStoreRevocationReadFailureIsNotRevoked(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	transaction.rows = []databaseRow{errorRow{err: pgx.ErrNoRows}, suspendedRow{suspended: false},
		errorRow{err: errors.New("connection reset")}}
	_, err := store.Load(t.Context(), identity)
	if !errors.Is(err, ErrLoadSnapshot) || errors.Is(err, appmapsession.ErrUnauthorized) ||
		errors.Is(err, appmapsession.ErrRevoked) {
		t.Fatalf("Load() error = %v, want ErrLoadSnapshot only", err)
	}
}

func TestStoreTellsASuspendedDeviceApart(t *testing.T) {
	store, _, transaction, observer, identity := validStoreFixture(t)
	transaction.rows = []databaseRow{errorRow{err: pgx.ErrNoRows}, suspendedRow{suspended: true}}

	_, err := store.Load(t.Context(), identity)
	if !errors.Is(err, appmapsession.ErrSuspended) || errors.Is(err, appmapsession.ErrUnauthorized) {
		t.Fatalf("Load() error = %v, want mapsession.ErrSuspended", err)
	}
	fingerprint := identity.MachineFingerprint()
	nodeKey := identity.NodeKey().Bytes()
	last := len(transaction.queries) - 1
	if transaction.queries[last] != mapSessionSuspendedSQL ||
		!reflect.DeepEqual(transaction.arguments[last], []any{fingerprint[:], nodeKey[:]}) {
		t.Fatal("suspension read was not pinned to the authenticated keys")
	}
	if transaction.committed || observer.calls != 1 {
		t.Fatalf("committed=%t observer calls=%d, want false/1", transaction.committed, observer.calls)
	}
}

// TestStoreLoadsDeviceNamingFacts: the snapshot carries the Device's DNS
// label, its peers' labels and the scope's display codes (schema 169), and
// a Device of the scope without a label fails the read closed.
func TestStoreLoadsDeviceNamingFacts(t *testing.T) {
	t.Parallel()
	store, _, _, _, identity := validStoreFixture(t)
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	label, labeled := snapshot.DNSLabel()
	workspaceCode, networkCode, coded := snapshot.DisplayCodes()
	if !labeled || label.String() != "node-1" || !coded ||
		workspaceCode.String() != testWorkspaceCode || networkCode.String() != testNetworkCode {
		t.Fatalf("label %q (%v), codes %q %q (%v)", label, labeled, workspaceCode, networkCode, coded)
	}
	peers := snapshot.PeerCandidates()
	if peerLabel, ok := peers[0].DNSLabel(); len(peers) != 1 || !ok || peerLabel.String() != "node-2" {
		t.Fatalf("peer label = %q, %v", peerLabel, ok)
	}
	for name, mutate := range map[string]func(*fakeTransaction){
		"self without label": func(transaction *fakeTransaction) {
			record := transaction.rows[2].(snapshotRow).record
			record.dnsLabel = nil
			transaction.rows[2] = snapshotRow{record: record}
		},
		"self without codes": func(transaction *fakeTransaction) {
			record := transaction.rows[2].(snapshotRow).record
			record.networkCode = nil
			transaction.rows[2] = snapshotRow{record: record}
		},
		"invalid label": func(transaction *fakeTransaction) {
			record := transaction.rows[2].(snapshotRow).record
			record.dnsLabel = textPointer("Node_1")
			transaction.rows[2] = snapshotRow{record: record}
		},
		"peer without label": func(transaction *fakeTransaction) {
			transaction.candidateRows.records[0].dnsLabel = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, _, transaction, _, identity := validStoreFixture(t)
			mutate(transaction)
			if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
				t.Fatalf("Load() error = %v, want snapshot evidence error", err)
			}
		})
	}
}
