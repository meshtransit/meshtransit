package mapsession

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"meshtransit.net/core/internal/control"
	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/relay"
)

const (
	maximumStatementTimeout = time.Minute
	maximumIdleTimeout      = time.Minute
	rollbackTimeout         = 2 * time.Second
	maximumInventoryMaxAge  = 5 * time.Minute
)

var (
	// ErrInvalidStore reports a missing dependency, identity, or unsafe resource bound.
	ErrInvalidStore = errors.New("invalid postgres map session store")
	// ErrLoadSnapshot classifies a map snapshot that could not be read consistently.
	ErrLoadSnapshot = errors.New("load postgres map session snapshot")
	// ErrSnapshotEvidence reports malformed or incomplete authoritative state.
	ErrSnapshotEvidence = errors.New("postgres map session snapshot evidence is invalid")
)

// Options bounds database work owned by one map snapshot load.
type Options struct {
	StatementTimeout   time.Duration
	IdleTimeout        time.Duration
	PeerCandidateLimit int
	PolicyRuleLimit    int
	RelayDirectory     relay.Directory
	// RelayDirectories, when set, returns a Network's own relay directory
	// (the shared regions plus its Private Interchange regions); a failure
	// falls back to RelayDirectory.
	RelayDirectories    func(network.ID) (relay.Directory, error)
	EnableDeviceAliases bool
	// SharedInventory reads each Network's live Devices once per revision
	// and shares them between its Devices' snapshots, instead of reading
	// every other Device for each snapshot. InventoryStatementTimeout bounds
	// that read; InventoryMaxAge bounds how long one read answers for a
	// revision (state changes that do not advance the revision).
	SharedInventory           bool
	InventoryStatementTimeout time.Duration
	InventoryMaxAge           time.Duration
	// ShareStatementTimeout, when above StatementTimeout, bounds each share
	// reader statement instead (a Device receiving up to 10000 shares).
	ShareStatementTimeout time.Duration
	// SubnetRoutes reads each Network's subnet routes with its shared
	// policy (MESHTRANSIT_SUBNET_ROUTES_ENABLED); RoutePeerLimit is the peer
	// limit a router's consumers are cut at, the map sessions' own. Maps
	// read without the shared inventory carry no routes.
	SubnetRoutes   bool
	RoutePeerLimit int
	// ExitNodes reads each Network's Exit Pools with its shared policy
	// (MESHTRANSIT_EXIT_NODES_ENABLED), at the same peer limit.
	ExitNodes bool
	// ExitSpread reads spread pools' serving sets so maps assign consumers
	// their own exit nodes (MESHTRANSIT_EXIT_SPREAD_ENABLED); off, every
	// pool is read as failover.
	ExitSpread bool
	// DNSZones reads each Network's DNS zones with its shared policy
	// (MESHTRANSIT_DNS_ZONES_ENABLED), at the same peer limit.
	DNSZones bool
	// DNSProtectedNames are host names no zone a map carries may hold
	// (MESHTRANSIT_DNS_PROTECTED_NAMES): a zone that does is left out of
	// every map, with its names, so names added after the zone (a new
	// relay) stay reachable. The relay directory's host names are added.
	DNSProtectedNames []string
}

// protectedDNSNames are the configured protected names and the relay
// directory's host names.
func (options Options) protectedDNSNames() []string {
	names := slices.Clone(options.DNSProtectedNames)
	for _, region := range options.RelayDirectory.Regions() {
		for _, relayNode := range region.Nodes() {
			if host := strings.ToLower(strings.TrimSuffix(relayNode.HostName(), ".")); host != "" {
				names = append(names, host)
			}
		}
	}
	return names
}

// Store loads exact-scope snapshots in read-only repeatable-read transactions.
// It owns no goroutine or process-local authorization state.
type Store struct {
	database    database
	options     Options
	observer    Observer
	inventories *inventoryCache // nil unless SharedInventory
	stats       inventoryStats
	revisions   revisionReads
	// gatewaysGranted: this role may run the schema 231 gateway reader.
	gatewaysGranted atomic.Bool
	// kubernetesSourcesGranted: this role may run the schema 237 readers.
	kubernetesSourcesGranted atomic.Bool
	// kubernetesCAsGranted: schema 242's reader of clusters' CAs is
	// granted (probed until it is).
	kubernetesCAsGranted atomic.Bool
}

// InventoryStats counts how map snapshots got their candidates.
type InventoryStats struct {
	// Shared snapshots used a Network inventory (Reads of them read it).
	Shared uint64
	Reads  uint64
	// Direct snapshots read their candidates themselves: the shared
	// inventory is off, or none answered for that exact read.
	Direct uint64
	// PolicyMismatches counts Devices whose policy expanded from the
	// Network policy differed from their own policy read (shadow check
	// before the expansion replaces that read); they were read directly.
	PolicyMismatches uint64
	// Derived snapshots were refreshed from the shared view alone, without
	// reading the Device.
	Derived uint64
	// Unchanged refreshes found the view the snapshot came from still the
	// latest and kept the snapshot (O(1)).
	Unchanged uint64
	// SharingDeclines counts refreshes (Unchanged, Derive) declined because a
	// Device share binds the Device; it was read on its own.
	SharingDeclines uint64
	// ChangeReads of the Reads applied the Devices changed since the cached
	// inventory instead of reading the whole Network (schema 153).
	// ChangeFallbacks read the whole Network because the changes contradicted
	// the snapshot or the cached inventory.
	ChangeReads     uint64
	ChangeFallbacks uint64
	// SharesSkipped reads ran no share reader because the Network's latest
	// inventory showed the Device takes part in no share (schema 154);
	// ShareRechecks of them were read again because the inventory they were
	// completed with showed one.
	SharesSkipped uint64
	ShareRechecks uint64
	// PoliciesExpanded reads did not read the Device's packet policy: it was
	// expanded from the Network policy of the inventory the read was
	// completed with. PolicyShadowChecks of the reads that could have done so
	// read it anyway and compared (PolicyMismatches counts differences).
	PoliciesExpanded   uint64
	PolicyShadowChecks uint64
	// GuardrailCuts counts shares left out of maps because an enforced
	// guardrail of either side blocks them (schema 164).
	GuardrailCuts uint64
	// KubernetesWithheld counts gateway maps built without their peers'
	// Kubernetes access (K1a3 §12.2), by reason: the inventory did not read
	// the evidence (Unread) or read it inconsistent (Evidence), the Device
	// was read on its own (Direct), or has direct projections (Projections).
	KubernetesWithheldUnread      uint64
	KubernetesWithheldEvidence    uint64
	KubernetesWithheldDirect      uint64
	KubernetesWithheldProjections uint64
	// KubernetesCAsWithheld counts inventory reads whose clusters' CAs were
	// withheld (a restore suspected); KubernetesCAsRejected those whose
	// answer could not be trusted (schema 242, mtcp-v1 §7.10).
	KubernetesCAsWithheld, KubernetesCAsRejected uint64
}

// policyShadowInterval: one in this many reads that could expand the
// Device's packet policy reads it as well and compares, so a divergence of
// the two still shows in PolicyMismatches.
const policyShadowInterval = 64

type inventoryStats struct {
	shared, reads, direct, policyMismatch, derived, unchanged, sharingDeclines, changeReads, changeFallbacks,
	sharesSkipped, shareRechecks, policiesExpanded, policyShadowChecks, policyCandidates,
	guardrailCuts, kubernetesWithheldUnread, kubernetesWithheldEvidence, kubernetesWithheldDirect,
	kubernetesWithheldProjections, kubernetesCAsWithheld, kubernetesCAsRejected atomic.Uint64
}

// InventoryStats returns the counters since the store was built.
func (store *Store) InventoryStats() InventoryStats {
	return InventoryStats{Shared: store.stats.shared.Load(), Reads: store.stats.reads.Load(),
		Direct: store.stats.direct.Load(), PolicyMismatches: store.stats.policyMismatch.Load(),
		Derived: store.stats.derived.Load(), Unchanged: store.stats.unchanged.Load(),
		SharingDeclines: store.stats.sharingDeclines.Load(), ChangeReads: store.stats.changeReads.Load(),
		ChangeFallbacks: store.stats.changeFallbacks.Load(), SharesSkipped: store.stats.sharesSkipped.Load(),
		ShareRechecks: store.stats.shareRechecks.Load(), PoliciesExpanded: store.stats.policiesExpanded.Load(),
		PolicyShadowChecks: store.stats.policyShadowChecks.Load(), GuardrailCuts: store.stats.guardrailCuts.Load(),
		KubernetesWithheldUnread:      store.stats.kubernetesWithheldUnread.Load(),
		KubernetesWithheldEvidence:    store.stats.kubernetesWithheldEvidence.Load(),
		KubernetesWithheldDirect:      store.stats.kubernetesWithheldDirect.Load(),
		KubernetesWithheldProjections: store.stats.kubernetesWithheldProjections.Load(),
		KubernetesCAsWithheld:         store.stats.kubernetesCAsWithheld.Load(),
		KubernetesCAsRejected:         store.stats.kubernetesCAsRejected.Load()}
}

// policyMatches checks, for a read that read the Device's own packet policy,
// that the Network policy expanded for it equals that read: a Device a share
// binds (unless it has direct projections, whose own read is kept), or a
// shadow check of the expansion other reads use instead (withExpandedPolicy).
func (store *Store) policyMatches(cached cachedInventory, read snapshotRead) bool {
	snapshot := read.snapshot
	if !cached.policy.IsValid() || cached.policy.Revision() != snapshot.PacketPolicy().Revision() {
		return false
	}
	if snapshot.HasDirectProjections() {
		return true
	}
	expanded, err := cached.policy.For(snapshot.NodeID(), read.readAt, store.options.PolicyRuleLimit)
	if err == nil && expanded.Equal(snapshot.PacketPolicy()) {
		return true
	}
	store.stats.policyMismatch.Add(1)
	return false
}

var _ appmapsession.SnapshotStore = (*Store)(nil)

// NewStore constructs a bounded PostgreSQL map-session store.
func NewStore(pool *pgxpool.Pool, options Options, observer Observer) (*Store, error) {
	return newStore(newPGXDatabase(pool), options, observer)
}

func newStore(database database, options Options, observer Observer) (*Store, error) {
	if database == nil || observer == nil || !validOptions(options) {
		return nil, ErrInvalidStore
	}
	store := &Store{database: database, options: options, observer: observer}
	if options.SharedInventory {
		store.inventories = newInventoryCache(options.InventoryMaxAge)
	}
	return store, nil
}

// Load resolves authority from the bound identity, installs exact RLS scope,
// and reads all first-response facts from one immutable database snapshot.
func (store *Store) Load(
	ctx context.Context,
	identity control.AuthenticatedNode,
) (snapshot appmapsession.Snapshot, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.observer != nil {
			store.observer.ObserveMapSession(OperationLoad, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || store.observer == nil ||
		!validOptions(store.options) || !identity.IsValid() {
		return appmapsession.Snapshot{}, ErrInvalidStore
	}
	if err := ctx.Err(); err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, err)
	}
	if store.inventories != nil {
		// A gateway replica's map carries its peers' Kubernetes access only
		// from the shared view, so a gateway tries it once more before its
		// own read, which withholds that access (K1a3 §13.10).
		for attempt := 0; ; attempt++ {
			read, err := store.loadSnapshot(ctx, identity, true)
			if err != nil || read.complete {
				return read.snapshot, err
			}
			shared, ok, gateway, err := store.withSharedInventory(ctx, read)
			if err != nil || ok {
				if ok {
					store.stats.shared.Add(1)
				}
				return shared, err
			}
			if gateway.newer && attempt == 0 {
				continue // the Device's facts lag the view: read them again
			}
			if gateway.listed {
				store.stats.kubernetesWithheldDirect.Add(1)
			}
			break
		}
		// No inventory answers for this read (none usable, it does not list
		// this Device unchanged, or the policy moved on): read the
		// candidates directly, afresh.
	}
	read, err := store.loadSnapshot(ctx, identity, false)
	if err == nil {
		store.stats.direct.Add(1)
	}
	return read.snapshot, err
}

// snapshotRead is one transaction's result: a complete snapshot, or (for a
// shared-inventory read) the Device's own facts awaiting the inventory of
// revision, read at the PostgreSQL time readAt.
type snapshotRead struct {
	snapshot       appmapsession.Snapshot
	complete       bool
	revision       int64
	readAt         time.Time
	workspaceValue string
	networkValue   string
	// sharesSkipped: the share readers did not run (an inventory showed the
	// Device takes part in no share); directSkipped: the legacy direct
	// endpoint reader did not run (the Network held no such endpoint).
	sharesSkipped bool
	directSkipped bool
	// policyDeferred: the Device's packet policy was not read; the snapshot
	// holds an empty one (which admits nothing) of the Device's policy
	// revision until withSharedInventory expands the Network policy.
	policyDeferred bool
}

// withSharedInventory completes a shared-inventory read with the Network's
// inventory of that revision or a later one, which must list self exactly as
// self and carry the same policy revision; the peers are then those of the
// later revision, which only removes revoked ones and adds Devices the same
// policy admits.
//
// gateway reports whether the inventory lists the Device as a Kubernetes
// gateway replica, whose own read would withhold its peers' access, and is
// of a later revision than the read.
func (store *Store) withSharedInventory(ctx context.Context, read snapshotRead) (
	snapshot appmapsession.Snapshot, ok bool, gateway gatewayRead, err error) {
	scope := read.snapshot.Scope()
	cached, found, readErr := store.inventories.get(ctx, scope, read.revision, read.readAt,
		func(readCtx context.Context, previous cachedInventory) (cachedInventory, error) {
			store.stats.reads.Add(1)
			return store.readInventory(readCtx, scope, read.workspaceValue, read.networkValue, previous)
		})
	if readErr != nil {
		return appmapsession.Snapshot{}, false, gatewayRead{}, readErr
	}
	if !found {
		return appmapsession.Snapshot{}, false, gatewayRead{}, nil
	}
	if cached.gatewayListed(read.snapshot.NodeID()) {
		gateway = gatewayRead{listed: true, newer: cached.revision > read.revision}
	}
	if !read.policyDeferred && !store.policyMatches(cached, read) {
		return appmapsession.Snapshot{}, false, gateway, nil
	}
	if (read.sharesSkipped && !cached.sharesAbsent(read.snapshot.NumericNodeID())) ||
		(read.directSkipped && cached.directEndpoints) {
		// The inventory this read is completed with (of its revision or later)
		// shows a share: read the Device again with its shares.
		store.stats.shareRechecks.Add(1)
		return appmapsession.Snapshot{}, false, gateway, nil
	}
	inventory := cached.inventory
	self, listed := inventory.Device(read.snapshot.NodeID())
	if !listed || self.NumericNodeID() != read.snapshot.NumericNodeID() ||
		self.MachineKey() != read.snapshot.MachineKey() || self.NodeKey() != read.snapshot.NodeKey() {
		return appmapsession.Snapshot{}, false, gateway, nil
	}
	if read.policyDeferred {
		snapshot, ok, err = store.withExpandedPolicy(cached, read)
		return snapshot, ok, gateway, err
	}
	routes := cached.policy.RoutesFor(read.snapshot.NodeID(), read.readAt)
	snapshot, err = read.snapshot.WithInventoryRoutes(inventory, read.snapshot.PacketPolicy(), routes)
	if err != nil {
		return appmapsession.Snapshot{}, false, gateway, errors.Join(ErrSnapshotEvidence, err)
	}
	// policyMatches compared the Device's own policy with the expansion
	// the access comes from, except for a Device with direct projections.
	if read.snapshot.HasDirectProjections() {
		if gateway.listed {
			store.stats.kubernetesWithheldProjections.Add(1)
		}
		return snapshot, true, gateway, nil
	}
	view := store.kubernetesView(cached, read.snapshot.NodeID(), read.readAt, true)
	return snapshot.WithKubernetes(view), true, gateway, nil
}

// withExpandedPolicy completes a read that deferred its packet policy: the
// policy is the Network policy of the completing inventory (of the read's
// revision or later, listing self as read) expanded for the Device at the
// read's time, as the peers come from that inventory. The policy revisions
// must match; a Device beyond the rule limit is read on its own, which
// reports the limit.
func (store *Store) withExpandedPolicy(cached cachedInventory, read snapshotRead) (appmapsession.Snapshot, bool, error) {
	snapshot := read.snapshot
	if !cached.policy.IsValid() || cached.policy.Revision() != snapshot.PacketPolicy().Revision() {
		return appmapsession.Snapshot{}, false, nil
	}
	expanded, err := cached.policy.For(snapshot.NodeID(), read.readAt, store.options.PolicyRuleLimit)
	if errors.Is(err, appmapsession.ErrPacketPolicyLimit) {
		return appmapsession.Snapshot{}, false, nil
	}
	if err != nil {
		return appmapsession.Snapshot{}, false, errors.Join(ErrSnapshotEvidence, err)
	}
	routes := cached.policy.RoutesFor(snapshot.NodeID(), read.readAt)
	completed, err := snapshot.WithInventoryRoutes(cached.inventory, expanded, routes)
	if err != nil {
		return appmapsession.Snapshot{}, false, errors.Join(ErrSnapshotEvidence, err)
	}
	view := store.kubernetesView(cached, snapshot.NodeID(), read.readAt, true)
	store.stats.policiesExpanded.Add(1)
	return completed.WithKubernetes(view), true, nil
}

// loadSnapshot reads one Device's snapshot in one repeatable-read
// transaction. With shared, it skips the per-Device candidate read and
// returns the Device's own facts for withSharedInventory.
func (store *Store) loadSnapshot(
	ctx context.Context,
	identity control.AuthenticatedNode,
	shared bool,
) (read snapshotRead, resultErr error) {
	// This host's clock before the read: the read's database time is later,
	// so deadlines measured from it come early, never late.
	beginLocal := time.Now()

	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return snapshotRead{}, errors.Join(ErrLoadSnapshot, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollback(transaction))
		}
	}()
	if err := configure(ctx, transaction, store.options); err != nil {
		return snapshotRead{}, errors.Join(ErrLoadSnapshot, err)
	}

	if err := markSessionProven(ctx, transaction, identity); err != nil {
		return snapshotRead{}, errors.Join(ErrLoadSnapshot, err)
	}
	fingerprint := identity.MachineFingerprint()
	nodeKey := identity.NodeKey().Bytes()
	var workspaceValue, networkValue string
	var recoveryEpoch int64
	if err := transaction.QueryRow(ctx, resolveScopeSQL, fingerprint[:], nodeKey[:]).Scan(
		&workspaceValue,
		&networkValue,
		&recoveryEpoch,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return snapshotRead{}, suspendedOrUnauthorized(
				ctx,
				transaction,
				fingerprint[:],
				nodeKey[:],
			)
		}
		return snapshotRead{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("resolve authenticated scope: %w", err),
		)
	}

	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(ctx, setScopeSQL, workspaceValue, networkValue).Scan(
		&workspaceInternalID,
		&networkInternalID,
	); err != nil {
		return snapshotRead{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("set exact scope: %w", err),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 || recoveryEpoch <= 0 {
		return snapshotRead{}, ErrSnapshotEvidence
	}
	scope, err := scopeFromText(workspaceValue, networkValue)
	if err != nil {
		return snapshotRead{}, err
	}

	record := snapshotRecord{readLocal: beginLocal}
	if err := transaction.QueryRow(ctx, loadSnapshotSQL, fingerprint[:], nodeKey[:]).Scan(
		&record.numericNodeID,
		&record.numericOwnerID,
		&record.networkName,
		&record.nodeID,
		&record.hostname,
		&record.machineKey,
		&record.nodeKey,
		&record.sessionGeneration,
		&record.createdAt,
		&record.keyExpiry,
		&record.networkRevision,
		&record.policyRevision,
		&record.addresses,
		&record.readAt,
		&record.dnsLabel,
		&record.workspaceCode,
		&record.networkCode,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return snapshotRead{}, appmapsession.ErrUnauthorized
		}
		return snapshotRead{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("read scoped snapshot: %w", err),
		)
	}
	// A shared-inventory read takes the candidates from the Network's
	// inventory after commit; the empty list keeps direct projections
	// decodable meanwhile (they are checked against the inventory then).
	peerCandidates := []appmapsession.PeerCandidate{}
	if !shared {
		var err error
		peerCandidates, err = store.loadPeerCandidates(
			ctx,
			transaction,
			scope,
			fingerprint[:],
			nodeKey[:],
		)
		if err != nil {
			return snapshotRead{}, err
		}
	}
	// The share readers authenticate the Device again and scan for its
	// shares; a shared read skips them when the Network's latest inventory
	// shows the Device takes part in no share, and withSharedInventory
	// checks that against the inventory it completes the read with.
	// The legacy direct endpoint reader is skipped alone when the Network
	// holds no such endpoint, whatever shares the Device takes part in.
	skipShares, skipDirect, deferPolicy := false, false, false
	if shared {
		if cached, found := store.inventories.peek(scope); found {
			skipShares = cached.sharesAbsent(record.numericNodeID)
			skipDirect = !cached.directEndpoints
			deferPolicy = skipShares && store.deferPolicy(cached, record.policyRevision)
		}
	}
	packetPolicy, err := store.readOrDeferPacketPolicy(ctx, transaction, scope, record, deferPolicy)
	if err != nil {
		return snapshotRead{}, err
	}
	snapshot, err := record.snapshot(
		workspaceValue,
		networkValue,
		recoveryEpoch,
		peerCandidates,
		packetPolicy,
		store.relayDirectory(scope.NetworkID()),
	)
	if err != nil {
		return snapshotRead{}, err
	}
	if skipShares {
		store.stats.sharesSkipped.Add(1)
	} else {
		snapshot, err = store.loadDirectEdges(ctx, transaction, snapshot, fingerprint[:], nodeKey[:], !skipDirect)
		if err != nil {
			return snapshotRead{}, err
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return snapshotRead{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("commit read snapshot: %w", err))
	}
	committed = true
	return snapshotRead{
		snapshot: snapshot, complete: !shared, revision: record.networkRevision, readAt: record.readAt,
		workspaceValue: workspaceValue, networkValue: networkValue, sharesSkipped: skipShares,
		directSkipped: skipShares || skipDirect, policyDeferred: deferPolicy,
	}, nil
}

// deferPolicy reports whether a shared read of a Device in no share may skip
// its packet policy read, to expand the Network policy instead: the latest
// inventory carries a policy of the Device's policy revision, and this is
// not one of the reads kept as shadow checks.
func (store *Store) deferPolicy(cached cachedInventory, policyRevision int64) bool {
	if !cached.policy.IsValid() || cached.policy.Revision() != policyRevision {
		return false
	}
	if store.stats.policyCandidates.Add(1)%policyShadowInterval == 0 {
		store.stats.policyShadowChecks.Add(1)
		return false
	}
	return true
}

// readOrDeferPacketPolicy reads the Device's packet policy, or, when
// deferred, returns an empty policy of the Device's policy revision that
// admits nothing until withSharedInventory replaces it.
func (store *Store) readOrDeferPacketPolicy(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	record snapshotRecord,
	deferred bool,
) (policy.Snapshot, error) {
	if !deferred {
		return store.loadPacketPolicy(ctx, transaction, scope, record.numericNodeID, record.policyRevision)
	}
	placeholder, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: record.policyRevision, Rules: []policy.Rule{},
	})
	if err != nil {
		return policy.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
	}
	return placeholder, nil
}

func (store *Store) loadPacketPolicy(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	numericNodeID int64,
	policyRevision int64,
) (policy.Snapshot, error) {
	rows, err := transaction.Query(
		ctx,
		loadPacketPolicySQL,
		numericNodeID,
		policyRevision,
		store.options.PolicyRuleLimit+1,
	)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return policy.Snapshot{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("read packet policy: %w", err),
		)
	}
	defer rows.Close()
	rules := make([]policy.Rule, 0, min(store.options.PolicyRuleLimit, 64))
	releaseFound := false
	for rows.Next() {
		var record policyRuleRecord
		if err := rows.Scan(
			&record.policyRevision,
			&record.ruleID,
			&record.sourceNodeID,
			&record.destinationNodeID,
			&record.protocol,
			&record.portRangeFirst,
			&record.portRangeLast,
		); err != nil {
			return policy.Snapshot{}, errors.Join(
				ErrLoadSnapshot,
				fmt.Errorf("scan packet policy: %w", err),
			)
		}
		if record.policyRevision != policyRevision {
			return policy.Snapshot{}, ErrSnapshotEvidence
		}
		releaseFound = true
		if record.ruleID == nil {
			if !record.isEmptyRelease() {
				return policy.Snapshot{}, ErrSnapshotEvidence
			}
			continue
		}
		if len(rules) == store.options.PolicyRuleLimit {
			return policy.Snapshot{}, errors.Join(
				ErrLoadSnapshot,
				appmapsession.ErrPacketPolicyLimit,
			)
		}
		rule, err := record.rule(scope)
		if err != nil {
			return policy.Snapshot{}, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return policy.Snapshot{}, errors.Join(
			ErrLoadSnapshot,
			fmt.Errorf("iterate packet policy: %w", err),
		)
	}
	if !releaseFound && policyRevision != 1 {
		return policy.Snapshot{}, ErrSnapshotEvidence
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    scope,
		Revision: policyRevision,
		Rules:    rules,
	})
	if err != nil {
		return policy.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
	}
	return snapshot, nil
}

func (store *Store) loadPeerCandidates(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	machineFingerprint []byte,
	nodeKey []byte,
) ([]appmapsession.PeerCandidate, error) {
	records, err := store.readPeerCandidateRecords(ctx, transaction, machineFingerprint, nodeKey)
	if err != nil || len(records) == 0 {
		return []appmapsession.PeerCandidate{}, err
	}
	// Read after the candidates' rows are closed: one statement at a time.
	gateways, _, err := store.readKubernetesGateways(ctx, transaction)
	if err != nil {
		return nil, err
	}
	candidates := make([]appmapsession.PeerCandidate, 0, len(records))
	for _, record := range records {
		gateways.mark(&record)
		candidate, err := record.candidate(scope)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func (store *Store) readPeerCandidateRecords(
	ctx context.Context,
	transaction databaseTransaction,
	machineFingerprint []byte,
	nodeKey []byte,
) ([]peerCandidateRecord, error) {
	rows, err := transaction.Query(
		ctx,
		loadPeerCandidatesSQL,
		machineFingerprint,
		nodeKey,
		store.options.PeerCandidateLimit+1,
	)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read peer candidates: %w", err))
	}
	defer rows.Close()
	records := make([]peerCandidateRecord, 0, min(store.options.PeerCandidateLimit, 64))
	for rows.Next() {
		if len(records) == store.options.PeerCandidateLimit {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPeerCandidateLimit)
		}
		var record peerCandidateRecord
		if err := rows.Scan(
			&record.numericNodeID,
			&record.numericOwnerID,
			&record.nodeID,
			&record.ownerID,
			&record.hostname,
			&record.machineKey,
			&record.nodeKey,
			&record.sessionGeneration,
			&record.createdAt,
			&record.keyExpiry,
			&record.addresses,
			&record.dnsLabel,
		); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan peer candidate: %w", err))
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate peer candidates: %w", err))
	}
	return records, nil
}

func configure(ctx context.Context, transaction databaseTransaction, options Options) error {
	if err := transaction.Exec(
		ctx,
		configureTransactionSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return fmt.Errorf("configure transaction timeouts: %w", err)
	}
	return nil
}

func validOptions(options Options) bool {
	return options.StatementTimeout >= time.Millisecond &&
		options.StatementTimeout <= maximumStatementTimeout &&
		options.IdleTimeout >= time.Millisecond && options.IdleTimeout <= maximumIdleTimeout &&
		options.PeerCandidateLimit > 0 &&
		options.PeerCandidateLimit <= appmapsession.MaximumPeerCandidates &&
		options.PolicyRuleLimit > 0 &&
		options.PolicyRuleLimit <= appmapsession.MaximumPacketPolicyRules &&
		options.RelayDirectory.IsValid() &&
		options.ShareStatementTimeout >= 0 && options.ShareStatementTimeout <= maximumStatementTimeout &&
		(!options.SharedInventory || options.InventoryStatementTimeout >= time.Millisecond &&
			options.InventoryStatementTimeout <= maximumStatementTimeout &&
			options.InventoryMaxAge >= time.Second && options.InventoryMaxAge <= maximumInventoryMaxAge) &&
		(!options.SubnetRoutes && !options.ExitNodes && !options.DNSZones ||
			options.SharedInventory && options.RoutePeerLimit > 0 &&
				options.RoutePeerLimit <= appmapsession.DefaultPeerLimit)
}

// relayDirectory returns the Network's relay directory.
func (store *Store) relayDirectory(id network.ID) relay.Directory {
	if store.options.RelayDirectories == nil {
		return store.options.RelayDirectory
	}
	directory, err := store.options.RelayDirectories(id)
	if err != nil || !directory.IsValid() || directory.Revision() < store.options.RelayDirectory.Revision() {
		return store.options.RelayDirectory
	}
	return directory
}

func postgresTimeout(value time.Duration) string {
	return strconv.FormatInt(value.Milliseconds(), 10) + "ms"
}

func rollback(transaction databaseTransaction) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := transaction.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back map snapshot: %w", err)
	}
	return nil
}

// suspendedOrUnauthorized tells a suspended Device apart from one without
// authority, so the client waits instead of stopping for good, and a Device
// revoked with exactly these keys apart from both, so the client erases them
// (schema 161). Anything else stays unauthorized and the client keeps its keys.
func suspendedOrUnauthorized(
	ctx context.Context,
	transaction databaseTransaction,
	fingerprint []byte,
	nodeKey []byte,
) error {
	var suspended bool
	if err := transaction.QueryRow(ctx, mapSessionSuspendedSQL, fingerprint, nodeKey).Scan(&suspended); err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("read suspension: %w", err))
	}
	if suspended {
		return appmapsession.ErrSuspended
	}
	var revoked bool
	if err := transaction.QueryRow(ctx, mapSessionRevokedSQL, fingerprint, nodeKey).Scan(&revoked); err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("read revocation: %w", err))
	}
	if revoked {
		return appmapsession.ErrRevoked
	}
	return appmapsession.ErrUnauthorized
}
