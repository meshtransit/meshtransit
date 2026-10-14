package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const lockBrowserCompletionSQL = `SELECT
    intent_internal_id, intent_public_id::TEXT,
    registration_internal_id, registration_public_id::TEXT,
    registration_version, workspace_internal_id, workspace_public_id::TEXT,
    network_internal_id, network_public_id::TEXT, profile_internal_id,
    profile_public_id::TEXT, principal_internal_id, principal_public_id::TEXT,
    session_public_id::TEXT, current_network_revision,
    node_lifetime_seconds, ephemeral_mode, request_hash
FROM mesh_ops.lock_browser_registration_completion_authority_v2(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA,
    $5::BYTEA, $6::BYTEA, $7::TEXT
)`

const insertBrowserCompletionDeviceSQL = `INSERT INTO mesh.device (
    public_id, workspace_id, network_id, enrollment_profile_id,
    owner_principal_id, custodian_principal_id,
    registered_by_kind, registered_by_principal_id,
    hostname, hostname_key, is_ephemeral, expires_at,
    state, created_at, updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    $5::BIGINT, $5::BIGINT, 'principal', $5::BIGINT,
    $6::TEXT, $6::TEXT, $7::BOOLEAN, $8::TIMESTAMPTZ,
    'active', $9::TIMESTAMPTZ, $9::TIMESTAMPTZ
) RETURNING id, version`

// countRecentBrowserDevicesSQL counts the Devices a person added to the
// Network by signing in since $4, whatever their state now. It runs under
// the Network revision lock, which orders every registration of the Network.
const countRecentBrowserDevicesSQL = `SELECT pg_catalog.count(*)
FROM mesh.device
WHERE registered_by_principal_id = $3::BIGINT
  AND workspace_id = $1::BIGINT
  AND network_id = $2::BIGINT
  AND registered_by_kind = 'principal'
  AND created_at > pg_catalog.transaction_timestamp() - ($4::BIGINT * INTERVAL '1 millisecond')`

const finishBrowserIntentSQL = `SELECT mesh_ops.complete_browser_registration_intent_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::BYTEA, $5::BYTEA, $6::BYTEA
)`

const readCompletedBrowserRegistrationSQL = `SELECT
    registration_public_id::TEXT, workspace_public_id::TEXT,
    network_public_id::TEXT, device_public_id::TEXT,
    completed_hostname, completed_disposition, completed_network_revision
FROM mesh_ops.read_completed_browser_registration_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA,
    $5::BYTEA, $6::BYTEA, $7::TEXT
)`

var (
	// ErrInvalidBrowserCompletion reports invalid machine-bound completion input.
	ErrInvalidBrowserCompletion = errors.New("invalid browser registration completion")
	// ErrBrowserCompletionUnavailable reports a closed completion dependency or transaction.
	ErrBrowserCompletionUnavailable = errors.New("browser registration completion unavailable")
	// ErrBrowserCompletionConflict reports incompatible existing Device authority.
	ErrBrowserCompletionConflict = errors.New("browser registration Device already exists")
)

// BrowserCompletionStore owns one Noise-bound, audited Device transaction.
// A false found result means the intent is not currently approved.
type BrowserCompletionStore struct {
	database      registrationTransactionDatabase
	options       RegistrationTransactionOptions
	deploymentID  deployment.ID
	recoveryEpoch int64
}

// NewBrowserCompletionStore validates the transaction and intent-key dependencies.
func NewBrowserCompletionStore(
	pool *Pool, options RegistrationTransactionOptions,
	deploymentID deployment.ID, recoveryEpoch int64,
) (*BrowserCompletionStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime ||
		pool.registrationTransactionDatabase == nil ||
		!validRegistrationTransactionOptions(options) ||
		!deploymentID.IsValid() || recoveryEpoch <= 0 {
		return nil, ErrInvalidBrowserCompletion
	}
	return &BrowserCompletionStore{
		database: pool.registrationTransactionDatabase, options: options,
		deploymentID: deploymentID, recoveryEpoch: recoveryEpoch,
	}, nil
}

type browserCompletionAuthority struct {
	intentInternalID, registrationInternalID, registrationVersion        int64
	workspaceInternalID, networkInternalID, profileInternalID            int64
	principalInternalID, currentNetworkRevision, lifetimeSeconds         int64
	intentPublicID, registrationPublicID, workspacePublicID              string
	networkPublicID, profilePublicID, principalPublicID, sessionPublicID string
	ephemeralMode                                                        string
	requestHash                                                          []byte
}

type browserCompletionIDs struct {
	device, machineEpoch, nodeEpoch, v4Lease, v6Lease publicid.ID
	change, event, outbox                             publicid.ID
}

func newBrowserCompletionIDs() (browserCompletionIDs, error) {
	var values [8]publicid.ID
	for index := range values {
		id, err := publicid.New()
		if err != nil {
			return browserCompletionIDs{}, err
		}
		values[index] = id
	}
	return browserCompletionIDs{
		device: values[0], machineEpoch: values[1], nodeEpoch: values[2],
		v4Lease: values[3], v6Lease: values[4], change: values[5],
		event: values[6], outbox: values[7],
	}, nil
}

// Complete commits or replays the approved Device registration in one transaction.
func (store *BrowserCompletionStore) Complete(
	ctx context.Context, identityValue node.RegistrationIdentity,
	hostname node.Hostname, encodedToken string,
) (_ registration.Result, found bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil ||
		!validRegistrationTransactionOptions(store.options) ||
		!store.deploymentID.IsValid() || store.recoveryEpoch <= 0 ||
		!identityValue.IsValid() || !hostname.IsValid() {
		return registration.Result{}, false, ErrInvalidBrowserCompletion
	}
	digest, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken)
	if err != nil {
		return registration.Result{}, false, ErrInvalidBrowserCompletion
	}
	ids, err := newBrowserCompletionIDs()
	if err != nil {
		return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, err)
	}
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackRegistrationSetup(tx))
		}
	}()
	if _, err := tx.Exec(ctx, configureRegistrationTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout)); err != nil {
		return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, err)
	}
	machineKey := identityValue.MachineKey().Bytes()
	fingerprint := identityValue.MachineKey().Fingerprint()
	nodeKey := identityValue.NodeKey().Bytes()
	digestBytes := digest.Bytes()
	var authority browserCompletionAuthority
	err = tx.QueryRow(ctx, lockBrowserCompletionSQL,
		store.deploymentID.String(), store.recoveryEpoch, digestBytes[:],
		machineKey[:], fingerprint[:], nodeKey[:], hostname.String(),
	).Scan(
		&authority.intentInternalID, &authority.intentPublicID,
		&authority.registrationInternalID, &authority.registrationPublicID,
		&authority.registrationVersion, &authority.workspaceInternalID,
		&authority.workspacePublicID, &authority.networkInternalID,
		&authority.networkPublicID, &authority.profileInternalID,
		&authority.profilePublicID, &authority.principalInternalID,
		&authority.principalPublicID, &authority.sessionPublicID,
		&authority.currentNetworkRevision, &authority.lifetimeSeconds,
		&authority.ephemeralMode, &authority.requestHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		replayed, replayFound, replayErr := store.readCompleted(ctx, tx,
			identityValue, hostname, digest)
		if replayErr != nil {
			return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, replayErr)
		}
		if err := tx.Commit(ctx); err != nil {
			return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, err)
		}
		closed = true
		return replayed, replayFound, nil
	}
	if err != nil {
		return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, err)
	}
	result, err := completeApprovedBrowserRegistration(ctx, tx, store.options,
		identityValue, hostname, digest, authority, ids, store.deploymentID, store.recoveryEpoch)
	if err != nil {
		return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return registration.Result{}, false, errors.Join(ErrBrowserCompletionUnavailable, err)
	}
	closed = true
	return result, true, nil
}

func (store *BrowserCompletionStore) readCompleted(
	ctx context.Context, tx registrationDatabaseTransaction,
	identityValue node.RegistrationIdentity, hostname node.Hostname,
	digest enrollment.BrowserIntentDigest,
) (registration.Result, bool, error) {
	machineKey := identityValue.MachineKey().Bytes()
	fingerprint := identityValue.MachineKey().Fingerprint()
	nodeKey := identityValue.NodeKey().Bytes()
	digestBytes := digest.Bytes()
	var registrationPublicID, workspacePublicID, networkPublicID, devicePublicID string
	var completedHostname, disposition string
	var revision int64
	err := tx.QueryRow(ctx, readCompletedBrowserRegistrationSQL,
		store.deploymentID.String(), store.recoveryEpoch, digestBytes[:],
		machineKey[:], fingerprint[:], nodeKey[:], hostname.String(),
	).Scan(&registrationPublicID, &workspacePublicID, &networkPublicID,
		&devicePublicID, &completedHostname, &disposition, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration.Result{}, false, nil
	}
	if err != nil {
		return registration.Result{}, false, err
	}
	registrationID, registrationErr := enrollment.ParseRegistrationID(registrationPublicID)
	workspaceID, workspaceErr := workspace.ParseID(workspacePublicID)
	networkID, networkErr := network.ParseID(networkPublicID)
	nodeID, nodeErr := node.ParseID(devicePublicID)
	selectedHostname, hostnameErr := node.ParseHostname(completedHostname)
	parsedDisposition, dispositionErr := registrationDisposition(disposition)
	if registrationErr != nil || workspaceErr != nil || networkErr != nil ||
		nodeErr != nil || hostnameErr != nil || dispositionErr != nil ||
		(parsedDisposition != registration.DispositionCreated &&
			parsedDisposition != registration.DispositionResumed) || revision <= 0 {
		return registration.Result{}, false, ErrRegistrationEvidence
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return registration.Result{}, false, ErrRegistrationEvidence
	}
	result, err := registration.NewResult(registrationID, scope, nodeID,
		selectedHostname, parsedDisposition, revision)
	if err != nil {
		return registration.Result{}, false, ErrRegistrationEvidence
	}
	return result, true, nil
}

func completeApprovedBrowserRegistration(
	ctx context.Context, tx registrationDatabaseTransaction,
	options RegistrationTransactionOptions, identityValue node.RegistrationIdentity,
	requestedHostname node.Hostname, tokenDigest enrollment.BrowserIntentDigest,
	authority browserCompletionAuthority,
	ids browserCompletionIDs, deploymentID deployment.ID, recoveryEpoch int64,
) (registration.Result, error) {
	workspaceID, workspaceErr := workspace.ParseID(authority.workspacePublicID)
	networkID, networkErr := network.ParseID(authority.networkPublicID)
	registrationID, registrationErr := enrollment.ParseRegistrationID(authority.registrationPublicID)
	principalID, principalErr := identity.ParsePrincipalID(authority.principalPublicID)
	if workspaceErr != nil || networkErr != nil || registrationErr != nil ||
		principalErr != nil || authority.intentInternalID <= 0 ||
		authority.registrationInternalID <= 0 || authority.registrationVersion <= 0 ||
		authority.workspaceInternalID <= 0 || authority.networkInternalID <= 0 ||
		authority.profileInternalID <= 0 || authority.principalInternalID <= 0 ||
		authority.currentNetworkRevision <= 0 || len(authority.requestHash) != sha256.Size ||
		authority.lifetimeSeconds <= 0 ||
		authority.lifetimeSeconds > int64((1<<63-1)/time.Second) ||
		(authority.ephemeralMode != "persistent" && authority.ephemeralMode != "ephemeral") {
		return registration.Result{}, ErrRegistrationEvidence
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return registration.Result{}, ErrRegistrationEvidence
	}
	var networkRevision, inventoryRevision, group, policy, dns, route, sharing, isolation int64
	if err := tx.QueryRow(ctx, lockRegistrationNetworkRevisionSQL).Scan(
		&networkRevision, &inventoryRevision, &group, &policy, &dns,
		&route, &sharing, &isolation,
	); err != nil || networkRevision != authority.currentNetworkRevision ||
		inventoryRevision <= 0 || group <= 0 || policy <= 0 || dns <= 0 ||
		route <= 0 || sharing <= 0 || isolation <= 0 {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	resumed, existing, err := lockBrowserResumeDevice(ctx, tx, identityValue, authority)
	if err != nil {
		return registration.Result{}, err
	}
	if !resumed {
		if err := checkNewDeviceLimit(ctx, tx, authority); err != nil {
			return registration.Result{}, err
		}
	}
	disposition := registration.DispositionCreated
	if resumed {
		id, parseErr := publicid.Parse(existing.publicID)
		if parseErr != nil {
			return registration.Result{}, ErrRegistrationEvidence
		}
		ids.device = id
		disposition = registration.DispositionResumed
	}
	helper := &registrationTransaction{
		database: tx, scope: scope,
		workspaceInternalID: authority.workspaceInternalID,
		networkInternalID:   authority.networkInternalID,
		candidateLimit:      options.AddressCandidateLimit,
	}
	if resumed {
		helper.locked.device = existing
	}
	helper.locked.hostnameOwner = authority.principalInternalID
	if err := helper.selectHostname(ctx, &helper.locked, requestedHostname); err != nil {
		return registration.Result{}, err
	}
	if err := helper.lockAddressState(ctx, &helper.locked); err != nil {
		return registration.Result{}, err
	}
	selectedHostname := helper.locked.hostname
	if resumed {
		selectedHostname, err = node.ParseHostname(existing.hostname)
		if err != nil {
			return registration.Result{}, ErrRegistrationEvidence
		}
	}
	leasing, err := helper.allocateRegistrationLeases()
	if err != nil {
		return registration.Result{}, err
	}
	// Lock audit heads after Device/key and address state, then recheck wall-clock authority.
	if err := helper.lockAuditHead(ctx, &helper.locked); err != nil {
		return registration.Result{}, err
	}
	if err := recheckBrowserCompletion(ctx, tx, deploymentID, recoveryEpoch,
		identityValue, requestedHostname, tokenDigest, authority); err != nil {
		return registration.Result{}, err
	}
	var occurredAt time.Time
	if err := tx.QueryRow(ctx, browserCompletionTimeSQL).Scan(&occurredAt); err != nil || occurredAt.IsZero() {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	expiresAt := occurredAt.Add(time.Duration(authority.lifetimeSeconds) * time.Second)
	if !expiresAt.After(occurredAt) {
		return registration.Result{}, ErrRegistrationEvidence
	}
	if _, err := tx.Exec(ctx, setRegistrationChangeSQL, ids.change.String()); err != nil {
		return registration.Result{}, err
	}
	machineFingerprint := identityValue.MachineKey().Fingerprint()
	var deviceInternalID, deviceVersion int64
	if resumed {
		deviceInternalID = existing.internalID
		resumeSQL := resumeBrowserDeviceSQL
		if existing.handover {
			resumeSQL = handoverBrowserDeviceSQL
		}
		if err := tx.QueryRow(ctx, resumeSQL,
			deviceInternalID, expiresAt, occurredAt, existing.version,
			authority.principalInternalID, authority.profileInternalID,
		).Scan(&deviceVersion); err != nil || deviceVersion != existing.version+1 {
			return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
		}
	} else {
		if err := helper.releaseHostname(ctx, selectedHostname); err != nil {
			return registration.Result{}, err
		}
		if err := tx.QueryRow(ctx, insertBrowserCompletionDeviceSQL,
			ids.device.String(), authority.workspaceInternalID, authority.networkInternalID,
			authority.profileInternalID, authority.principalInternalID,
			selectedHostname.String(), authority.ephemeralMode == "ephemeral",
			expiresAt, occurredAt,
		).Scan(&deviceInternalID, &deviceVersion); err != nil ||
			deviceInternalID <= 0 || deviceVersion != 1 {
			return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
		}
		machineKey := identityValue.MachineKey().Bytes()
		nodeKey := identityValue.NodeKey().Bytes()
		nodeFingerprint := identityValue.NodeKey().Fingerprint()
		for _, key := range []struct {
			query                 string
			id                    publicid.ID
			material, fingerprint [32]byte
		}{
			{insertRegistrationMachineKeySQL, ids.machineEpoch, machineKey, machineFingerprint},
			{insertRegistrationNodeKeySQL, ids.nodeEpoch, nodeKey, nodeFingerprint},
		} {
			if _, err := tx.Exec(ctx, key.query, key.id.String(),
				authority.workspaceInternalID, authority.networkInternalID,
				deviceInternalID, key.material[:], key.fingerprint[:], occurredAt,
			); err != nil {
				return registration.Result{}, err
			}
		}
	}
	for _, lease := range leasing {
		leaseID := ids.v4Lease
		if lease.family == 6 {
			leaseID = ids.v6Lease
		}
		if err := releaseReclaimedRegistrationLease(ctx, tx, lease, occurredAt); err != nil {
			return registration.Result{}, err
		}
		if _, err := tx.Exec(ctx, insertRegistrationLeaseSQL,
			leaseID.String(), authority.workspaceInternalID, authority.networkInternalID,
			lease.prefix.realmInternalID, lease.prefix.poolInternalID,
			lease.prefix.internalID, deviceInternalID, lease.address.String(),
			lease.family, occurredAt,
		); err != nil {
			return registration.Result{}, err
		}
	}
	if err := helper.storeAddressFloors(ctx); err != nil {
		return registration.Result{}, err
	}
	var newNetworkRevision, newInventoryRevision int64
	if err := tx.QueryRow(ctx, advanceRegistrationRevisionSQL).Scan(
		&newNetworkRevision, &newInventoryRevision,
	); err != nil || newNetworkRevision != networkRevision+1 ||
		newInventoryRevision != inventoryRevision+1 {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	updated, err := tx.Exec(ctx, completePendingRegistrationSQL,
		authority.registrationInternalID, deviceInternalID, selectedHostname.String(),
		registrationDispositionValue(disposition), newNetworkRevision, occurredAt, authority.registrationVersion,
	)
	if err != nil || updated.RowsAffected() != 1 {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	tokenDigestBytes := tokenDigest.Bytes()
	nodeKey := identityValue.NodeKey().Bytes()
	var intentClosed bool
	if err := tx.QueryRow(ctx, finishBrowserIntentSQL,
		authority.intentPublicID, authority.registrationPublicID,
		ids.device.String(), tokenDigestBytes[:], machineFingerprint[:], nodeKey[:],
	).Scan(&intentClosed); err != nil || !intentClosed {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	if err := appendBrowserCompletionEvidence(ctx, tx, helper.locked.audit,
		authority, ids, selectedHostname, deviceVersion,
		newNetworkRevision, newInventoryRevision, disposition, resumed && existing.handover,
	); err != nil {
		return registration.Result{}, err
	}
	nodeID, err := node.ParseID(ids.device.String())
	if err != nil {
		return registration.Result{}, ErrRegistrationEvidence
	}
	result, err := registration.NewResult(registrationID, scope, nodeID,
		selectedHostname, disposition, newNetworkRevision)
	if err != nil || !principalID.IsValid() {
		return registration.Result{}, ErrRegistrationEvidence
	}
	return result, nil
}

func appendBrowserCompletionEvidence(
	ctx context.Context, tx registrationDatabaseTransaction,
	head registrationAuditHead, authority browserCompletionAuthority,
	ids browserCompletionIDs, hostname node.Hostname,
	deviceVersion, networkRevision, inventoryRevision int64, disposition registration.Disposition,
	handover bool,
) error {
	action := "device.registered"
	if disposition == registration.DispositionResumed {
		action = "device.resumed"
	}
	if handover {
		action = "device.handover_completed"
	}
	auditPayload, err := json.Marshal(struct {
		Hostname       string `json:"hostname"`
		RegistrationID string `json:"registration_id"`
	}{hostname.String(), authority.registrationPublicID})
	if err != nil {
		return err
	}
	outboxPayload, err := json.Marshal(registrationOutboxPayload{
		InventoryRevision: inventoryRevision, NetworkRevision: networkRevision,
	})
	if err != nil {
		return err
	}
	var semanticHash [sha256.Size]byte
	copy(semanticHash[:], authority.requestHash)
	principalID, err := publicid.Parse(authority.principalPublicID)
	if err != nil {
		return ErrRegistrationEvidence
	}
	registrationID, err := publicid.Parse(authority.registrationPublicID)
	if err != nil {
		return ErrRegistrationEvidence
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: head.previousHash, EventID: ids.event, ChangeID: ids.change,
		AggregateKind: "device", AggregateID: ids.device,
		AggregateVersion: deviceVersion, NetworkRevision: networkRevision,
		ActorPrincipalID: principalID, Action: action,
		Permission: "device.register", CorrelationID: registrationID,
		AfterSemanticHash: semanticHash,
		AuditPayloadHash:  sha256.Sum256(auditPayload),
		OutboxEventClass:  registrationOutboxEventClass,
		OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return err
	}
	var sequence int64
	if err := tx.QueryRow(ctx, appendRegistrationEvidenceSQL,
		head.streamInternalID, ids.event.String(), ids.outbox.String(),
		head.nextSequence, head.previousHash[:], eventHash[:],
		ids.device.String(), deviceVersion, networkRevision,
		authority.principalPublicID, action, authority.registrationPublicID,
		semanticHash[:], auditPayload, outboxPayload,
	).Scan(&sequence); err != nil || sequence != head.nextSequence {
		return errors.Join(ErrRegistrationEvidence, err)
	}
	return nil
}

// checkNewDeviceLimit refuses a new Device for a person who already added
// registration.NewDeviceLimit to the Network within its window.
func checkNewDeviceLimit(ctx context.Context, tx registrationDatabaseTransaction, authority browserCompletionAuthority) error {
	var recent int64
	if err := tx.QueryRow(ctx, countRecentBrowserDevicesSQL,
		authority.workspaceInternalID, authority.networkInternalID, authority.principalInternalID,
		registration.NewDeviceWindow.Milliseconds(),
	).Scan(&recent); err != nil {
		return errors.Join(ErrRegistrationEvidence, err)
	}
	if recent < 0 {
		return ErrRegistrationEvidence
	}
	if recent >= registration.NewDeviceLimit {
		return registration.ErrNewDeviceLimit
	}
	return nil
}
