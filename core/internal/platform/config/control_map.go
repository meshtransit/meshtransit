package config

import (
	"strconv"
	"time"
)

const (
	envControlMapDeviceAliases        = "MESHTRANSIT_DEVICE_ALIASES_ENABLED"
	envControlMapRequestTimeout       = "MESHTRANSIT_CONTROL_MAP_REQUEST_TIMEOUT"
	envControlMapStatementTimeout     = "MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT"
	envControlMapTransactionIdleLimit = "MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT"
	envControlMapPresenceTTL          = "MESHTRANSIT_CONTROL_MAP_PRESENCE_TTL"
	envControlMapCoordinationTimeout  = "MESHTRANSIT_CONTROL_MAP_COORDINATION_TIMEOUT"
	envControlMapKeepAliveInterval    = "MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL"
	envControlMapReconcileInterval    = "MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL"
	// Shared Network inventory (scale-out S1): one read of a Network's live
	// Devices per revision, shared by its Devices' maps. On by default; off
	// reads every other Device for each map as before.
	envControlMapSharedInventory           = "MESHTRANSIT_CONTROL_MAP_SHARED_INVENTORY"
	envControlMapSharedConnectivity        = "MESHTRANSIT_CONTROL_MAP_SHARED_CONNECTIVITY"
	envControlMapPeerLimit                 = "MESHTRANSIT_CONTROL_MAP_PEER_LIMIT"
	defaultControlMapPeerLimit             = 10_000
	minControlMapPeerLimit                 = 100
	maxControlMapPeerLimit                 = 10_000
	envControlMapInventoryStatementTimeout = "MESHTRANSIT_CONTROL_MAP_INVENTORY_STATEMENT_TIMEOUT"
	defaultControlMapInventoryStatement    = 30 * time.Second
	envControlMapShareStatementTimeout     = "MESHTRANSIT_CONTROL_MAP_SHARE_STATEMENT_TIMEOUT"
	defaultControlMapShareStatement        = 10 * time.Second
	defaultControlMapRequestTimeout        = 10 * time.Second
	defaultControlMapStatementTimeout      = 3 * time.Second
	defaultControlMapIdleLimit             = 5 * time.Second
	defaultControlMapPresenceTTL           = 30 * time.Second
	defaultControlMapCoordination          = 2 * time.Second
	defaultControlMapKeepAlive             = 30 * time.Second
	defaultControlMapReconcile             = 30 * time.Second
	minControlMapRequestTimeout            = 100 * time.Millisecond
	maxControlMapRequestTimeout            = time.Minute
	minControlMapDatabaseTimeout           = time.Millisecond
	maxControlMapDatabaseTimeout           = time.Minute
	minControlMapPresenceTTL               = 3 * time.Second
	maxControlMapPresenceTTL               = 5 * time.Minute
	minControlMapCoordinationTimeout       = 100 * time.Millisecond
	maxControlMapCoordinationTimeout       = 30 * time.Second
	minControlMapKeepAliveInterval         = time.Second
	maxControlMapKeepAliveInterval         = 90 * time.Second
	minControlMapReconcileInterval         = time.Second
	maxControlMapReconcileInterval         = 5 * time.Minute
)

// ControlMapConfig bounds request and PostgreSQL work for one map snapshot.
type ControlMapConfig struct {
	EnableDeviceAliases  bool
	RequestTimeout       time.Duration
	StatementTimeout     time.Duration
	TransactionIdleLimit time.Duration
	PresenceTTL          time.Duration
	CoordinationTimeout  time.Duration
	KeepAliveInterval    time.Duration
	ReconcileInterval    time.Duration
	RelayDirectory       *RelayDirectoryConfig // nil when the relay map is the source
	// SharedInventory reads each Network's live Devices once per revision;
	// InventoryStatementTimeout bounds that read (a whole Network).
	SharedInventory           bool
	InventoryStatementTimeout time.Duration
	// ShareStatementTimeout bounds each share reader statement of a map (a
	// Device receiving up to 10000 shares) when above StatementTimeout.
	ShareStatementTimeout time.Duration
	// SharedConnectivity keeps one connectivity table per Network on each
	// replica, read once per wakeup instead of once per stream.
	SharedConnectivity bool
	// PeerLimit bounds the peers of one map; a Device authorized for more
	// receives a prioritized subset.
	PeerLimit int
}

func loadControlMapConfig(lookup LookupFunc) (ControlMapConfig, error) {
	aliases := valueOrDefault(lookup, envControlMapDeviceAliases, "false")
	if aliases != "true" && aliases != "false" {
		return ControlMapConfig{}, settingError(envControlMapDeviceAliases)
	}
	requestTimeout, err := parseDurationInRange(
		valueOrDefault(
			lookup,
			envControlMapRequestTimeout,
			defaultControlMapRequestTimeout.String(),
		),
		minControlMapRequestTimeout,
		maxControlMapRequestTimeout,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapRequestTimeout)
	}
	statementTimeout, err := parseDurationInRange(
		valueOrDefault(
			lookup,
			envControlMapStatementTimeout,
			defaultControlMapStatementTimeout.String(),
		),
		minControlMapDatabaseTimeout,
		maxControlMapDatabaseTimeout,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapStatementTimeout)
	}
	idleLimit, err := parseDurationInRange(
		valueOrDefault(
			lookup,
			envControlMapTransactionIdleLimit,
			defaultControlMapIdleLimit.String(),
		),
		minControlMapDatabaseTimeout,
		maxControlMapDatabaseTimeout,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapTransactionIdleLimit)
	}
	presenceTTL, err := parseDurationInRange(
		valueOrDefault(lookup, envControlMapPresenceTTL, defaultControlMapPresenceTTL.String()),
		minControlMapPresenceTTL,
		maxControlMapPresenceTTL,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapPresenceTTL)
	}
	coordinationTimeout, err := parseDurationInRange(
		valueOrDefault(
			lookup,
			envControlMapCoordinationTimeout,
			defaultControlMapCoordination.String(),
		),
		minControlMapCoordinationTimeout,
		maxControlMapCoordinationTimeout,
	)
	if err != nil || coordinationTimeout >= presenceTTL/3 {
		return ControlMapConfig{}, settingError(envControlMapCoordinationTimeout)
	}
	keepAliveInterval, err := parseDurationInRange(
		valueOrDefault(lookup, envControlMapKeepAliveInterval, defaultControlMapKeepAlive.String()),
		minControlMapKeepAliveInterval,
		maxControlMapKeepAliveInterval,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapKeepAliveInterval)
	}
	reconcileInterval, err := parseDurationInRange(
		valueOrDefault(lookup, envControlMapReconcileInterval, defaultControlMapReconcile.String()),
		minControlMapReconcileInterval,
		maxControlMapReconcileInterval,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapReconcileInterval)
	}
	sharedInventory := valueOrDefault(lookup, envControlMapSharedInventory, "true")
	if sharedInventory != "true" && sharedInventory != "false" {
		return ControlMapConfig{}, settingError(envControlMapSharedInventory)
	}
	sharedConnectivity := valueOrDefault(lookup, envControlMapSharedConnectivity, "true")
	if sharedConnectivity != "true" && sharedConnectivity != "false" {
		return ControlMapConfig{}, settingError(envControlMapSharedConnectivity)
	}
	peerLimit, err := parseIntInRange(valueOrDefault(lookup, envControlMapPeerLimit, strconv.Itoa(defaultControlMapPeerLimit)),
		minControlMapPeerLimit, maxControlMapPeerLimit)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapPeerLimit)
	}
	inventoryTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envControlMapInventoryStatementTimeout, defaultControlMapInventoryStatement.String()),
		minControlMapDatabaseTimeout,
		maxControlMapDatabaseTimeout,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapInventoryStatementTimeout)
	}
	shareTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envControlMapShareStatementTimeout, defaultControlMapShareStatement.String()),
		minControlMapDatabaseTimeout,
		maxControlMapDatabaseTimeout,
	)
	if err != nil {
		return ControlMapConfig{}, settingError(envControlMapShareStatementTimeout)
	}
	// The relay directory file is optional: a relay authority with a relay
	// map supplies the directory instead (checked by Load).
	var relayDirectory *RelayDirectoryConfig
	_, hasFile := lookup(envRelayDirectoryFile)
	_, hasDigest := lookup(envRelayDirectorySHA256)
	if hasFile || hasDigest {
		loaded, err := loadRelayDirectoryConfig(lookup)
		if err != nil {
			return ControlMapConfig{}, err
		}
		relayDirectory = &loaded
	}
	return ControlMapConfig{
		EnableDeviceAliases:  aliases == "true",
		RequestTimeout:       requestTimeout,
		StatementTimeout:     statementTimeout,
		TransactionIdleLimit: idleLimit,
		PresenceTTL:          presenceTTL,
		CoordinationTimeout:  coordinationTimeout,
		KeepAliveInterval:    keepAliveInterval,
		ReconcileInterval:    reconcileInterval,
		RelayDirectory:       relayDirectory,

		SharedInventory:           sharedInventory == "true",
		InventoryStatementTimeout: inventoryTimeout,
		ShareStatementTimeout:     shareTimeout,
		SharedConnectivity:        sharedConnectivity == "true",
		PeerLimit:                 peerLimit,
	}, nil
}
