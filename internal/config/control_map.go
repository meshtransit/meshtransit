package config

import "time"

const (
	envControlMapRequestTimeout       = "MESHTRANSIT_CONTROL_MAP_REQUEST_TIMEOUT"
	envControlMapStatementTimeout     = "MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT"
	envControlMapTransactionIdleLimit = "MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT"
	envControlMapPresenceTTL          = "MESHTRANSIT_CONTROL_MAP_PRESENCE_TTL"
	envControlMapCoordinationTimeout  = "MESHTRANSIT_CONTROL_MAP_COORDINATION_TIMEOUT"
	envControlMapKeepAliveInterval    = "MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL"
	envControlMapReconcileInterval    = "MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL"
	defaultControlMapRequestTimeout   = 10 * time.Second
	defaultControlMapStatementTimeout = 3 * time.Second
	defaultControlMapIdleLimit        = 5 * time.Second
	defaultControlMapPresenceTTL      = 30 * time.Second
	defaultControlMapCoordination     = 2 * time.Second
	defaultControlMapKeepAlive        = time.Minute
	defaultControlMapReconcile        = 30 * time.Second
	minControlMapRequestTimeout       = 100 * time.Millisecond
	maxControlMapRequestTimeout       = time.Minute
	minControlMapDatabaseTimeout      = time.Millisecond
	maxControlMapDatabaseTimeout      = time.Minute
	minControlMapPresenceTTL          = 3 * time.Second
	maxControlMapPresenceTTL          = 5 * time.Minute
	minControlMapCoordinationTimeout  = 100 * time.Millisecond
	maxControlMapCoordinationTimeout  = 30 * time.Second
	minControlMapKeepAliveInterval    = time.Second
	maxControlMapKeepAliveInterval    = 90 * time.Second
	minControlMapReconcileInterval    = time.Second
	maxControlMapReconcileInterval    = 5 * time.Minute
)

// ControlMapConfig bounds request and PostgreSQL work for one map snapshot.
type ControlMapConfig struct {
	RequestTimeout       time.Duration
	StatementTimeout     time.Duration
	TransactionIdleLimit time.Duration
	PresenceTTL          time.Duration
	CoordinationTimeout  time.Duration
	KeepAliveInterval    time.Duration
	ReconcileInterval    time.Duration
}

func loadControlMapConfig(lookup LookupFunc) (ControlMapConfig, error) {
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
	return ControlMapConfig{
		RequestTimeout:       requestTimeout,
		StatementTimeout:     statementTimeout,
		TransactionIdleLimit: idleLimit,
		PresenceTTL:          presenceTTL,
		CoordinationTimeout:  coordinationTimeout,
		KeepAliveInterval:    keepAliveInterval,
		ReconcileInterval:    reconcileInterval,
	}, nil
}
