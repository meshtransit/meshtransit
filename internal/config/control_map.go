package config

import "time"

const (
	envControlMapRequestTimeout       = "MESHTRANSIT_CONTROL_MAP_REQUEST_TIMEOUT"
	envControlMapStatementTimeout     = "MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT"
	envControlMapTransactionIdleLimit = "MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT"
	defaultControlMapRequestTimeout   = 10 * time.Second
	defaultControlMapStatementTimeout = 3 * time.Second
	defaultControlMapIdleLimit        = 5 * time.Second
	minControlMapRequestTimeout       = 100 * time.Millisecond
	maxControlMapRequestTimeout       = time.Minute
	minControlMapDatabaseTimeout      = time.Millisecond
	maxControlMapDatabaseTimeout      = time.Minute
)

// ControlMapConfig bounds request and PostgreSQL work for one map snapshot.
type ControlMapConfig struct {
	RequestTimeout       time.Duration
	StatementTimeout     time.Duration
	TransactionIdleLimit time.Duration
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
	return ControlMapConfig{
		RequestTimeout:       requestTimeout,
		StatementTimeout:     statementTimeout,
		TransactionIdleLimit: idleLimit,
	}, nil
}
