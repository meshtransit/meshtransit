package config

import "time"

const (
	envControlMapStatementTimeout     = "MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT"
	envControlMapTransactionIdleLimit = "MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT"
	defaultControlMapStatementTimeout = 3 * time.Second
	defaultControlMapIdleLimit        = 5 * time.Second
	minControlMapDatabaseTimeout      = time.Millisecond
	maxControlMapDatabaseTimeout      = time.Minute
)

// ControlMapConfig bounds PostgreSQL work required to authorize one map snapshot.
type ControlMapConfig struct {
	StatementTimeout     time.Duration
	TransactionIdleLimit time.Duration
}

func loadControlMapConfig(lookup LookupFunc) (ControlMapConfig, error) {
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
		StatementTimeout:     statementTimeout,
		TransactionIdleLimit: idleLimit,
	}, nil
}
