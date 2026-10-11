package config

import (
	"strconv"
	"time"
)

const (
	envRevisionWorkerBatchSize        = "MESHTRANSIT_NETWORK_REVISION_BATCH_SIZE"
	envRevisionWorkerLease            = "MESHTRANSIT_NETWORK_REVISION_LEASE"
	envRevisionWorkerPollInterval     = "MESHTRANSIT_NETWORK_REVISION_POLL_INTERVAL"
	envRevisionWorkerRetryDelay       = "MESHTRANSIT_NETWORK_REVISION_RETRY_DELAY"
	envRevisionWorkerOperationTimeout = "MESHTRANSIT_NETWORK_REVISION_OPERATION_TIMEOUT"

	// A revision reaches streams only after the worker publishes it, so the
	// poll interval adds directly to propagation latency; full batches are
	// drained without waiting (scale-out S4).
	defaultRevisionWorkerBatchSize        = 32
	defaultRevisionWorkerLease            = time.Minute
	defaultRevisionWorkerPollInterval     = 200 * time.Millisecond
	defaultRevisionWorkerRetryDelay       = 5 * time.Second
	defaultRevisionWorkerOperationTimeout = 500 * time.Millisecond

	minRevisionWorkerBatchSize        = 1
	maxRevisionWorkerBatchSize        = 256
	minRevisionWorkerLease            = time.Second
	maxRevisionWorkerLease            = 5 * time.Minute
	minRevisionWorkerPollInterval     = 100 * time.Millisecond
	maxRevisionWorkerPollInterval     = time.Minute
	minRevisionWorkerRetryDelay       = 100 * time.Millisecond
	maxRevisionWorkerRetryDelay       = 24 * time.Hour
	minRevisionWorkerOperationTimeout = 100 * time.Millisecond
	maxRevisionWorkerOperationTimeout = 30 * time.Second

	revisionWorkerOperationsPerClaim = 3
)

// RevisionWorkerConfig bounds one process's durable revision delivery work.
type RevisionWorkerConfig struct {
	BatchSize        int
	Lease            time.Duration
	PollInterval     time.Duration
	RetryDelay       time.Duration
	OperationTimeout time.Duration
}

func loadRevisionWorkerConfig(lookup LookupFunc) (RevisionWorkerConfig, error) {
	batchSize, err := parseIntInRange(
		valueOrDefault(lookup, envRevisionWorkerBatchSize, strconv.Itoa(defaultRevisionWorkerBatchSize)),
		minRevisionWorkerBatchSize,
		maxRevisionWorkerBatchSize,
	)
	if err != nil {
		return RevisionWorkerConfig{}, settingError(envRevisionWorkerBatchSize)
	}
	lease, err := parseDurationInRange(
		valueOrDefault(lookup, envRevisionWorkerLease, defaultRevisionWorkerLease.String()),
		minRevisionWorkerLease,
		maxRevisionWorkerLease,
	)
	if err != nil {
		return RevisionWorkerConfig{}, settingError(envRevisionWorkerLease)
	}
	pollInterval, err := parseDurationInRange(
		valueOrDefault(lookup, envRevisionWorkerPollInterval, defaultRevisionWorkerPollInterval.String()),
		minRevisionWorkerPollInterval,
		maxRevisionWorkerPollInterval,
	)
	if err != nil {
		return RevisionWorkerConfig{}, settingError(envRevisionWorkerPollInterval)
	}
	retryDelay, err := parseDurationInRange(
		valueOrDefault(lookup, envRevisionWorkerRetryDelay, defaultRevisionWorkerRetryDelay.String()),
		minRevisionWorkerRetryDelay,
		maxRevisionWorkerRetryDelay,
	)
	if err != nil {
		return RevisionWorkerConfig{}, settingError(envRevisionWorkerRetryDelay)
	}
	operationTimeout, err := parseDurationInRange(
		valueOrDefault(
			lookup,
			envRevisionWorkerOperationTimeout,
			defaultRevisionWorkerOperationTimeout.String(),
		),
		minRevisionWorkerOperationTimeout,
		maxRevisionWorkerOperationTimeout,
	)
	if err != nil {
		return RevisionWorkerConfig{}, settingError(envRevisionWorkerOperationTimeout)
	}

	claimBudget := time.Duration(batchSize*revisionWorkerOperationsPerClaim) * operationTimeout
	if lease <= claimBudget {
		return RevisionWorkerConfig{}, settingError(envRevisionWorkerLease)
	}

	return RevisionWorkerConfig{
		BatchSize:        batchSize,
		Lease:            lease,
		PollInterval:     pollInterval,
		RetryDelay:       retryDelay,
		OperationTimeout: operationTimeout,
	}, nil
}
