package mapsession

import "time"

const (
	minimumStreamOperationTimeout = time.Millisecond
	maximumStreamOperationTimeout = time.Minute
	minimumStreamInterval         = time.Second
	maximumStreamInterval         = 5 * time.Minute
)

func validStreamOptions(options StreamOptions) bool {
	return options.ReplicaID.IsValid() &&
		options.SnapshotTimeout >= minimumStreamOperationTimeout &&
		options.SnapshotTimeout <= maximumStreamOperationTimeout &&
		options.PresenceTTL >= minimumStreamInterval &&
		options.PresenceTTL <= maximumStreamInterval &&
		options.CoordinationTimeout >= minimumStreamOperationTimeout &&
		options.CoordinationTimeout < options.PresenceTTL/3 &&
		options.KeepAliveInterval >= minimumStreamInterval &&
		options.KeepAliveInterval <= maximumStreamInterval &&
		options.ReconcileInterval >= minimumStreamInterval &&
		options.ReconcileInterval <= maximumStreamInterval &&
		(options.ExitRevisionPoll == 0 || options.ExitRevisionPoll >= minimumStreamInterval &&
			options.ExitRevisionPoll <= maximumStreamInterval)
}
