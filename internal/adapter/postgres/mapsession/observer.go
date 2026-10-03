package mapsession

import "time"

// Operation is a fixed low-cardinality map-session database operation.
type Operation uint8

const (
	// OperationUnknown is the invalid zero value.
	OperationUnknown Operation = iota
	// OperationLoad opens and reads one scoped repeatable-read snapshot.
	OperationLoad
	// OperationObserveClientVersion records a transport-bound compatibility claim.
	OperationObserveClientVersion
)

// Observer records bounded operation latency and outcome without identity labels.
type Observer interface {
	ObserveMapSession(Operation, time.Duration, error)
}
