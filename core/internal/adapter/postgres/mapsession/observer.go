package mapsession

import (
	"context"
	"regexp"
	"strconv"
	"time"
)

// Operation is a fixed low-cardinality map-session database operation.
type Operation uint8

const (
	// OperationUnknown is the invalid zero value.
	OperationUnknown Operation = iota
	// OperationLoad opens and reads one scoped repeatable-read snapshot.
	OperationLoad
	// OperationObserveClientVersion records a transport-bound compatibility claim.
	OperationObserveClientVersion
	// OperationLoadInventory reads one Network's whole live inventory.
	OperationLoadInventory
	// OperationReadNetworkRevision reads one Network's revision for an exit
	// node's stream.
	OperationReadNetworkRevision
)

// Observer records bounded operation latency and outcome without identity labels.
type Observer interface {
	ObserveMapSession(Operation, time.Duration, error)
}

// Reader paths a map load reports through FunctionVersionObserver.
const (
	FunctionPathAliasMapEdges       = "alias_map_edges"
	FunctionPathSharingDependencies = "sharing_dependencies"
)

// FunctionVersionObserver records, when the Observer implements it, the
// version of each reader a map load selected: a pending operator step keeps
// an older, more limited one.
type FunctionVersionObserver interface {
	ObserveFunctionVersion(ctx context.Context, path string, version int)
}

var readerFunctionVersion = regexp.MustCompile(`mesh_ops\.[a-z_]+_v([0-9]+)\(`)

func (store *Store) observeReader(ctx context.Context, path string, reader edgeReader) {
	observer, ok := store.observer.(FunctionVersionObserver)
	if !ok {
		return
	}
	version := 1
	if match := readerFunctionVersion.FindStringSubmatch(reader.query); match != nil {
		if parsed, err := strconv.Atoi(match[1]); err == nil {
			version = parsed
		}
	}
	observer.ObserveFunctionVersion(ctx, path, version)
}
