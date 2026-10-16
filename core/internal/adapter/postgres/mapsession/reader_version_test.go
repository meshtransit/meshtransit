package mapsession

import (
	"context"
	"testing"
	"time"
)

type versionRecordingObserver struct {
	versions map[string]int
}

func (*versionRecordingObserver) ObserveMapSession(Operation, time.Duration, error) {}

func (observer *versionRecordingObserver) ObserveFunctionVersion(_ context.Context, path string, version int) {
	observer.versions[path] = version
}

// A map load reports the version of each reader it selected, read from the
// function the reader calls.
func TestStoreReportsTheSelectedReaderVersion(t *testing.T) {
	t.Parallel()
	observer := &versionRecordingObserver{versions: map[string]int{}}
	store := &Store{observer: observer}
	store.observeReader(t.Context(), FunctionPathAliasMapEdges, edgeReader{query: loadKeyedAliasEdgesSQL})
	store.observeReader(t.Context(), FunctionPathSharingDependencies, edgeReader{query: loadSharingDependenciesSQL})
	if observer.versions[FunctionPathAliasMapEdges] != 7 || observer.versions[FunctionPathSharingDependencies] != 1 {
		t.Fatalf("versions = %v", observer.versions)
	}
	// An observer without the optional interface is left alone.
	(&Store{observer: &recordingObserver{}}).observeReader(t.Context(), FunctionPathAliasMapEdges, edgeReader{})
}
