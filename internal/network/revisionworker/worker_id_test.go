package revisionworker

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewWorkerIDUsesBoundedOpaqueEntropy(t *testing.T) {
	t.Parallel()

	workerID, err := newWorkerID(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatalf("newWorkerID() error = %v", err)
	}
	if workerID != "revision-00000000000000000000000000000000" || !validWorkerID(workerID) {
		t.Fatalf("newWorkerID() = %q, want canonical bounded identity", workerID)
	}
}

func TestNewWorkerIDPropagatesEntropyFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("entropy unavailable")
	workerID, err := newWorkerID(errorReader{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Fatalf("newWorkerID() error = %v, want entropy failure", err)
	}
	if workerID != "" {
		t.Fatalf("newWorkerID() = %q, want empty", workerID)
	}
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}
