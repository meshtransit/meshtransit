package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only the receiver store calls the receiver's cross-tenant reads (design
// C39): no other path of the runtime role may reach them.
func TestOnlyTheReceiverStoreCallsItsReads(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || file == "flowlog_receiver_store.go" {
			continue
		}
		content, err := os.ReadFile(file) //nolint:gosec // a source file of this package, from Glob
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), "mesh_ops.flowlog_") {
			t.Errorf("%s calls a connection log receiver read", file)
		}
	}
}

func TestNewFlowlogReceiverStoreNeedsTheRuntimePool(t *testing.T) {
	t.Parallel()
	if _, err := NewFlowlogReceiverStore(nil, nil); err == nil {
		t.Fatal("built without a pool")
	}
	if _, err := NewFlowlogReceiverStore(&Pool{role: PoolRoleWorker}, nil); err == nil {
		t.Fatal("built on the worker pool")
	}
}
