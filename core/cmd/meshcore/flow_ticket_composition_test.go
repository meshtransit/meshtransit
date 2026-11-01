package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/adapter/flowloginternal"
	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/shared/key"
)

func TestFlowReportCapabilities(t *testing.T) {
	t.Parallel()
	if got := flowReportCapabilities(nil); got != nil {
		t.Fatalf("without a signer: %v", got)
	}
	if got := flowReportCapabilities(&mtcpadapter.FlowSigner{}); len(got) != 1 || got[0] != "flow.report1" {
		t.Fatalf("with a signer: %v", got)
	}
}

func TestSharesSigningKey(t *testing.T) {
	t.Parallel()
	one, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	two, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{2}, 32))
	same, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if sharesSigningKey([]*key.SigningPrivate{&one, nil}, []*key.SigningPrivate{&two, nil}) {
		t.Error("distinct keys shared")
	}
	if !sharesSigningKey([]*key.SigningPrivate{&two, &one}, []*key.SigningPrivate{&same, nil}) {
		t.Error("a next key shared with the relay passed")
	}
}

// Only the internal listener's composition builds the receiver store.
func TestOnlyTheInternalListenerBuildsTheReceiverStore(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || file == "flow_ticket_composition.go" {
			continue
		}
		content, err := os.ReadFile(file) //nolint:gosec // a source file of this package, from Glob
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), "NewFlowlogReceiverStore") {
			t.Errorf("%s builds the receiver store", file)
		}
	}
}

// receiverStoreStub answers the store's errors.
type receiverStoreStub struct{ err error }

func (stub receiverStoreStub) Networks(context.Context, network.ID, int) (connectionlog.ReceiverNetworks, error) {
	return connectionlog.ReceiverNetworks{}, stub.err
}

func (stub receiverStoreStub) Destination(context.Context, network.Scope) (connectionlog.ReceiverDestination, error) {
	return connectionlog.ReceiverDestination{}, stub.err
}

func (stub receiverStoreStub) Revocations(context.Context) (connectionlog.ReceiverRevocations, error) {
	return connectionlog.ReceiverRevocations{}, stub.err
}

func (stub receiverStoreStub) Directory(context.Context, network.Scope) (connectionlog.ReceiverDirectory, error) {
	return connectionlog.ReceiverDirectory{}, stub.err
}

// The store's "no destination" is the API's 404 and its cut revocation
// list the API's refusal, never anything else.
func TestFlowlogReceiverReaderMapsTheStoreErrors(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	missing := flowlogReceiverReader{store: receiverStoreStub{err: postgresadapter.ErrFlowlogNotFound}}
	if _, err := missing.Destination(ctx, network.Scope{}); !errors.Is(err, flowloginternal.ErrNotFound) {
		t.Fatalf("no destination: %v", err)
	}
	cut := flowlogReceiverReader{store: receiverStoreStub{err: errors.Join(postgresadapter.ErrFlowlogReceiver,
		postgresadapter.ErrFlowlogRevocationsCut)}}
	if _, err := cut.Revocations(ctx); !errors.Is(err, flowloginternal.ErrRevocationsCut) {
		t.Fatalf("cut revocations: %v", err)
	}
	down := flowlogReceiverReader{store: receiverStoreStub{err: postgresadapter.ErrFlowlogReceiver}}
	if _, err := down.Destination(ctx, network.Scope{}); errors.Is(err, flowloginternal.ErrNotFound) || err == nil {
		t.Fatalf("an outage became not found: %v", err)
	}
	if _, err := down.Revocations(ctx); errors.Is(err, flowloginternal.ErrRevocationsCut) || err == nil {
		t.Fatalf("an outage became a cut list: %v", err)
	}
	if _, err := missing.Directory(ctx, network.Scope{}); !errors.Is(err, flowloginternal.ErrNotFound) {
		t.Fatalf("no directory: %v", err)
	}
	large := flowlogReceiverReader{store: receiverStoreStub{err: postgresadapter.ErrFlowlogDirectoryTooLarge}}
	if _, err := large.Directory(ctx, network.Scope{}); !errors.Is(err, flowloginternal.ErrDirectoryTooLarge) {
		t.Fatalf("a large directory: %v", err)
	}
	if _, err := down.Directory(ctx, network.Scope{}); errors.Is(err, flowloginternal.ErrNotFound) ||
		errors.Is(err, flowloginternal.ErrDirectoryTooLarge) || err == nil {
		t.Fatalf("an outage became a missing or large directory: %v", err)
	}
}
