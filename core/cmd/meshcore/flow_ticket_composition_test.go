package main

import (
	"bytes"
	"testing"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
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
