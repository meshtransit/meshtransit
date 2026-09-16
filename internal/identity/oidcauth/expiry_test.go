package oidcauth

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func expirySnapshotFixture(t *testing.T, consuming bool) ExpirySnapshot {
	t.Helper()
	dep, err := publicid.Parse("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	id, err := publicid.Parse("01890f00-0000-7000-8000-000000000999")
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	params := ExpirySnapshotParams{
		DeploymentID: deployment.ID(dep), TransactionID: TransactionID(id), State: "pending", Version: 1,
		CreatedAt: created, ExpiresAt: created.Add(time.Minute), SemanticHash: [32]byte{1},
	}
	if consuming {
		params.State, params.Version, params.ConsumedAt = "consuming", 2, created.Add(time.Second)
	}
	snapshot, err := NewExpirySnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestExpiryExclusiveDeadlineAndTombstone(t *testing.T) {
	t.Parallel()
	for _, consuming := range []bool{false, true} {
		snapshot := expirySnapshotFixture(t, consuming)
		if _, err := NewExpired(snapshot, snapshot.ExpiresAt().Add(-time.Microsecond)); err == nil {
			t.Fatal("expired before exclusive deadline")
		}
		terminal, err := NewExpired(snapshot, snapshot.ExpiresAt())
		if err != nil || !terminal.IsValid() || terminal.Version() != snapshot.Version()+1 {
			t.Fatal(err)
		}
		want := snapshot.ExpiresAt()
		if consuming {
			want = snapshot.ConsumedAt()
		}
		if !terminal.ConsumedAt().Equal(want) {
			t.Fatal("claim time/tombstone substituted")
		}
		version := uint64(1)
		if consuming {
			version = 2
		}
		if terminal.BeforeSemanticHash() != hashClaimLifecycle(snapshot.SemanticHash(), version, snapshot.ConsumedAt()) {
			t.Fatal("before hash diverged from claim lifecycle")
		}
		before, after := terminal.BeforeSemanticHash(), terminal.AfterSemanticHash()
		if bytes.Equal(before[:], after[:]) {
			t.Fatal("expiry hash unchanged")
		}
		if fmt.Sprint(snapshot) != "[REDACTED]" || fmt.Sprint(terminal) != "[REDACTED]" {
			t.Fatal("lifecycle formatting leaked")
		}
	}
}

func TestExpirySnapshotRejectsLegacyAndTerminalEvidence(t *testing.T) {
	t.Parallel()
	snapshot := expirySnapshotFixture(t, false)
	for _, name := range []string{"legacy hash", "succeeded", "wrong version", "pending claim", "submicro", "deadline", "zero ID"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := snapshot.Params()
			switch name {
			case "legacy hash":
				params.SemanticHash = [32]byte{}
			case "succeeded":
				params.State, params.Version = "succeeded", 3
			case "wrong version":
				params.Version = 2
			case "pending claim":
				params.ConsumedAt = params.CreatedAt
			case "submicro":
				params.CreatedAt = params.CreatedAt.Add(time.Nanosecond)
			case "deadline":
				params.ExpiresAt = params.CreatedAt
			case "zero ID":
				params.TransactionID = TransactionID{}
			}
			if result, err := NewExpirySnapshot(params); err == nil || result.IsValid() {
				t.Fatal("invalid cleanup evidence accepted")
			}
		})
	}
}

func TestExpiryLifecycleCrossLanguageVectors(t *testing.T) {
	t.Parallel()
	// Independently generated with Ruby SHA-256, explicit big-endian uint64
	// versions and unsigned LEB128 of twice each nonnegative Unix microsecond.
	for _, vector := range []struct {
		consuming     bool
		before, after string
	}{
		{false, "21ac501b7d003c3a8e0c69143613a33ea2da77a80b811c7bc31e282eebae6798",
			"0055f53bf2ac349b48c0e74c7c3e00af69e4530a4e1b46c2d32fd31bba1c767f"},
		{true, "79dcb0b3c0d978d9eb812956a658d9f514d4fe9f268248f12628771ecffbacb9",
			"d2d38f276a6c23b4a57514a98dcfed146dcd9e46a678cbfdeec8c819f5bd91d9"},
	} {
		snapshot := expirySnapshotFixture(t, vector.consuming)
		terminal, err := NewExpired(snapshot, snapshot.ExpiresAt())
		if err != nil {
			t.Fatal(err)
		}
		before, after := terminal.BeforeSemanticHash(), terminal.AfterSemanticHash()
		if hex.EncodeToString(before[:]) != vector.before || hex.EncodeToString(after[:]) != vector.after {
			t.Fatal("expiry lifecycle encoding diverged from independent vectors")
		}
	}
}
