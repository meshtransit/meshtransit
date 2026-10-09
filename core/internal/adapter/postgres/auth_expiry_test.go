package postgres

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

func authExpirySnapshotFixture(t *testing.T, consuming bool) oidcauth.ExpirySnapshot {
	t.Helper()
	pending := authTransactionPendingFixture(t)
	params := oidcauth.ExpirySnapshotParams{
		DeploymentID: pending.Route().DeploymentID(), TransactionID: pending.TransactionID(), State: "pending", Version: 1,
		CreatedAt: pending.CreatedAt(), ExpiresAt: pending.ExpiresAt(), SemanticHash: pending.SemanticHash(),
	}
	if consuming {
		params.State, params.Version, params.ConsumedAt = "consuming", 2, pending.CreatedAt().Add(time.Second)
	}
	snapshot, err := oidcauth.NewExpirySnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestAuthExpiryUnitRejectsMetadataAndCommitsOnce(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"pending", "consuming", "version", "claim time", "early", "submicro", "head", "sequence", "overflow", "short hash", "append error", "append sequence", "unknown"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := authExpirySnapshotFixture(t, name == "consuming")
			ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
			if err != nil {
				t.Fatal(err)
			}
			command, err := oidcauth.NewExpiryCommand(snapshot, ids)
			if err != nil {
				t.Fatal(err)
			}
			database := newFakeAuthTransactionDatabaseTransaction()
			database.enqueueRow(expireAuthSQL, authTransactionTestRow{scan: func(dest ...any) error {
				terminal, err := oidcauth.NewExpired(snapshot, snapshot.ExpiresAt())
				if err != nil {
					return err
				}
				*dest[0].(*int64), *dest[1].(*time.Time), *dest[2].(*time.Time) = terminal.Version(), terminal.ConsumedAt(), terminal.ExpiredAt()
				*dest[3].(*int64), *dest[4].(*int64), *dest[5].(*[]byte) = 1, 7, make([]byte, 32)
				switch name {
				case "version":
					*dest[0].(*int64) = 3
				case "claim time":
					*dest[1].(*time.Time) = terminal.ConsumedAt().Add(time.Microsecond)
				case "early":
					*dest[2].(*time.Time) = snapshot.ExpiresAt().Add(-time.Microsecond)
				case "submicro":
					*dest[2].(*time.Time) = snapshot.ExpiresAt().Add(time.Nanosecond)
				case "head":
					*dest[3].(*int64) = 0
				case "sequence":
					*dest[4].(*int64) = 0
				case "overflow":
					*dest[4].(*int64) = 9223372036854775807
				case "short hash":
					*dest[5].(*[]byte) = make([]byte, 31)
				}
				return nil
			}})
			database.enqueueRow(appendAuthExpirySQL, authTransactionTestRow{scan: func(dest ...any) error {
				if name == "append error" {
					return errors.New("private-detail")
				}
				*dest[0].(*int64) = 7
				if name == "append sequence" {
					*dest[0].(*int64) = 8
				}
				return nil
			}})
			if name == "unknown" {
				database.commitErr = errors.New("private-detail")
			}
			unit := newAuthExpiryTransaction(database, snapshot.DeploymentID(), nil)
			result, err := unit.Expire(t.Context(), command)
			valid := name == "pending" || name == "consuming" || name == "unknown"
			if valid {
				if err != nil || !result.IsValid() {
					t.Fatal(err)
				}
				args := database.calls[1].arguments
				if (args[5] == nil) != (name != "consuming") {
					t.Fatal("NULL/original consumed time changed")
				}
				before, after := result.BeforeSemanticHash(), result.AfterSemanticHash()
				args = database.calls[2].arguments
				if string(args[8].([]byte)) != string(before[:]) || string(args[9].([]byte)) != string(after[:]) {
					t.Fatal("lifecycle hashes diverged")
				}
				err = unit.Commit(t.Context())
				if name == "unknown" && !errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) {
					t.Fatal("unknown classification lost")
				}
				if name != "unknown" && err != nil {
					t.Fatal(err)
				}
				if unit.Commit(t.Context()) == nil || database.commitCalls != 1 {
					t.Fatal("Commit replayed")
				}
			} else if err == nil || result.IsValid() || unit.Commit(t.Context()) == nil || database.commitCalls != 0 {
				t.Fatal("malformed metadata committed")
			}
			if err != nil && strings.Contains(err.Error(), "private-detail") {
				t.Fatal("dependency error disclosed")
			}
			if err := unit.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthExpiryUnitRejectsNonqueuedOverlap(t *testing.T) {
	t.Parallel()
	snapshot := authExpirySnapshotFixture(t, false)
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	command, err := oidcauth.NewExpiryCommand(snapshot, ids)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	database := newFakeAuthTransactionDatabaseTransaction()
	database.enqueueRow(expireAuthSQL, authTransactionTestRow{scan: func(...any) error { close(entered); <-release; return errors.New("rejected") }})
	unit := newAuthExpiryTransaction(database, snapshot.DeploymentID(), nil)
	finished := make(chan error, 1)
	go func() { _, err := unit.Expire(t.Context(), command); finished <- err }()
	<-entered
	if _, err := unit.Expire(t.Context(), command); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("queued Expire")
	}
	if err := unit.Commit(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("queued Commit")
	}
	if err := unit.Rollback(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("queued Rollback")
	}
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("failure lost")
	}
	if err := unit.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(database.calls) != 2 || database.rollbackCalls != 1 || database.commitCalls != 0 {
		t.Fatal("overlapped database I/O")
	}
}

func authExpiryJSONFixture(t *testing.T, snapshot oidcauth.ExpirySnapshot) []byte {
	t.Helper()
	hash := snapshot.SemanticHash()
	raw, err := json.Marshal([]authExpiryCandidateRow{{DeploymentID: snapshot.DeploymentID().String(), TransactionID: snapshot.TransactionID().String(),
		State: snapshot.State(), Version: snapshot.Version(), CreatedAt: snapshot.CreatedAt(), ExpiresAt: snapshot.ExpiresAt(), BindingHash: hex.EncodeToString(hash[:])}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAuthExpiryListCompletesReadBeforeRelease(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"confirmed", "null", "overflow", "unknown field", "trailing", "read error", "commit error", "setup error", "cleanup error"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := authExpirySnapshotFixture(t, false)
			raw := authExpiryJSONFixture(t, snapshot)
			database := newFakeAuthTransactionDatabaseTransaction()
			switch name {
			case "null":
				raw = []byte("null")
			case "overflow":
				raw = []byte(strings.Repeat(" ", 2049))
			case "unknown field":
				raw = []byte(strings.Replace(string(raw), `"state":`, `"proof":"forbidden","state":`, 1))
			case "trailing":
				raw = append(raw, []byte(" []")...)
			case "commit error":
				database.commitErr = errors.New("private-detail")
			case "setup error":
				database.execErrors[configureAuthTransactionSQL] = []error{errors.New("private-detail")}
			case "cleanup error":
				raw = []byte("null")
				database.rollbackErr = errors.New("private-detail")
			}
			database.enqueueRow(listAuthExpirySQL, authTransactionTestRow{scan: func(dest ...any) error {
				if name == "read error" {
					return errors.New("private-detail")
				}
				*dest[0].(*[]byte) = raw
				return nil
			}})
			owner := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{database}}
			store := &AuthExpiryStore{database: owner, options: testAuthTransactionOptions()}
			batch, err := store.ListDue(t.Context(), snapshot.DeploymentID(), 2)
			if name == "confirmed" {
				if err != nil || len(batch) != 1 || batch[0].Params() != snapshot.Params() || database.commitCalls != 1 || database.rollbackCalls != 0 {
					t.Fatal("confirmed read failed", err)
				}
			} else if err == nil || len(batch) != 0 || database.rollbackCalls != 1 || strings.Contains(err.Error(), "private-detail") {
				t.Fatal("failed read leaked metadata/ownership")
			}
			if name == "cleanup error" && !errors.Is(err, oidcauth.ErrExpiryCleanupFailed) {
				t.Fatal("failed selector cleanup lost fatal worker category")
			}
			if len(owner.readOnly) != 1 || !owner.readOnly[0] {
				t.Fatal("selector read was not read-only")
			}
		})
	}
}

func FuzzAuthExpiryBatch(f *testing.F) {
	f.Add("[]", uint8(1))
	f.Add("null", uint8(2))
	f.Add("[{}]", uint8(128))
	f.Fuzz(func(t *testing.T, raw string, requested uint8) {
		if len(raw) > 128*1024 {
			return
		}
		snapshot := authExpirySnapshotFixture(t, false)
		limit := int(requested)
		batch, err := decodeAuthExpiryBatch([]byte(raw), snapshot.DeploymentID(), limit)
		if err != nil {
			if batch != nil {
				t.Fatal("failed parse released partial batch")
			}
			return
		}
		if limit < 1 || limit > 128 || len(batch) > limit {
			t.Fatal("parser exceeded bound")
		}
		for _, candidate := range batch {
			if !candidate.IsValid() || candidate.DeploymentID() != snapshot.DeploymentID() {
				t.Fatal("malformed hint admitted")
			}
		}
	})
}
