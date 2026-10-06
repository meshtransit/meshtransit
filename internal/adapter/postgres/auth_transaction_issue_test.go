package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestIssueBeginOwnsSetupAndIndependentCleanup(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"confirmed", "begin error", "owned begin error", "setup error", "cleanup error", "canceled setup",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := authIssueCommandFixture(t)
			transaction := newFakeAuthTransactionDatabaseTransaction()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			owned := &authIssueContextTransaction{authTransactionDatabaseTransaction: transaction}
			if name != "confirmed" {
				owned.onRollback = func(cleanup context.Context) {
					if cleanup.Err() != nil {
						t.Error("setup rollback inherited request cancellation")
					}
					if _, ok := cleanup.Deadline(); !ok {
						t.Error("setup rollback lost finite deadline")
					}
				}
			}
			database := authIssueBeginDatabase{transaction: owned}
			switch name {
			case "begin error":
				database.transaction = nil
				database.err = errors.New("synthetic begin detail")
			case "owned begin error":
				database.err = errors.New("synthetic owned begin detail")
			case "setup error", "cleanup error":
				transaction.execErrors[configureAuthTransactionSQL] = []error{errors.New("synthetic setup detail")}
			case "canceled setup":
				owned.onExec = func(call context.Context) {
					if call != ctx {
						t.Error("setup replaced caller context")
					}
					cancel()
				}
			}
			if name == "cleanup error" {
				transaction.rollbackErr = &pgconn.PgError{Code: "23514", Detail: "synthetic cleanup detail"}
			}
			store := &AuthTransactionStore{database: database, options: testAuthTransactionOptions()}
			unit, err := store.BeginIssue(ctx, command.Lookup().Snapshot().Route())
			if name == "confirmed" {
				if err != nil || unit == nil || transaction.rollbackCalls != 0 {
					t.Fatal("successful setup did not transfer ownership", err)
				}
				if len(transaction.calls) != 1 || transaction.calls[0].query != configureAuthTransactionSQL {
					t.Fatal("begin did more than bounded write setup")
				}
				if err := unit.Rollback(t.Context()); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || unit != nil || transaction.commitCalls != 0 {
				t.Fatal("failed setup transferred/committed a unit")
			}
			if name != "begin error" && transaction.rollbackCalls != 1 {
				t.Fatal("owned failed setup was not rolled back exactly once")
			}
			cleanupClassified := errors.Is(err, ErrRollbackAuthTransaction)
			cleanupRedacted := !strings.Contains(err.Error(), "synthetic cleanup")
			if name == "cleanup error" && (!cleanupClassified || !cleanupRedacted) {
				t.Fatal("cleanup classification/redaction lost")
			}
			if name == "canceled setup" && !errors.Is(err, context.Canceled) {
				t.Fatal("setup cancellation lost")
			}
		})
	}
}

func TestIssueUnitRejectsMalformedAtomicMetadata(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"transaction ID", "transaction version", "short binding hash", "substituted binding hash", "consumed time",
		"state", "result kind", "result ID", "session ID", "session version", "issued time",
		"idle deadline", "absolute deadline",
		"stream ID", "sequence", "overflow sequence", "head hash", "no rows",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := authIssueCommandFixture(t)
			database := newFakeAuthTransactionDatabaseTransaction()
			row := authIssueRow(command, func(dest []any) {
				switch name {
				case "transaction ID":
					*dest[0].(*string) = command.IDs().SessionID().String()
				case "transaction version":
					*dest[1].(*int64) = 2
				case "short binding hash":
					*dest[2].(*[]byte) = make([]byte, 31)
				case "substituted binding hash":
					*dest[2].(*[]byte) = make([]byte, 32)
				case "consumed time":
					*dest[3].(*time.Time) = command.Lookup().Claimed().ConsumedAt().Add(time.Microsecond)
				case "state":
					*dest[4].(*string) = "consuming"
				case "result kind":
					*dest[5].(*string) = "step_up"
				case "result ID":
					*dest[6].(*string) = command.Lookup().Claimed().TransactionID().String()
				case "session ID":
					*dest[7].(*string) = command.Lookup().Claimed().TransactionID().String()
				case "session version":
					*dest[8].(*int64) = 2
				case "issued time":
					*dest[9].(*time.Time) = command.Lookup().Claimed().ConsumedAt().Add(-time.Microsecond)
				case "idle deadline":
					*dest[10].(*time.Time) = (*dest[10].(*time.Time)).Add(time.Microsecond)
				case "absolute deadline":
					*dest[11].(*time.Time) = (*dest[11].(*time.Time)).Add(time.Microsecond)
				case "stream ID":
					*dest[12].(*int64) = 0
				case "sequence":
					*dest[13].(*int64) = 0
				case "overflow sequence":
					*dest[13].(*int64) = 9223372036854775807
				case "head hash":
					*dest[14].(*[]byte) = make([]byte, 31)
				}
			})
			if name == "no rows" {
				row = authTransactionTestRow{err: pgx.ErrNoRows}
			}
			database.enqueueRow(issueAuthTransactionSQL, row)
			unit := beginAuthIssueUnitFixture(t, database, command)
			result, err := unit.Issue(t.Context(), command)
			if err == nil || result.IsValid() || !errors.Is(unit.Commit(t.Context()), ErrAuthTransactionState) {
				t.Fatal("malformed metadata released/committed")
			}
			if err := unit.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(database.calls) != 3 || database.commitCalls != 0 || database.rollbackCalls != 1 {
				t.Fatal("malformed metadata reached evidence or escaped cleanup")
			}
		})
	}
}

func TestIssueUnitSecondAppendFailureRollsBackThroughOwner(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"second append error", "second append sequence", "unknown commit", "postgres commit rejection",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			database := newFakeAuthTransactionDatabaseTransaction()
			store := &AuthTransactionStore{
				database: &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{database}},
				options:  testAuthTransactionOptions(),
			}
			owner := &authIssueCaptureTransactions{transactions: store}
			fixture := authIssueApplicationFixture(t, owner)
			database.enqueueRow(issueAuthTransactionSQL, authTransactionTestRow{scan: func(dest ...any) error {
				return authIssueRow(owner.command, nil).Scan(dest...)
			}})
			database.enqueueRow(appendAuthIssueEvidenceSQL, authIssueSequenceRow(7))
			second := authIssueSequenceRow(8)
			switch name {
			case "second append error":
				second = authTransactionTestRow{err: &pgconn.PgError{Code: "23514", Detail: "synthetic append detail"}}
			case "second append sequence":
				second = authIssueSequenceRow(9)
			case "unknown commit":
				database.commitErr = errors.New("synthetic transport detail")
			case "postgres commit rejection":
				database.commitErr = &pgconn.PgError{Code: "23514", Detail: "synthetic commit detail"}
			}
			database.enqueueRow(appendAuthIssueEvidenceSQL, second)
			result, err := fixture.service.IssueBrowser(t.Context(), fixture.exchange, fixture.subject)
			if err == nil || result.IsValid() || result.Token().Encoded() != "" || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("failed append/Commit released bearer or dependency details")
			}
			if errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) != (name == "unknown commit") {
				t.Fatal("Commit outcome classification lost")
			}
			wantCommits := 0
			if name == "unknown commit" || name == "postgres commit rejection" {
				wantCommits = 1
			}
			if database.commitCalls != wantCommits || database.rollbackCalls != 1 || len(database.calls) != 5 {
				t.Fatal("partial evidence/Commit failure lost short-unit ownership")
			}
			retry, retryErr := fixture.service.IssueBrowser(t.Context(), fixture.exchange, fixture.subject)
			if retryErr == nil || retry.IsValid() {
				t.Fatal("failed issuance retried")
			}
			if database.commitCalls != wantCommits || database.rollbackCalls != 1 || owner.begins != 1 {
				t.Fatal("failure retried database/cleanup")
			}
		})
	}
}

func TestIssueUnitOverlappingMethodsFailWithoutQueueing(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		owner  string
		method string
	}{
		{name: "Issue overlaps Issue", owner: "Issue", method: "Issue"},
		{name: "Issue overlaps Commit", owner: "Issue", method: "Commit"},
		{name: "Issue overlaps Rollback", owner: "Issue", method: "Rollback"},
		{name: "Commit overlaps Issue", owner: "Commit", method: "Issue"},
		{name: "Commit overlaps Commit", owner: "Commit", method: "Commit"},
		{name: "Commit overlaps Rollback", owner: "Commit", method: "Rollback"},
		{name: "Rollback overlaps Issue", owner: "Rollback", method: "Issue"},
		{name: "Rollback overlaps Commit", owner: "Rollback", method: "Commit"},
		{name: "Rollback overlaps Rollback", owner: "Rollback", method: "Rollback"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				command := authIssueCommandFixture(t)
				entered, release := make(chan struct{}), make(chan struct{})
				database := newFakeAuthTransactionDatabaseTransaction()
				blocking := &authIssueContextTransaction{authTransactionDatabaseTransaction: database}
				block := func(context.Context) {
					close(entered)
					<-release
				}
				row := authIssueRow(command, nil)
				switch test.owner {
				case "Issue":
					row = authTransactionTestRow{scan: func(...any) error {
						block(t.Context())
						return errors.New("synthetic scan rejection")
					}}
				case "Commit":
					blocking.onCommit = block
				case "Rollback":
					blocking.onRollback = block
				}
				database.enqueueRow(issueAuthTransactionSQL, row)
				database.enqueueRow(appendAuthIssueEvidenceSQL, authIssueSequenceRow(7))
				database.enqueueRow(appendAuthIssueEvidenceSQL, authIssueSequenceRow(8))
				unit := beginAuthIssueUnitFixture(t, blocking, command)
				if test.owner != "Issue" {
					if issued, err := unit.Issue(t.Context(), command); err != nil || !issued.Matches(command) {
						t.Fatal("owner was not prepared before Commit/Rollback", err)
					}
				}
				finished := make(chan error, 1)
				go func() {
					var err error
					switch test.owner {
					case "Issue":
						_, err = unit.Issue(t.Context(), command)
					case "Commit":
						err = unit.Commit(t.Context())
					case "Rollback":
						err = unit.Rollback(t.Context())
					}
					finished <- err
				}()
				<-entered
				rejected := make(chan error, 1)
				go func() {
					var err error
					switch test.method {
					case "Issue":
						_, err = unit.Issue(t.Context(), command)
					case "Commit":
						err = unit.Commit(t.Context())
					case "Rollback":
						err = unit.Rollback(t.Context())
					}
					rejected <- err
				}()
				synctest.Wait()
				select {
				case err := <-rejected:
					if !errors.Is(err, ErrAuthTransactionState) {
						t.Error("overlap did not reject")
					}
				default:
					t.Error("overlap queued behind database I/O")
				}
				close(release)
				if err := <-finished; (err != nil) != (test.owner == "Issue") {
					t.Fatal("owner result changed", err)
				}
				if err := unit.Rollback(t.Context()); err != nil {
					t.Fatal(err)
				}
				wantCalls, wantCommits, wantRollbacks := 5, 0, 1
				if test.owner == "Issue" {
					wantCalls = 3
				}
				if test.owner == "Commit" {
					wantCommits, wantRollbacks = 1, 0
				}
				validCalls := len(database.calls) == wantCalls && database.commitCalls == wantCommits &&
					database.rollbackCalls == wantRollbacks
				if !validCalls {
					t.Fatal("overlapping method performed database I/O")
				}
			})
		})
	}
}

func TestIssueUnitChainsExactSafeEventsAndCommitsOnce(t *testing.T) {
	t.Parallel()
	command := authIssueCommandFixture(t)
	database := newFakeAuthTransactionDatabaseTransaction()
	database.enqueueRow(issueAuthTransactionSQL, authIssueRow(command, nil))
	database.enqueueRow(appendAuthIssueEvidenceSQL, authIssueSequenceRow(7))
	database.enqueueRow(appendAuthIssueEvidenceSQL, authIssueSequenceRow(8))
	unit := beginAuthIssueUnitFixture(t, database, command)
	issued, err := unit.Issue(t.Context(), command)
	if err != nil || !issued.Matches(command) || database.commitCalls != 0 || len(database.calls) != 5 {
		t.Fatal("atomic apply did not retain explicit Commit ownership", err)
	}
	changeInstalled := database.calls[1].query == setAuthTransactionChangeSQL &&
		database.calls[1].arguments[0] == command.IDs().ChangeID().String()
	if !changeInstalled {
		t.Fatal("change context not installed before authority mutation")
	}
	if database.calls[2].query != issueAuthTransactionSQL || len(database.calls[2].arguments) != 51 {
		t.Fatal("issuance query/parameter contract changed")
	}
	previous := bytesOf(0x72, 32)
	for index, call := range database.calls[3:] {
		args := call.arguments
		validAppend := call.query == appendAuthIssueEvidenceSQL && len(args) == 17
		validChain := args[3] == int64(7+index) && bytes.Equal(args[4].([]byte), previous)
		if !validAppend || !validChain {
			t.Fatal("event sequence/previous hash did not chain")
		}
		payload := args[14].([]byte)
		for _, forbidden := range []string{
			" Synthetic-é-SID ", " Exact-é ", "synthetic-code", "authentication_time",
			"acr", "amr", "token_digest", "pkce",
		} {
			if bytes.Contains(payload, []byte(forbidden)) {
				t.Fatal("audit/outbox payload exposed secret/provider evidence")
			}
		}
		if !bytes.Equal(payload, args[16].([]byte)) {
			t.Fatal("audit/outbox payload mismatch")
		}
		aggregateID, auditID := publicid.ID(command.IDs().SessionID()), command.IDs().SessionAuditID()
		before, after := [32]byte{}, issued.SessionSemanticHash()
		aggregate, action := "account_session", "account_session.created"
		class, version := "identity.account_session.created", int64(1)
		outboxID := command.IDs().SessionOutboxID()
		if index == 1 {
			aggregateID = publicid.ID(command.Lookup().Claimed().TransactionID())
			auditID, outboxID = command.IDs().SuccessAuditID(), command.IDs().SuccessOutboxID()
			before, after = command.Lookup().Claimed().AfterSemanticHash(), issued.SuccessSemanticHash()
			aggregate, action = "auth_transaction", "auth_transaction.succeeded"
			class, version = "identity.auth_transaction.succeeded", 3
		}
		validIDs := args[1] == auditID.String() && args[2] == outboxID.String() && args[7] == aggregateID.String()
		validAggregate := args[6] == aggregate && args[8] == version
		validAction := args[10] == action && args[15] == class
		validActor := args[9] == command.Subject().PrincipalID().String() &&
			args[11] == command.Lookup().Claimed().TransactionID().String()
		if !validIDs || !validAggregate || !validAction || !validActor {
			t.Fatal("evidence aggregate/action/version/IDs substituted")
		}
		var previousHash [32]byte
		copy(previousHash[:], previous)
		expected, err := audit.HashEvent(audit.EventHashMaterial{
			PreviousHash: previousHash, EventID: auditID, ChangeID: command.IDs().ChangeID(),
			AggregateKind: aggregate, AggregateID: aggregateID, AggregateVersion: version,
			ActorPrincipalID: publicid.ID(command.Subject().PrincipalID()), Action: action,
			Permission: "identity.authenticate", CorrelationID: publicid.ID(command.Lookup().Claimed().TransactionID()),
			BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
			OutboxEventClass: class, OutboxPayloadHash: sha256.Sum256(payload),
		})
		validEventHash := bytes.Equal(args[5].([]byte), expected[:])
		validSemantics := bytes.Equal(args[12].([]byte), before[:]) && bytes.Equal(args[13].([]byte), after[:])
		if err != nil || !validEventHash || !validSemantics {
			t.Fatal("canonical evidence hash mismatch", err)
		}
		previous = expected[:]
	}
	if err := unit.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(unit.Commit(t.Context()), ErrAuthTransactionState) || database.commitCalls != 1 {
		t.Fatal("Commit retried")
	}
	if err := unit.Rollback(t.Context()); err != nil || database.rollbackCalls != 0 {
		t.Fatal("confirmed Commit retained rollback ownership", err)
	}
}

type authIssueBeginDatabase struct {
	transaction authTransactionDatabaseTransaction
	err         error
}

func (database authIssueBeginDatabase) Begin(
	_ context.Context,
	readOnly bool,
) (authTransactionDatabaseTransaction, error) {
	if readOnly {
		return nil, errors.New("issuance requested a read-only unit")
	}
	return database.transaction, database.err
}

type authIssueContextTransaction struct {
	authTransactionDatabaseTransaction
	onExec     func(context.Context)
	onCommit   func(context.Context)
	onRollback func(context.Context)
}

func (transaction *authIssueContextTransaction) Commit(ctx context.Context) error {
	if transaction.onCommit != nil {
		transaction.onCommit(ctx)
	}
	return transaction.authTransactionDatabaseTransaction.Commit(ctx)
}

func (transaction *authIssueContextTransaction) Exec(ctx context.Context, query string, args ...any) error {
	if transaction.onExec != nil {
		transaction.onExec(ctx)
	}
	return transaction.authTransactionDatabaseTransaction.Exec(ctx, query, args...)
}

func (transaction *authIssueContextTransaction) QueryRow(
	ctx context.Context,
	query string,
	args ...any,
) authTransactionRow {
	// pgx encodes arguments before Scan completes. Detach the fake's retained
	// arguments so the next head update cannot rewrite previous-call evidence.
	detached := append([]any{}, args...)
	for index, value := range detached {
		switch value := value.(type) {
		case []byte:
			if value != nil {
				detached[index] = bytes.Clone(value)
			}
		case []string:
			if value != nil {
				detached[index] = append([]string{}, value...)
			}
		}
	}
	return transaction.authTransactionDatabaseTransaction.QueryRow(ctx, query, detached...)
}

func (transaction *authIssueContextTransaction) Rollback(ctx context.Context) error {
	if transaction.onRollback != nil {
		transaction.onRollback(ctx)
	}
	return transaction.authTransactionDatabaseTransaction.Rollback(ctx)
}

func beginAuthIssueUnitFixture(
	t *testing.T,
	database authTransactionDatabaseTransaction,
	command oidcauth.IssueCommand,
) oidcauth.IssueTransaction {
	t.Helper()
	store := &AuthTransactionStore{
		database: authIssueBeginDatabase{
			transaction: &authIssueContextTransaction{authTransactionDatabaseTransaction: database},
		},
		options: testAuthTransactionOptions(),
	}
	unit, err := store.BeginIssue(t.Context(), command.Lookup().Snapshot().Route())
	if err != nil || unit == nil {
		t.Fatal("begin owned issuance fixture", err)
	}
	return unit
}

func authIssueRow(command oidcauth.IssueCommand, mutate func([]any)) authTransactionRow {
	return authTransactionTestRow{scan: func(dest ...any) error {
		hash := command.Lookup().Snapshot().SemanticHash()
		*dest[0].(*string), *dest[1].(*int64) = command.Lookup().Claimed().TransactionID().String(), 3
		*dest[2].(*[]byte), *dest[3].(*time.Time) = hash[:], command.Lookup().Claimed().ConsumedAt()
		*dest[4].(*string), *dest[5].(*string) = "succeeded", "account_session"
		*dest[6].(*string), *dest[7].(*string) = command.IDs().SessionID().String(), command.IDs().SessionID().String()
		*dest[8].(*int64) = 1
		at := command.Lookup().Claimed().ConsumedAt().Add(time.Second)
		*dest[9].(*time.Time), *dest[10].(*time.Time) = at, at.Add(command.IdleLifetime())
		*dest[11].(*time.Time) = command.Subject().MembershipExpiresAt()
		*dest[12].(*int64), *dest[13].(*int64), *dest[14].(*[]byte) = 51, 7, bytesOf(0x72, 32)
		if mutate != nil {
			mutate(dest)
		}
		return nil
	}}
}

func authIssueSequenceRow(sequence int64) authTransactionRow {
	return authTransactionTestRow{scan: func(dest ...any) error {
		*dest[0].(*int64) = sequence
		return nil
	}}
}

type authIssueApplication struct {
	service  *oidcauth.IssueService
	exchange oidcauth.ExchangeResult
	subject  oidcauth.LoginSubjectSnapshot
}

func authIssueCommandFixture(t *testing.T) oidcauth.IssueCommand {
	t.Helper()
	capture := &authIssueCaptureTransactions{}
	fixture := authIssueApplicationFixture(t, capture)
	result, err := fixture.service.IssueBrowser(t.Context(), fixture.exchange, fixture.subject)
	if err == nil || result.IsValid() || !capture.command.IsValid() {
		t.Fatal("opaque issuance command was not captured through application pipeline")
	}
	return capture.command
}

func authIssueApplicationFixture(t *testing.T, transactions oidcauth.IssueTransactions) authIssueApplication {
	t.Helper()
	pending, secrets := authTransactionBrowserFixture(t)
	snapshot, err := oidcauth.NewPendingSnapshot(oidcauth.PendingSnapshotParams{
		TransactionID: pending.TransactionID(), Route: pending.Route(), Version: 1, State: "pending",
		FlowKind: "browser_authorization_code", OperationKind: "login",
		StateDigest: pending.StateDigest(), NonceDigest: pending.NonceDigest(),
		VerifierCiphertext: pending.VerifierCiphertext(), SemanticHash: pending.SemanticHash(),
		CreatedAt: pending.CreatedAt(), ExpiresAt: pending.ExpiresAt(),
	})
	if err != nil {
		t.Fatal(err)
	}
	digestID, err := oidcauth.NewDigestKeyID("oidc-digest-v1")
	if err != nil {
		t.Fatal(err)
	}
	digestKey, err := oidcauth.NewDigestKey(digestID, bytesOf(0x41, 32))
	if err != nil {
		t.Fatal(err)
	}
	cipherID, err := oidcauth.NewVerifierEncryptionKeyID("oidc-verifier-v1")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherID, bytesOf(0x52, 32))
	if err != nil {
		t.Fatal(err)
	}
	clock := authClaimClock{at: snapshot.CreatedAt().Add(time.Second)}
	verification, err := oidcauth.NewBrowserVerificationService(
		oidcauth.BrowserVerificationOptions{RequestTimeout: time.Second},
		oidcauth.BrowserVerificationDependencies{
			Pending: authClaimLoader{snapshot: snapshot}, DigestKey: digestKey, VerifierCipher: cipher, Clock: clock,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verification.VerifyBrowser(t.Context(), pending.Route(), secrets.State(), secrets.PreAuthCookie())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oidcauth.NewClaimService(
		oidcauth.ClaimOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second},
		oidcauth.ClaimDependencies{Transactions: failureFixtureClaims{}, IDs: oidcauth.SystemClaimIDs{}, Clock: clock},
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := claims.ClaimBrowser(t.Context(), verified)
	if err != nil {
		t.Fatal(err)
	}
	exchanges, err := oidcauth.NewExchangeService(
		oidcauth.ExchangeOptions{RequestTimeout: time.Second, MaxConcurrent: 1},
		oidcauth.ExchangeDependencies{
			Provider: authIssueProvider{nonce: secrets.Nonce(), at: clock.at},
			Cipher:   cipher, DigestKey: digestKey, Clock: clock,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	code, err := oidcauth.ParseCode("synthetic-code")
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := exchanges.ExchangeBrowser(t.Context(), receipt, code)
	if err != nil {
		t.Fatal(err)
	}
	subjectKeys := make([]oidcauth.SubjectKey, 0, 2)
	for index, value := range []string{"subject-active-v1", "subject-previous-v1"} {
		id, err := oidcauth.NewDigestKeyID(value)
		if err != nil {
			t.Fatal(err)
		}
		key, err := oidcauth.NewSubjectKey(id, bytesOf(byte(0x61+index), 32))
		if err != nil {
			t.Fatal(err)
		}
		subjectKeys = append(subjectKeys, key)
	}
	ring, err := oidcauth.NewSubjectKeyring(subjectKeys[0], subjectKeys[1])
	if err != nil {
		t.Fatal(err)
	}
	digests, err := ring.Digests(pending.Route(), exchange.Identity())
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := oidcauth.NewSubjectLookup(exchange.Claimed(), digests)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000711")
	if err != nil {
		t.Fatal(err)
	}
	membership, err := oidcauth.ParseLoginMembershipID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := oidcauth.NewLoginSubjectSnapshot(oidcauth.LoginSubjectParams{
		Lookup: lookup, Digest: digests[1], PrincipalID: principal, IdentitySubjectID: subjectID, MembershipID: membership,
		WorkspaceID:    authTransactionTestWorkspaceID(t),
		SubjectVersion: 2, AccountVersion: 3, MembershipVersion: 4,
		PrincipalAuthorityGeneration: 5, AccountSessionGeneration: 6, MembershipAuthorityGeneration: 7,
		EvaluatedAt: clock.at, MembershipExpiresAt: clock.at.Add(90 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := accountsession.NewDigestKeyID("session-active-v1")
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := accountsession.NewDigestKey(sessionID, bytesOf(0x64, 32))
	if err != nil {
		t.Fatal(err)
	}
	sessionKeys, err := accountsession.NewKeyring(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	sidID, err := oidcauth.NewDigestKeyID("provider-session-v1")
	if err != nil {
		t.Fatal(err)
	}
	sidKey, err := oidcauth.NewProviderSessionKey(sidID, bytesOf(0x65, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := oidcauth.NewIssueService(
		oidcauth.IssueOptions{
			RequestTimeout: time.Second, RollbackTimeout: time.Second,
			IdleLifetime: time.Minute, AbsoluteLifetime: time.Hour, MaxConcurrent: 1,
		},
		oidcauth.IssueDependencies{
			Transactions: transactions, Material: oidcauth.SystemIssueMaterial{},
			Subjects: ring, Sessions: sessionKeys, ProviderSessions: sidKey,
			Clock: authClaimClock{at: clock.at.Add(time.Second)}, Observer: authIssueObserver{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return authIssueApplication{service: service, exchange: exchange, subject: subject}
}

// Controlled trusted-provider evidence only; no live signature or login proof.
type authIssueProvider struct {
	nonce oidcauth.Nonce
	at    time.Time
}

type authIssueObserver struct{}

func (authIssueObserver) IssueOpened() {}

func (authIssueObserver) IssueClosed(oidcauth.IssueOutcome, time.Duration) {}

func (provider authIssueProvider) Authenticate(
	_ context.Context,
	request oidcauth.ExchangeRequest,
) (oidcauth.TokenEvidence, error) {
	at := provider.at.Truncate(time.Second)
	return oidcauth.NewTokenEvidence(oidcauth.TokenEvidenceParams{
		Issuer: request.Route().Issuer(), Subject: " Exact-é ", Nonce: provider.nonce,
		IssuedAt: at, ExpiresAt: at.Add(4 * time.Minute), AuthTime: at.Add(-time.Minute),
		SessionID: " Synthetic-é-SID ", ACR: "urn:meshtransit:assurance:mfa", AMR: []string{"synthetic"},
	})
}

type authIssueCaptureTransactions struct {
	transactions oidcauth.IssueTransactions
	command      oidcauth.IssueCommand
	begins       int
}

func (capture *authIssueCaptureTransactions) BeginIssue(
	ctx context.Context,
	route oidcauth.Route,
) (oidcauth.IssueTransaction, error) {
	capture.begins++
	if capture.transactions == nil {
		return &authIssueCaptureUnit{capture: capture}, nil
	}
	unit, err := capture.transactions.BeginIssue(ctx, route)
	if unit == nil {
		return nil, err
	}
	return &authIssueCaptureUnit{capture: capture, IssueTransaction: unit}, err
}

type authIssueCaptureUnit struct {
	oidcauth.IssueTransaction
	capture *authIssueCaptureTransactions
}

func (unit *authIssueCaptureUnit) Issue(ctx context.Context, command oidcauth.IssueCommand) (oidcauth.Issued, error) {
	unit.capture.command = command
	if unit.IssueTransaction == nil {
		return oidcauth.Issued{}, errors.New("synthetic command capture")
	}
	return unit.IssueTransaction.Issue(ctx, command)
}

func (unit *authIssueCaptureUnit) Rollback(ctx context.Context) error {
	if unit.IssueTransaction == nil {
		return nil
	}
	return unit.IssueTransaction.Rollback(ctx)
}
