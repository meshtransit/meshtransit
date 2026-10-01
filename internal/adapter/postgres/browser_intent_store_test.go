package postgres

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/node"
)

func TestBrowserIntentStoreReissuesPersistedTokenAfterRetry(t *testing.T) {
	t.Parallel()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := enrollment.ParseBrowserIntentID("01890f00-0000-7000-8000-000000016301")
	if err != nil {
		t.Fatal(err)
	}
	retryID, err := enrollment.ParseBrowserIntentID("01890f00-0000-7000-8000-000000016302")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := enrollment.NewBrowserIntentKeyID("browser-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := enrollment.NewBrowserIntentKey(keyID, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.NewBrowserIntentKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	var firstRawNonce, retryRawNonce [32]byte
	copy(firstRawNonce[:], bytes.Repeat([]byte{0x72}, 32))
	copy(retryRawNonce[:], bytes.Repeat([]byte{0x73}, 32))
	firstNonce, err := enrollment.ParseBrowserIntentNonce(firstRawNonce)
	if err != nil {
		t.Fatal(err)
	}
	retryNonce, err := enrollment.ParseBrowserIntentNonce(retryRawNonce)
	if err != nil {
		t.Fatal(err)
	}
	want, digest, _, err := keys.Issue(deploymentID, 1, firstID, firstNonce)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := digest.Bytes()
	fakeRow := fakeAccountSessionRow{values: []any{
		firstID.String(), int64(1), firstRawNonce[:], keyID.String(),
		digestBytes[:], "pending", time.Now().Add(5 * time.Minute),
	}}
	transaction := &fakeAccountSessionTransaction{rows: []fakeAccountSessionRow{
		fakeRow,
		{values: []any{int64(1), int64(1), make([]byte, 32)}},
		{values: []any{int64(1)}},
		fakeRow,
	}}
	store, err := newBrowserIntentStore(&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, keys)
	if err != nil {
		t.Fatal(err)
	}
	var machineRaw, nodeRaw [32]byte
	copy(machineRaw[:], bytes.Repeat([]byte{0x74}, 32))
	copy(nodeRaw[:], bytes.Repeat([]byte{0x75}, 32))
	machineKey, err := node.NewMachineKey(machineRaw)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey(nodeRaw)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := node.ParseHostname("browser-device")
	if err != nil {
		t.Fatal(err)
	}
	for _, proposal := range []struct {
		id    enrollment.BrowserIntentID
		nonce enrollment.BrowserIntentNonce
	}{
		{id: firstID, nonce: firstNonce},
		{id: retryID, nonce: retryNonce},
	} {
		got, err := store.Issue(t.Context(), deploymentID, 1, identity,
			hostname, proposal.id, proposal.nonce, time.Now().Add(5*time.Minute))
		if err != nil || got.Encoded() != want.Encoded() {
			t.Fatalf("retry changed browser URL token: got=%q err=%v", got.Encoded(), err)
		}
	}
	if transaction.commits != 2 || transaction.rollbacks != 0 || len(transaction.rows) != 0 {
		t.Fatalf("browser intent store commit/rollback = %d/%d", transaction.commits, transaction.rollbacks)
	}

	corrupt := make([]byte, 32)
	copy(corrupt, digestBytes[:])
	corrupt[0] ^= 0xff
	badTransaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{
		firstID.String(), int64(1), firstRawNonce[:], keyID.String(),
		corrupt, "pending", time.Now().Add(5 * time.Minute),
	}}}
	badStore, err := newBrowserIntentStore(&fakeAccountSessionDatabase{transaction: badTransaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, keys)
	if err != nil {
		t.Fatal(err)
	}
	_, err = badStore.Issue(t.Context(), deploymentID, 1, identity,
		hostname, retryID, retryNonce, time.Now().Add(5*time.Minute))
	if !errors.Is(err, ErrBrowserIntentIssueEvidence) || badTransaction.commits != 0 ||
		badTransaction.rollbacks != 1 {
		t.Fatalf("corrupt persisted digest accepted: err=%v commit/rollback=%d/%d",
			err, badTransaction.commits, badTransaction.rollbacks)
	}

	readTransaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{
		firstID.String(), "pending", (*string)(nil), time.Now().Add(5 * time.Minute),
	}}}
	readStore, err := newBrowserIntentStore(&fakeAccountSessionDatabase{transaction: readTransaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, keys)
	if err != nil {
		t.Fatal(err)
	}
	followup, found, err := readStore.ReadFollowup(t.Context(), deploymentID, 1,
		identity, hostname, want.Encoded())
	if err != nil || !found || followup.IntentID != firstID || followup.State != "pending" ||
		followup.PendingRegistrationID.IsValid() || readTransaction.commits != 1 {
		t.Fatalf("ReadFollowup() = (%+v, %v, %v), commits=%d",
			followup, found, err, readTransaction.commits)
	}
	missingTransaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{err: pgx.ErrNoRows}}
	missingStore, err := newBrowserIntentStore(&fakeAccountSessionDatabase{transaction: missingTransaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, keys)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err = missingStore.ReadFollowup(t.Context(), deploymentID, 1,
		identity, hostname, want.Encoded())
	if err != nil || found || missingTransaction.commits != 1 {
		t.Fatalf("missing followup = (found=%v, error=%v), commits=%d",
			found, err, missingTransaction.commits)
	}
	sessionKeyID, err := accountsession.NewDigestKeyID("session-v1")
	if err != nil {
		t.Fatal(err)
	}
	var sessionBytes [32]byte
	copy(sessionBytes[:], bytes.Repeat([]byte{0x81}, 32))
	sessionDigest, err := accountsession.NewDigest(sessionKeyID, sessionBytes)
	if err != nil {
		t.Fatal(err)
	}
	landingTransaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{
		firstID.String(), "pending", "browser-device", time.Now().Add(5 * time.Minute),
	}}}
	landingStore, err := newBrowserIntentStore(&fakeAccountSessionDatabase{transaction: landingTransaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, keys)
	if err != nil {
		t.Fatal(err)
	}
	landing, found, err := landingStore.ReadLanding(t.Context(), deploymentID, 1,
		sessionDigest, want.Encoded())
	if err != nil || !found || landing.IntentID != firstID ||
		landing.Hostname != "browser-device" || !landing.IsValid() ||
		landingTransaction.commits != 1 {
		t.Fatalf("ReadLanding() = (%+v, %v, %v), commits=%d",
			landing, found, err, landingTransaction.commits)
	}
	missingLandingTransaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{err: pgx.ErrNoRows}}
	missingLandingStore, err := newBrowserIntentStore(
		&fakeAccountSessionDatabase{transaction: missingLandingTransaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, keys)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err = missingLandingStore.ReadLanding(t.Context(), deploymentID, 1,
		sessionDigest, want.Encoded())
	if err != nil || found || missingLandingTransaction.commits != 1 {
		t.Fatalf("missing landing = (found=%v, error=%v), commits=%d",
			found, err, missingLandingTransaction.commits)
	}
}
