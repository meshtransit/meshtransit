package postgres

import (
	"context"
	"database/sql"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/workspace"
)

type fakeRegistrationReplayDatabase struct {
	transaction registrationReplayTransaction
	beginErr    error
	readOnly    bool
}

func (database *fakeRegistrationReplayDatabase) Begin(
	_ context.Context,
	readOnly bool,
) (registrationReplayTransaction, error) {
	database.readOnly = readOnly
	return database.transaction, database.beginErr
}

type fakeRegistrationReplayTransaction struct {
	queries       []string
	arguments     [][]any
	row           registrationReplayRow
	execErr       error
	commitErr     error
	rollbackErr   error
	committed     bool
	rollbackCalls int
}

func (transaction *fakeRegistrationReplayTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) error {
	transaction.record(query, arguments)
	return transaction.execErr
}

func (transaction *fakeRegistrationReplayTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) registrationReplayRow {
	transaction.record(query, arguments)
	return transaction.row
}

func (transaction *fakeRegistrationReplayTransaction) Commit(context.Context) error {
	transaction.committed = transaction.commitErr == nil
	return transaction.commitErr
}

func (transaction *fakeRegistrationReplayTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakeRegistrationReplayTransaction) record(query string, arguments []any) {
	transaction.queries = append(transaction.queries, query)
	transaction.arguments = append(transaction.arguments, append([]any(nil), arguments...))
}

type fakeRegistrationReplayRow struct {
	record registrationReplayRecord
	err    error
}

func (row fakeRegistrationReplayRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	*destinations[0].(*int16) = row.record.intentFormatVersion
	*destinations[1].(*string) = row.record.state
	*destinations[2].(*[]byte) = append([]byte(nil), row.record.requestHash...)
	*destinations[3].(*[]byte) = append([]byte(nil), row.record.machineFingerprint...)
	*destinations[4].(*[]byte) = append([]byte(nil), row.record.requestedNodeKey...)
	*destinations[5].(*string) = row.record.credentialPublicID
	*destinations[6].(*sql.NullString) = row.record.nodePublicID
	*destinations[7].(*sql.NullString) = row.record.completedHostname
	*destinations[8].(*sql.NullString) = row.record.completedDisposition
	*destinations[9].(*sql.NullInt64) = row.record.completedNetworkRevision
	return nil
}

func validRegistrationReplayCommand(t *testing.T) registration.Command {
	t.Helper()

	workspaceID, err := workspace.ParseID("01890f40-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f40-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	registrationID, err := enrollment.ParseRegistrationID("01890f40-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatalf("enrollment.ParseRegistrationID() error = %v", err)
	}
	credentialID, err := enrollment.ParseCredentialID("01890f40-0000-7000-8000-000000000401")
	if err != nil {
		t.Fatalf("enrollment.ParseCredentialID() error = %v", err)
	}
	machineKey, err := node.NewMachineKey(filledRegistrationReplayBytes(0x21))
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey(filledRegistrationReplayBytes(0x22))
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatalf("node.NewRegistrationIdentity() error = %v", err)
	}
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	return registration.Command{
		RegistrationID: registrationID,
		Scope:          scope,
		CredentialID:   credentialID,
		Identity:       identity,
		Hostname:       hostname,
		RecoveryEpoch:  7,
	}
}

func validRegistrationReplayRecord(
	t *testing.T,
	command registration.Command,
) registrationReplayRecord {
	t.Helper()

	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	machineFingerprint := command.Identity.MachineKey().Fingerprint()
	requestedNodeKey := command.Identity.NodeKey().Bytes()
	return registrationReplayRecord{
		intentFormatVersion:      2,
		state:                    "completed",
		requestHash:              append([]byte(nil), requestHash[:]...),
		machineFingerprint:       append([]byte(nil), machineFingerprint[:]...),
		requestedNodeKey:         append([]byte(nil), requestedNodeKey[:]...),
		credentialPublicID:       command.CredentialID.String(),
		nodePublicID:             sql.NullString{String: "01890f40-0000-7000-8000-000000000501", Valid: true},
		completedHostname:        sql.NullString{String: "node-one.example", Valid: true},
		completedDisposition:     sql.NullString{String: "created", Valid: true},
		completedNetworkRevision: sql.NullInt64{Int64: 42, Valid: true},
	}
}

func cloneRegistrationReplayRecord(record registrationReplayRecord) registrationReplayRecord {
	record.requestHash = append([]byte(nil), record.requestHash...)
	record.machineFingerprint = append([]byte(nil), record.machineFingerprint...)
	record.requestedNodeKey = append([]byte(nil), record.requestedNodeKey...)
	return record
}

func filledRegistrationReplayBytes(value byte) [32]byte {
	var bytes [32]byte
	for index := range bytes {
		bytes[index] = value
	}
	return bytes
}
