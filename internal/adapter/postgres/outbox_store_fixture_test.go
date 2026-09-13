package postgres

import "context"

type fakeOutboxDatabase struct {
	query       string
	arguments   []any
	queryRows   outboxRows
	queryErr    error
	queryRow    outboxRow
	transaction outboxTransaction
	beginErr    error
	readOnly    bool
}

func (database *fakeOutboxDatabase) Query(
	_ context.Context,
	query string,
	arguments ...any,
) (outboxRows, error) {
	database.query = query
	database.arguments = append([]any(nil), arguments...)
	return database.queryRows, database.queryErr
}

func (database *fakeOutboxDatabase) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) outboxRow {
	database.query = query
	database.arguments = append([]any(nil), arguments...)
	return database.queryRow
}

func (database *fakeOutboxDatabase) Begin(
	_ context.Context,
	readOnly bool,
) (outboxTransaction, error) {
	database.readOnly = readOnly
	return database.transaction, database.beginErr
}

type fakeOutboxRows struct {
	scans  []func(...any) error
	index  int
	err    error
	closed bool
}

func (rows *fakeOutboxRows) Next() bool { return rows.index < len(rows.scans) }

func (rows *fakeOutboxRows) Scan(destinations ...any) error {
	scan := rows.scans[rows.index]
	rows.index++
	return scan(destinations...)
}

func (rows *fakeOutboxRows) Err() error { return rows.err }

func (rows *fakeOutboxRows) Close() { rows.closed = true }

type fakeOutboxRow struct {
	scan func(...any) error
}

func (row fakeOutboxRow) Scan(destinations ...any) error {
	if row.scan == nil {
		return nil
	}
	return row.scan(destinations...)
}

type fakeOutboxTransaction struct {
	actions       []string
	queryRow      outboxRow
	execErr       error
	commitErr     error
	rollbackErr   error
	committed     bool
	rollbackCalls int
}

func (transaction *fakeOutboxTransaction) Exec(
	_ context.Context,
	query string,
	_ ...any,
) error {
	transaction.actions = append(transaction.actions, query)
	return transaction.execErr
}

func (transaction *fakeOutboxTransaction) QueryRow(
	_ context.Context,
	query string,
	_ ...any,
) outboxRow {
	transaction.actions = append(transaction.actions, query)
	return transaction.queryRow
}

func (transaction *fakeOutboxTransaction) Commit(context.Context) error {
	transaction.committed = transaction.commitErr == nil
	return transaction.commitErr
}

func (transaction *fakeOutboxTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}
