package postgres

import (
	"context"
	"errors"
	"fmt"
)

func readMigrationDatabaseState(
	ctx context.Context,
	transaction migrationTransaction,
) (migrationDatabaseState, error) {
	var migrationTable, compatibilityTable, backfillTable bool
	if err := transaction.QueryRow(ctx, migrationObjectsSQL).Scan(
		&migrationTable,
		&compatibilityTable,
		&backfillTable,
	); err != nil {
		return migrationDatabaseState{}, fmt.Errorf("inspect migration tables: %w", err)
	}
	if !migrationTable && !compatibilityTable && !backfillTable {
		return migrationDatabaseState{}, nil
	}
	if !migrationTable || !compatibilityTable || !backfillTable {
		return migrationDatabaseState{}, ErrMigrationState
	}

	rows, err := transaction.Query(ctx, appliedMigrationsSQL)
	if err != nil {
		return migrationDatabaseState{}, fmt.Errorf("query applied migrations: %w", err)
	}
	defer rows.Close()
	var applied []appliedMigration
	for rows.Next() {
		var migration appliedMigration
		if err := rows.Scan(&migration.version, &migration.checksum, &migration.result); err != nil {
			return migrationDatabaseState{}, fmt.Errorf("scan applied migration: %w", err)
		}
		applied = append(applied, migration)
	}
	if err := rows.Err(); err != nil {
		return migrationDatabaseState{}, fmt.Errorf("iterate applied migrations: %w", err)
	}

	var compatibility schemaCompatibility
	if err := transaction.QueryRow(ctx, migrationCompatibilitySQL).Scan(
		&compatibility.currentVersion,
		&compatibility.minimumReaderGeneration,
		&compatibility.maximumReaderGeneration,
		&compatibility.minimumWriterGeneration,
		&compatibility.maximumWriterGeneration,
		&compatibility.state,
	); err != nil {
		return migrationDatabaseState{}, errors.Join(ErrMigrationState, err)
	}
	return migrationDatabaseState{
		initialized:   true,
		applied:       applied,
		compatibility: compatibility,
	}, nil
}
