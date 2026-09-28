//go:build dexbroker && qualification

package dexbroker

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	dexsql "github.com/dexidp/dex/storage/sql"
)

func TestPreparePostgreSQLSchemaForQualificationMapsAndCloses(t *testing.T) {
	options := validPostgreSQLResourceTestOptions(t)
	storage := &qualificationStorage{}
	err := preparePostgreSQLSchemaForQualification(
		t.Context(),
		options,
		componentTestLogger(),
		func(postgres *dexsql.Postgres, logger *slog.Logger) (interface{ Close() error }, error) {
			if logger == nil {
				t.Fatal("migration logger is nil")
			}
			if postgres.Host != "postgres.internal" || postgres.Port != 5432 ||
				postgres.Database != "identity_broker" || postgres.User != "identity_runtime" ||
				postgres.Password != "difficult-password" || postgres.SSL.Mode != postgresVerifyFull ||
				postgres.ConnectionTimeout != 5 || postgres.MaxOpenConns != 8 ||
				postgres.MaxIdleConns != 3 || postgres.ConnMaxLifetime != 1800 {
				t.Fatal("unexpected migration configuration")
			}
			return storage, nil
		},
	)
	if err != nil {
		t.Fatalf("preparePostgreSQLSchemaForQualification() error = %v", err)
	}
	if storage.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", storage.closeCalls)
	}
}

func TestPreparePostgreSQLSchemaForQualificationMapsErrors(t *testing.T) {
	options := validPostgreSQLResourceTestOptions(t)
	if err := preparePostgreSQLSchemaForQualification(
		t.Context(), options, componentTestLogger(), nil,
	); !errors.Is(err, ErrInvalidPostgreSQLResource) {
		t.Fatalf("nil opener error = %v, want %v", err, ErrInvalidPostgreSQLResource)
	}

	privateErr := errors.New("private migration detail")
	storage := &qualificationStorage{}
	err := preparePostgreSQLSchemaForQualification(
		t.Context(), options, componentTestLogger(),
		func(*dexsql.Postgres, *slog.Logger) (interface{ Close() error }, error) {
			return storage, privateErr
		},
	)
	if !errors.Is(err, ErrOpenPostgreSQLResource) || strings.Contains(err.Error(), privateErr.Error()) {
		t.Fatalf("open error = %v, want redacted %v", err, ErrOpenPostgreSQLResource)
	}
	if storage.closeCalls != 1 {
		t.Fatalf("failed open close calls = %d, want 1", storage.closeCalls)
	}

	storage = &qualificationStorage{closeErr: privateErr}
	err = preparePostgreSQLSchemaForQualification(
		t.Context(), options, componentTestLogger(),
		func(*dexsql.Postgres, *slog.Logger) (interface{ Close() error }, error) {
			return storage, nil
		},
	)
	if !errors.Is(err, ErrClosePostgreSQLResource) || strings.Contains(err.Error(), privateErr.Error()) {
		t.Fatalf("close error = %v, want redacted %v", err, ErrClosePostgreSQLResource)
	}
}

type qualificationStorage struct {
	closeCalls int
	closeErr   error
}

func (storage *qualificationStorage) Close() error {
	storage.closeCalls++
	return storage.closeErr
}
