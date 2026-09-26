//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
	dexsql "github.com/dexidp/dex/storage/sql"
	"github.com/meshtransit/meshtransit/internal/config"
)

func TestOpenPostgreSQLResourceMapsExplicitRuntimePolicy(t *testing.T) {
	options := validPostgreSQLResourceTestOptions(t)
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	var captured *dexsql.Postgres
	resource, err := openPostgreSQLResource(
		t.Context(),
		options,
		componentTestLogger(),
		func(
			ctx context.Context,
			postgres *dexsql.Postgres,
			_ *slog.Logger,
		) (dexsql.PreparedPostgresStorage, error) {
			if ctx == nil || ctx.Err() != nil {
				t.Fatal("opener received an invalid context")
			}
			capturedConfig := *postgres
			captured = &capturedConfig
			return serverStorage, nil
		},
	)
	if err != nil {
		t.Fatalf("openPostgreSQLResource() error = %v", err)
	}
	t.Cleanup(func() { _ = resource.Shutdown(context.Background()) })
	if captured == nil {
		t.Fatal("opener did not receive configuration")
	}
	if captured.Host != "postgres.internal" || captured.Port != 5432 ||
		captured.Database != "identity_broker" || captured.User != "identity_runtime" {
		t.Fatal("opener received unexpected connection identity")
	}
	if captured.Password != "difficult-password" {
		t.Fatal("opener did not receive the credential file contents")
	}
	if captured.ConnectionTimeout != 5 || captured.MaxOpenConns != 8 ||
		captured.MaxIdleConns != 3 || captured.ConnMaxLifetime != 1800 {
		t.Fatal("opener received unexpected pool bounds")
	}
	if captured.SSL.Mode != postgresVerifyFull || captured.SSL.CAFile == "" ||
		captured.SSL.CertFile != "" || captured.SSL.KeyFile != "" {
		t.Fatal("opener received unexpected TLS policy")
	}
}

func TestPostgreSQLResourceCheckRedactsDependencyFailure(t *testing.T) {
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	serverStorage.check = func(context.Context) error {
		return errors.New("private-database-detail")
	}
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	err := resource.Check(t.Context())
	if !errors.Is(err, ErrCheckPostgreSQLResource) {
		t.Fatalf("Check() error = %v, want %v", err, ErrCheckPostgreSQLResource)
	}
	if strings.Contains(err.Error(), "private-database-detail") {
		t.Fatalf("Check() exposed dependency detail: %v", err)
	}
}

func TestPostgreSQLResourceShutdownJoinsChecksAndClosesOnce(t *testing.T) {
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	entered := make(chan struct{})
	release := make(chan struct{})
	serverStorage.check = func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	checkResult := make(chan error, 1)
	go func() { checkResult <- resource.Check(context.Background()) }()
	waitForComponentChannel(t, entered, "postgres check entry")

	timeoutCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := resource.Shutdown(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Shutdown() error = %v, want deadline", err)
	}
	if got := serverStorage.closeCalls.Load(); got != 0 {
		t.Fatalf("close calls while check active = %d, want 0", got)
	}
	if err := resource.Check(t.Context()); !errors.Is(err, ErrCheckPostgreSQLResource) {
		t.Fatalf("Check() after shutdown began error = %v", err)
	}
	close(release)
	if err := <-checkResult; err != nil {
		t.Fatalf("admitted Check() error = %v", err)
	}
	if err := resource.Shutdown(t.Context()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
	if err := resource.Shutdown(t.Context()); err != nil {
		t.Fatalf("third Shutdown() error = %v", err)
	}
	if got := serverStorage.closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

func TestPostgreSQLResourceCloseFailureIsStableAndRedacted(t *testing.T) {
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	serverStorage.closeErr = errors.New("private-close-detail")
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	for attempt := 0; attempt < 2; attempt++ {
		err := resource.Shutdown(t.Context())
		if !errors.Is(err, ErrClosePostgreSQLResource) {
			t.Fatalf("Shutdown() error = %v, want %v", err, ErrClosePostgreSQLResource)
		}
		if strings.Contains(err.Error(), "private-close-detail") {
			t.Fatalf("Shutdown() exposed close detail: %v", err)
		}
	}
	if got := serverStorage.closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

func TestPostgreSQLResourceRejectsUnsafeOptionsBeforeOpening(t *testing.T) {
	valid := validPostgreSQLResourceTestOptions(t)
	tests := []struct {
		name   string
		mutate func(*PostgreSQLResourceOptions)
	}{
		{name: "empty host", mutate: func(options *PostgreSQLResourceOptions) { options.Address = ":5432" }},
		{name: "invalid port", mutate: func(options *PostgreSQLResourceOptions) { options.Address = "postgres.internal:0" }},
		{name: "empty database", mutate: func(options *PostgreSQLResourceOptions) { options.Database = "" }},
		{name: "empty user", mutate: func(options *PostgreSQLResourceOptions) { options.User = "" }},
		{name: "zero open", mutate: func(options *PostgreSQLResourceOptions) { options.MaxOpenConnections = 0 }},
		{name: "idle over open", mutate: func(options *PostgreSQLResourceOptions) { options.MaxIdleConnections = 9 }},
		{name: "fractional timeout", mutate: func(options *PostgreSQLResourceOptions) { options.ConnectTimeout = 1500 * time.Millisecond }},
		{name: "short lifetime", mutate: func(options *PostgreSQLResourceOptions) { options.MaxConnectionLifetime = time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			called := false
			_, err := openPostgreSQLResource(
				t.Context(),
				options,
				componentTestLogger(),
				func(context.Context, *dexsql.Postgres, *slog.Logger) (dexsql.PreparedPostgresStorage, error) {
					called = true
					return newPostgreSQLResourceTestStorage(componentTestLogger()), nil
				},
			)
			if !errors.Is(err, ErrInvalidPostgreSQLResource) {
				t.Fatalf("openPostgreSQLResource() error = %v, want %v", err, ErrInvalidPostgreSQLResource)
			}
			if called {
				t.Fatal("invalid options reached opener")
			}
		})
	}
}

func TestPostgreSQLResourceFormattingAndJSONAreRedacted(t *testing.T) {
	options := validPostgreSQLResourceTestOptions(t)
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	formatted := fmt.Sprintf("%v %#v %v %#v", options, options, resource, resource)
	for _, private := range []string{"postgres.internal", "identity_runtime", "difficult-password"} {
		if strings.Contains(formatted, private) {
			t.Fatalf("formatting exposed private value %q", private)
		}
	}
	if !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("formatting was not redacted: %q", formatted)
	}
	if _, err := json.Marshal(options); !errors.Is(err, ErrInvalidPostgreSQLResource) {
		t.Fatalf("json.Marshal(options) error = %v", err)
	}
	if _, err := json.Marshal(resource); !errors.Is(err, ErrInvalidPostgreSQLResource) {
		t.Fatalf("json.Marshal(resource) error = %v", err)
	}
}

func validPostgreSQLResourceTestOptions(t *testing.T) PostgreSQLResourceOptions {
	t.Helper()
	directory := t.TempDir()
	passwordPath := filepath.Join(directory, "password")
	caPath := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(passwordPath, []byte("difficult-password\n"), 0o600); err != nil {
		t.Fatalf("write password: %v", err)
	}
	if err := os.WriteFile(caPath, []byte("test-ca-bundle"), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	passwordFile, err := config.NewSecretFile(passwordPath)
	if err != nil {
		t.Fatalf("NewSecretFile() error = %v", err)
	}
	caFile, err := config.NewTrustFile(caPath)
	if err != nil {
		t.Fatalf("NewTrustFile() error = %v", err)
	}
	return PostgreSQLResourceOptions{
		Address:               "postgres.internal:5432",
		Database:              "identity_broker",
		User:                  "identity_runtime",
		PasswordFile:          passwordFile,
		CAFile:                caFile,
		MaxOpenConnections:    8,
		MaxIdleConnections:    3,
		ConnectTimeout:        5 * time.Second,
		MaxConnectionLifetime: 30 * time.Minute,
	}
}

func openPostgreSQLResourceTestDouble(
	t *testing.T,
	serverStorage *postgreSQLResourceTestStorage,
) *PostgreSQLResource {
	t.Helper()
	resource, err := openPostgreSQLResource(
		t.Context(),
		validPostgreSQLResourceTestOptions(t),
		componentTestLogger(),
		func(context.Context, *dexsql.Postgres, *slog.Logger) (dexsql.PreparedPostgresStorage, error) {
			return serverStorage, nil
		},
	)
	if err != nil {
		t.Fatalf("openPostgreSQLResource() error = %v", err)
	}
	return resource
}

type postgreSQLResourceTestStorage struct {
	storage.Storage
	check       func(context.Context) error
	closeErr    error
	closeCalls  atomic.Int64
	closeOnce   sync.Once
	closeResult error
}

func newPostgreSQLResourceTestStorage(logger *slog.Logger) *postgreSQLResourceTestStorage {
	return &postgreSQLResourceTestStorage{Storage: memory.New(logger)}
}

func (serverStorage *postgreSQLResourceTestStorage) CheckPreparedSchema(ctx context.Context) error {
	if serverStorage.check != nil {
		return serverStorage.check(ctx)
	}
	return ctx.Err()
}

func (serverStorage *postgreSQLResourceTestStorage) Close() error {
	serverStorage.closeCalls.Add(1)
	serverStorage.closeOnce.Do(func() {
		serverStorage.closeResult = errors.Join(serverStorage.Storage.Close(), serverStorage.closeErr)
	})
	return serverStorage.closeResult
}
