package postgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/platform/app"
)

func TestBuildPoolConfigAppliesSecurityAndPoolBounds(t *testing.T) {
	t.Parallel()

	poolConfig, err := buildPoolConfig(Options{
		Role:           PoolRoleRuntime,
		Address:        "database.internal:5432",
		Database:       "meshtransit",
		User:           "meshcore",
		MaxConnections: 17,
		ConnectTimeout: 2 * time.Second,
	}, "credential", testCAPEM(t))
	if err != nil {
		t.Fatalf("buildPoolConfig() error = %v", err)
	}

	if poolConfig.ConnConfig.Host != "database.internal" || poolConfig.ConnConfig.Port != 5432 {
		t.Fatalf("endpoint = %s:%d, want database.internal:5432", poolConfig.ConnConfig.Host, poolConfig.ConnConfig.Port)
	}
	if poolConfig.ConnConfig.Database != "meshtransit" || poolConfig.ConnConfig.User != "meshcore" {
		t.Fatalf("identity = (%q, %q), want (meshtransit, meshcore)", poolConfig.ConnConfig.Database, poolConfig.ConnConfig.User)
	}
	if poolConfig.ConnConfig.TLSConfig == nil || poolConfig.ConnConfig.TLSConfig.ServerName != "database.internal" {
		t.Fatal("TLS server identity was not configured")
	}
	if poolConfig.ConnConfig.TLSConfig.MinVersion == 0 || poolConfig.ConnConfig.Fallbacks != nil {
		t.Fatal("TLS minimum or plaintext fallback invariant was not applied")
	}
	if poolConfig.ConnConfig.RequireAuth != "scram-sha-256" {
		t.Fatalf("RequireAuth = %q, want scram-sha-256", poolConfig.ConnConfig.RequireAuth)
	}
	if poolConfig.ConnConfig.ValidateConnect == nil {
		t.Fatal("new connections do not require a read-write primary")
	}
	if poolConfig.MaxConns != 17 || poolConfig.MinConns != 0 || poolConfig.MinIdleConns != 0 {
		t.Fatalf("pool bounds = (%d, %d, %d), want (17, 0, 0)", poolConfig.MaxConns, poolConfig.MinConns, poolConfig.MinIdleConns)
	}
	if poolConfig.ConnConfig.ConnectTimeout != 2*time.Second || poolConfig.PingTimeout != 2*time.Second {
		t.Fatal("connect and ping timeouts were not bounded")
	}
	if got := poolConfig.ConnConfig.RuntimeParams["application_name"]; got != "meshcore-runtime" {
		t.Fatalf("application_name = %q, want meshcore-runtime", got)
	}
}

func TestBuildPoolConfigRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()

	valid := Options{
		Role:           PoolRoleRuntime,
		Address:        "database.internal:5432",
		Database:       "meshtransit",
		User:           "meshcore",
		MaxConnections: 10,
		ConnectTimeout: time.Second,
	}
	tests := []struct {
		name     string
		options  Options
		password string
		caPEM    []byte
	}{
		{name: "missing host", options: withAddress(valid, ":5432"), password: "credential", caPEM: testCAPEM(t)},
		{name: "missing pool role", options: withPoolRole(valid, ""), password: "credential", caPEM: testCAPEM(t)},
		{name: "zero pool", options: withMaxConnections(valid, 0), password: "credential", caPEM: testCAPEM(t)},
		{name: "missing password", options: valid, caPEM: testCAPEM(t)},
		{name: "invalid ca", options: valid, password: "credential", caPEM: []byte("not a certificate")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := buildPoolConfig(test.options, test.password, test.caPEM); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("buildPoolConfig() error = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestOpenRejectsInvalidRoleBeforeReadingCredentialFiles(t *testing.T) {
	t.Parallel()

	if _, err := Open(t.Context(), Options{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("Open() error = %v, want ErrInvalidOptions", err)
	}
}

func TestPoolImplementsCheckAndIdempotentClose(t *testing.T) {
	t.Parallel()

	checkErr := errors.New("postgres unavailable")
	var gotContext context.Context
	closeCalls := 0
	pool := &Pool{
		ping: func(ctx context.Context) error {
			gotContext = ctx
			return checkErr
		},
		checkSchema: func(context.Context) error {
			t.Fatal("schema compatibility checked after failed ping")
			return nil
		},
		checkWritable: func(context.Context) error {
			t.Fatal("writable primary checked after failed ping")
			return nil
		},
		acquired: func() int32 { return 0 },
		reset:    func() {},
		close:    func() { closeCalls++ },
	}
	ctx := t.Context()
	if err := pool.Check(ctx); !errors.Is(err, checkErr) {
		t.Fatalf("Check() error = %v, want check error", err)
	}
	if gotContext != ctx {
		t.Fatal("Check() did not propagate context")
	}
	if pool.Component() != app.ComponentPostgreSQL {
		t.Fatalf("Component() = %s, want postgresql", pool.Component())
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

func TestPoolCheckRequiresPingWritablePrimaryAndCompatibleSchema(t *testing.T) {
	t.Parallel()

	var operations []string
	pool := &Pool{
		ping: func(context.Context) error {
			operations = append(operations, "ping")
			return nil
		},
		checkWritable: func(context.Context) error {
			operations = append(operations, "writable")
			return nil
		},
		checkSchema: func(context.Context) error {
			operations = append(operations, "schema")
			return nil
		},
		reset: func() {},
		close: func() {},
	}
	if err := pool.Check(t.Context()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !reflect.DeepEqual(operations, []string{"ping", "writable", "schema"}) {
		t.Fatalf("operations = %v, want [ping writable schema]", operations)
	}
}

func TestPoolCheckResetsConnectionsWhenPrimaryIsNotWritable(t *testing.T) {
	t.Parallel()

	primaryErr := errors.New("read-only server")
	resetCalls := 0
	pool := &Pool{
		ping: func(context.Context) error { return nil },
		checkWritable: func(context.Context) error {
			return primaryErr
		},
		checkSchema: func(context.Context) error {
			t.Fatal("schema compatibility checked on read-only server")
			return nil
		},
		reset: func() { resetCalls++ },
		close: func() {},
	}
	if err := pool.Check(t.Context()); !errors.Is(err, primaryErr) {
		t.Fatalf("Check() error = %v, want primary validation error", err)
	}
	if resetCalls != 1 {
		t.Fatalf("pool reset calls = %d, want 1", resetCalls)
	}
}

func TestPoolCheckReturnsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	pool := &Pool{
		ping: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		checkSchema: func(context.Context) error {
			t.Fatal("schema compatibility checked after canceled ping")
			return nil
		},
		checkWritable: func(context.Context) error {
			t.Fatal("writable primary checked after canceled ping")
			return nil
		},
		reset: func() {},
		close: func() {},
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := pool.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check() error = %v, want context canceled", err)
	}
}

func TestPoolConcurrentCloseRunsOnce(t *testing.T) {
	t.Parallel()

	var closeCalls atomic.Int32
	pool := &Pool{
		ping:        func(context.Context) error { return nil },
		checkSchema: func(context.Context) error { return nil },
		acquired:    func() int32 { return 0 },
		close:       func() { closeCalls.Add(1) },
	}
	start := make(chan struct{})
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(func() {
			<-start
			if err := pool.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
	close(start)
	callers.Wait()
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

func TestPoolShutdownRefusesToWaitForAcquiredConnections(t *testing.T) {
	t.Parallel()

	var acquired atomic.Int32
	acquired.Store(1)
	closeCalls := 0
	pool := &Pool{
		acquired: acquired.Load,
		close:    func() { closeCalls++ },
	}

	if err := pool.Shutdown(t.Context()); !errors.Is(err, ErrPoolInUse) {
		t.Fatalf("Shutdown() error = %v, want ErrPoolInUse", err)
	}
	if closeCalls != 0 {
		t.Fatalf("close calls = %d, want 0 while a connection is acquired", closeCalls)
	}

	acquired.Store(0)
	if err := pool.Shutdown(t.Context()); err != nil {
		t.Fatalf("retry Shutdown() error = %v", err)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1 after the pool became idle", closeCalls)
	}
}

func TestPoolShutdownHonorsCanceledContextBeforeClose(t *testing.T) {
	t.Parallel()

	closeCalls := 0
	pool := &Pool{
		acquired: func() int32 { return 0 },
		close:    func() { closeCalls++ },
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := pool.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown() error = %v, want context canceled", err)
	}
	if closeCalls != 0 {
		t.Fatalf("close calls = %d, want 0 after cancellation", closeCalls)
	}
}

func withAddress(options Options, address string) Options {
	options.Address = address
	return options
}

func withPoolRole(options Options, role PoolRole) Options {
	options.Role = role
	return options
}

func withMaxConnections(options Options, maximum int32) Options {
	options.MaxConnections = maximum
	return options
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
}
