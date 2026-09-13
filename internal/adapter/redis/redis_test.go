package redis

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9/maintnotifications"

	"github.com/meshtransit/meshtransit/internal/app"
)

func TestBuildClientOptionsAppliesSecurityAndPoolBounds(t *testing.T) {
	t.Parallel()

	clientOptions, err := buildClientOptions(Options{
		Address:        "cache.internal:6379",
		Username:       "meshcore",
		PoolSize:       19,
		RequestTimeout: 2 * time.Second,
	}, "credential", testCAPEM(t))
	if err != nil {
		t.Fatalf("buildClientOptions() error = %v", err)
	}

	if clientOptions.Addr != "cache.internal:6379" || clientOptions.Username != "meshcore" {
		t.Fatalf("endpoint identity = (%q, %q), want (cache.internal:6379, meshcore)", clientOptions.Addr, clientOptions.Username)
	}
	if clientOptions.TLSConfig == nil || clientOptions.TLSConfig.ServerName != "cache.internal" {
		t.Fatal("TLS server identity was not configured")
	}
	if clientOptions.TLSConfig.MinVersion == 0 {
		t.Fatal("TLS minimum was not configured")
	}
	if clientOptions.MaxRetries != -1 || clientOptions.DialerRetries != 1 {
		t.Fatalf("retry controls = (%d, %d), want (-1, 1)", clientOptions.MaxRetries, clientOptions.DialerRetries)
	}
	if !clientOptions.ContextTimeoutEnabled {
		t.Fatal("context timeouts are disabled")
	}
	if !clientOptions.DisableIdentity {
		t.Fatal("unsolicited client identity command is enabled")
	}
	if clientOptions.PoolSize != 19 || clientOptions.MaxActiveConns != 19 || clientOptions.MaxConcurrentDials != 2 {
		t.Fatalf("pool bounds = (%d, %d, %d), want (19, 19, 2)", clientOptions.PoolSize, clientOptions.MaxActiveConns, clientOptions.MaxConcurrentDials)
	}
	if clientOptions.MaintNotificationsConfig == nil || clientOptions.MaintNotificationsConfig.Mode != maintnotifications.ModeDisabled {
		t.Fatal("maintenance notifications must be explicitly disabled")
	}
}

func TestBuildClientOptionsRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()

	valid := Options{
		Address:        "cache.internal:6379",
		Username:       "meshcore",
		PoolSize:       10,
		RequestTimeout: time.Second,
	}
	tests := []struct {
		name     string
		options  Options
		password string
		caPEM    []byte
	}{
		{name: "missing host", options: withAddress(valid, ":6379"), password: "credential", caPEM: testCAPEM(t)},
		{name: "zero pool", options: withPoolSize(valid, 0), password: "credential", caPEM: testCAPEM(t)},
		{name: "missing password", options: valid, caPEM: testCAPEM(t)},
		{name: "invalid ca", options: valid, password: "credential", caPEM: []byte("not a certificate")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := buildClientOptions(test.options, test.password, test.caPEM); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("buildClientOptions() error = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestClientImplementsCheckAndIdempotentClose(t *testing.T) {
	t.Parallel()

	checkErr := errors.New("redis unavailable")
	closeErr := errors.New("close failed")
	var gotContext context.Context
	closeCalls := 0
	client := &Client{
		ping: func(ctx context.Context) error {
			gotContext = ctx
			return checkErr
		},
		close: func() error {
			closeCalls++
			return closeErr
		},
	}
	ctx := t.Context()
	if err := client.Check(ctx); !errors.Is(err, checkErr) {
		t.Fatalf("Check() error = %v, want check error", err)
	}
	if gotContext != ctx {
		t.Fatal("Check() did not propagate context")
	}
	if client.Component() != app.ComponentRedis {
		t.Fatalf("Component() = %s, want redis", client.Component())
	}
	if err := client.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want close error", err)
	}
	if err := client.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("second Close() error = %v, want stable close error", err)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

func TestClientCheckReturnsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	client := &Client{
		ping: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		close: func() error { return nil },
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check() error = %v, want context canceled", err)
	}
}

func TestClientConcurrentCloseRunsOnce(t *testing.T) {
	t.Parallel()

	var closeCalls atomic.Int32
	client := &Client{
		ping: func(context.Context) error { return nil },
		close: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	start := make(chan struct{})
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(func() {
			<-start
			if err := client.Close(); err != nil {
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

func withAddress(options Options, address string) Options {
	options.Address = address
	return options
}

func withPoolSize(options Options, poolSize int) Options {
	options.PoolSize = poolSize
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
