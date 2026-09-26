package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestComposePrivateIdentityFactoryOwnsCompletePrivateGraph(t *testing.T) {
	t.Parallel()
	fixture, options, dependencies := privateIdentityFactoryFixture(t, postgresadapter.PoolRoleRuntime)
	factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, options, dependencies)
	if err != nil || factory == nil {
		t.Fatal("production adapters did not compose", err)
	}
	t.Cleanup(factory.Close)
	root := factory.identity
	completeServices := root != nil && root.start != nil && root.callback != nil && root.sessions != nil && root.logout != nil
	completeHTTP := root != nil && root.login != nil && root.management != nil && root.metrics != nil
	if !completeServices || !completeHTTP || factory.discovery == nil || factory.provider == nil {
		t.Fatal("factory released an incomplete graph")
	}
	if _, err := root.metrics.Gather(); err != nil {
		t.Fatal("private collector registry is invalid", err)
	}
	// Request effects are not tested against these lazy, reserved dependencies.
	// Construction must not invoke the controlled fixture's alternate ports.
	if fixture.clockReads != 0 || len(fixture.effects) != 0 {
		t.Fatal("factory substituted the application's fixture effects")
	}
	factory.Close()
	factory.Close()
	// Another construction has independent client/registry owners. This does not
	// qualify later requests against the borrowed dependencies or their lifecycle.
	other, err := composePrivateIdentityFactory(t.Context(), fixture.keys, options, dependencies)
	if err != nil || other == nil || other.identity.metrics == root.metrics {
		t.Fatal("repeat construction failed or shared metrics", err)
	}
	t.Cleanup(other.Close)
}

func TestComposePrivateIdentityFactoryRejectsIncompleteAndUnsafeInputs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*privateIdentityFixture, *privateIdentityFactoryOptions, *privateIdentityFactoryDependencies)
	}{
		{name: "absent keys", change: func(f *privateIdentityFixture, _ *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			f.keys = nil
		}},
		{name: "absent runtime pool", change: func(_ *privateIdentityFixture, _ *privateIdentityFactoryOptions,
			d *privateIdentityFactoryDependencies) {
			d.Runtime = nil
		}},
		{name: "zero runtime pool", change: func(_ *privateIdentityFixture, _ *privateIdentityFactoryOptions,
			d *privateIdentityFactoryDependencies) {
			d.Runtime = &postgresadapter.Pool{}
		}},
		{name: "absent redis", change: func(_ *privateIdentityFixture, _ *privateIdentityFactoryOptions,
			d *privateIdentityFactoryDependencies) {
			d.Redis = nil
		}},
		{name: "zero redis", change: func(_ *privateIdentityFixture, _ *privateIdentityFactoryOptions,
			d *privateIdentityFactoryDependencies) {
			d.Redis = &redisadapter.Client{}
		}},
		{name: "absent logger", change: func(_ *privateIdentityFixture, _ *privateIdentityFactoryOptions,
			d *privateIdentityFactoryDependencies) {
			d.Logger = nil
		}},
		{name: "absent confidential secret", change: func(_ *privateIdentityFixture, _ *privateIdentityFactoryOptions,
			d *privateIdentityFactoryDependencies) {
			d.Secret = oidc.BasicSecret{}
		}},
		{name: "zero route", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Application.Route = oidcauth.Route{}
		}},
		{name: "foreign origin", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Application.Origin = "https://foreign.example.test"
		}},
		{name: "default discovery timeout", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Discovery.Timeout = 0
		}},
		{name: "default metadata bound", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Discovery.MaxMetadataBytes = 0
		}},
		{name: "oversize metadata", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Discovery.MaxMetadataBytes = 256*1024 + 1
		}},
		{name: "discovery outside start window", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Discovery.Timeout = o.Application.Start.RequestTimeout + time.Nanosecond
		}},
		{name: "zero token timeout", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Token.Timeout = 0
		}},
		{name: "token outside callback window", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Token.Timeout = o.Application.Callback.RequestTimeout + time.Nanosecond
		}},
		{name: "fractional token age", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Token.MaxTokenAge += time.Nanosecond
		}},
		{name: "negative skew", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Token.ClockSkew = -time.Second
		}},
		{name: "disabled sql lock from rounding", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Application.Management.RequestTimeout = 2*time.Millisecond - time.Nanosecond
		}},
		{name: "late graph validation failure", change: func(_ *privateIdentityFixture, o *privateIdentityFactoryOptions,
			_ *privateIdentityFactoryDependencies) {
			o.Application.Browser.MaxConcurrent = 0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture, options, dependencies := privateIdentityFactoryFixture(t, postgresadapter.PoolRoleRuntime)
			test.change(fixture, &options, &dependencies)
			factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, options, dependencies)
			if factory != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) {
				t.Fatal("invalid production binding released a graph", err)
			}
			if err.Error() != errInvalidPrivateIdentityComposition.Error() {
				t.Fatal("factory reflected dependency or profile details")
			}
		})
	}
}

func TestComposePrivateIdentityFactoryRejectsWorkerAndCancellation(t *testing.T) {
	t.Parallel()
	fixture, options, dependencies := privateIdentityFactoryFixture(t, postgresadapter.PoolRoleWorker)
	factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, options, dependencies)
	if factory != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) {
		t.Fatal("worker pool gained runtime login capability")
	}
	fixture, options, dependencies = privateIdentityFactoryFixture(t, postgresadapter.PoolRoleRuntime)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "absent context"}, {name: "canceled context", ctx: ctx},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory, err := composePrivateIdentityFactory(test.ctx, fixture.keys, options, dependencies)
			if factory != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) {
				t.Fatal("construction detached from its caller")
			}
		})
	}
	var absent *privateIdentityFactory
	absent.Close()
}

func TestPrivateIdentityDatabaseWindowNeverDisablesSQLTimeouts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                          string
		window, statement, lock, idle time.Duration
		invalid                       bool
	}{
		{name: "negative", window: -time.Second, invalid: true},
		{name: "zero", invalid: true},
		{name: "below lock resolution", window: 2*time.Millisecond - time.Nanosecond, invalid: true},
		{name: "minimum", window: 2 * time.Millisecond, statement: 2 * time.Millisecond,
			lock: time.Millisecond, idle: 2 * time.Millisecond},
		{name: "round down", window: 3500 * time.Microsecond, statement: 3 * time.Millisecond,
			lock: time.Millisecond, idle: 3 * time.Millisecond},
		{name: "maximum caps", window: time.Hour, statement: 5 * time.Second,
			lock: 2 * time.Second, idle: 10 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, err := privateIdentityDatabaseWindow(test.window)
			if test.invalid {
				if options != (postgresadapter.AuthTransactionOptions{}) || !errors.Is(err, errInvalidPrivateIdentityComposition) {
					t.Fatal("invalid window became an unbounded SQL timeout")
				}
				return
			}
			expected := postgresadapter.AuthTransactionOptions{
				StatementTimeout: test.statement, LockTimeout: test.lock, IdleTimeout: test.idle,
			}
			if err != nil || options != expected {
				t.Fatal("SQL caps exceed their request window or lose precision", err)
			}
		})
	}
}

func TestPrivateIdentityFactoryDiagnosticsAreRedacted(t *testing.T) {
	t.Parallel()
	fixture, options, dependencies := privateIdentityFactoryFixture(t, postgresadapter.PoolRoleRuntime)
	factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, options, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(factory.Close)
	for _, value := range []any{options, dependencies, factory} {
		if fmt.Sprint(value) != "[REDACTED]" || fmt.Sprintf("%#v", value) != "[REDACTED]" {
			t.Fatal("factory diagnostics disclosed owned or borrowed input")
		}
		if body, err := json.Marshal(value); body != nil || err == nil {
			t.Fatal("factory diagnostics serialize configuration or credentials")
		}
		valuer, ok := value.(slog.LogValuer)
		if !ok || valuer.LogValue().String() != "[REDACTED]" {
			t.Fatal("factory structured diagnostics disclose configuration")
		}
	}
}

func FuzzPrivateIdentityDatabaseWindow(f *testing.F) {
	for _, seed := range []int64{-1, 0, int64(time.Millisecond), int64(2 * time.Millisecond), int64(time.Hour)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input int64) {
		window := time.Duration(input)
		options, err := privateIdentityDatabaseWindow(window)
		if window < 2*time.Millisecond {
			if options != (postgresadapter.AuthTransactionOptions{}) || !errors.Is(err, errInvalidPrivateIdentityComposition) {
				t.Fatal("arbitrary window selected disabled SQL limits")
			}
			return
		}
		if err != nil {
			t.Fatal("valid window rejected", err)
		}
		for _, bound := range []time.Duration{options.StatementTimeout, options.LockTimeout, options.IdleTimeout} {
			if bound < time.Millisecond || bound%time.Millisecond != 0 || bound > window {
				t.Fatal("SQL timeout is disabled, fractional or outside request deadline")
			}
		}
		validStatement := options.StatementTimeout <= 5*time.Second && options.LockTimeout <= options.StatementTimeout/2
		if !validStatement || options.LockTimeout > 2*time.Second || options.IdleTimeout > 10*time.Second {
			t.Fatal("SQL caps widened existing production limits")
		}
	})
}

func privateIdentityFactoryFixture(
	t *testing.T,
	role postgresadapter.PoolRole,
) (*privateIdentityFixture, privateIdentityFactoryOptions, privateIdentityFactoryDependencies) {
	t.Helper()
	fixture := newPrivateIdentityFixture(t)
	processConfig, _ := managementProcessConfigFixture(t, false)
	pool, err := openPostgresRolePool(t.Context(), role, processConfig.Storage.PostgreSQL,
		*processConfig.Storage.PostgreSQL.Runtime, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		if err := pool.Shutdown(ctx); err != nil {
			t.Error("lazy pool cleanup", err)
		}
	})
	cacheConfig := processConfig.Storage.Redis
	cache, err := redisadapter.Open(t.Context(), redisadapter.Options{
		Address: cacheConfig.Address, Username: cacheConfig.Username,
		PasswordFile: cacheConfig.PasswordFile, CAFile: cacheConfig.CAFile,
		PoolSize: cacheConfig.PoolSize, RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		if err := cache.Shutdown(ctx); err != nil {
			t.Error("lazy cache cleanup", err)
		}
	})
	secret, err := oidc.NewBasicSecret(strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	options := privateIdentityFactoryOptions{
		Application: fixture.options, Discovery: oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
		Token: privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
	}
	dependencies := privateIdentityFactoryDependencies{
		Runtime: pool, Redis: cache, Secret: secret, Logger: discardCompositionLogger(),
	}
	return fixture, options, dependencies
}
