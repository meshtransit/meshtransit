//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/network"
)

func TestTLSAuthenticatedDependencies(t *testing.T) {
	if os.Getenv("MESHTRANSIT_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_INTEGRATION=1 with file-backed test credentials")
	}

	processConfig, err := config.Load(os.LookupEnv)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if processConfig.Storage == nil {
		t.Fatal("integration role must require storage")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	postgresPool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Address:        processConfig.Storage.PostgreSQL.Address,
		Database:       processConfig.Storage.PostgreSQL.Database,
		User:           processConfig.Storage.PostgreSQL.User,
		PasswordFile:   processConfig.Storage.PostgreSQL.PasswordFile,
		CAFile:         processConfig.Storage.PostgreSQL.CAFile,
		MaxConnections: processConfig.Storage.PostgreSQL.MaxConnections,
		ConnectTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		t.Fatalf("postgres.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := postgresPool.Close(); err != nil {
			t.Errorf("postgres Close() error = %v", err)
		}
	})
	if err := postgresPool.Check(ctx); err != nil {
		t.Fatalf("postgres Check() error = %v", err)
	}

	redisClient, err := redisadapter.Open(ctx, redisadapter.Options{
		Address:        processConfig.Storage.Redis.Address,
		Username:       processConfig.Storage.Redis.Username,
		PasswordFile:   processConfig.Storage.Redis.PasswordFile,
		CAFile:         processConfig.Storage.Redis.CAFile,
		PoolSize:       processConfig.Storage.Redis.PoolSize,
		RequestTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		t.Fatalf("redis.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := redisClient.Close(); err != nil {
			t.Errorf("redis Close() error = %v", err)
		}
	})
	if err := redisClient.Check(ctx); err != nil {
		t.Fatalf("redis Check() error = %v", err)
	}

	wakeup, err := network.NewRevisionAdvanced(
		"01890f00-0000-7000-8000-000000000201",
		42,
	)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	subscription, err := redisClient.SubscribeNetworkRevisionAdvanced(ctx)
	if err != nil {
		t.Fatalf("redis SubscribeNetworkRevisionAdvanced() error = %v", err)
	}
	t.Cleanup(func() {
		if err := subscription.Close(); err != nil {
			t.Errorf("redis revision subscription Close() error = %v", err)
		}
	})
	if err := redisClient.PublishNetworkRevisionAdvanced(ctx, wakeup); err != nil {
		t.Fatalf("redis PublishNetworkRevisionAdvanced() error = %v", err)
	}
	receiveCtx, receiveCancel := context.WithTimeout(ctx, processConfig.Dependencies.CheckTimeout)
	defer receiveCancel()
	receivedWakeup, err := subscription.Receive(receiveCtx)
	if err != nil {
		t.Fatalf("redis revision subscription Receive() error = %v", err)
	}
	if receivedWakeup.NetworkPublicID() != wakeup.NetworkPublicID() ||
		receivedWakeup.Number() != wakeup.Number() {
		t.Fatalf(
			"redis revision wakeup = (%q, %d), want (%q, %d)",
			receivedWakeup.NetworkPublicID(),
			receivedWakeup.Number(),
			wakeup.NetworkPublicID(),
			wakeup.Number(),
		)
	}
}
