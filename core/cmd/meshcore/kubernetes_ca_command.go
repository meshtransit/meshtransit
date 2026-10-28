package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

// kubernetesCAOperations are the operator's commands on Kubernetes cluster
// CAs (K1a4 §17.6). They run in a worker pod, with the worker's database
// role and custody; every change names --actor and --change-ref in the
// audit trail.
var kubernetesCAOperations = map[string]bool{
	"status": false, "rewrap": true, "rotate-data-key": true, "retire-ca": true,
}

type kubernetesCAArguments struct {
	operation string
	scope     network.Scope
	ca        publicid.ID
	reason    kubeca.Reason
	operator  kubeca.Operator
}

func parseKubernetesCAArguments(args []string) (kubernetesCAArguments, bool) {
	if len(args) == 0 {
		return kubernetesCAArguments{}, false
	}
	changes, known := kubernetesCAOperations[args[0]]
	if !known {
		return kubernetesCAArguments{}, false
	}
	flags := flag.NewFlagSet("kubernetes-ca", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	workspaceID := flags.String("workspace", "", "Workspace ID")
	networkID := flags.String("network", "", "Network ID")
	caID := flags.String("ca", "", "CA ID (retire-ca)")
	reason := flags.String("reason", "", "compromise, emergency or admin (retire-ca)")
	actor := flags.String("actor", "", "who makes the change")
	changeRef := flags.String("change-ref", "", "the change record that allows it")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return kubernetesCAArguments{}, false
	}
	parsedWorkspace, workspaceErr := workspace.ParseID(*workspaceID)
	parsedNetwork, networkErr := network.ParseID(*networkID)
	scope, scopeErr := network.NewScope(parsedWorkspace, parsedNetwork)
	arguments := kubernetesCAArguments{
		operation: args[0], scope: scope, reason: kubeca.Reason(*reason),
		operator: kubeca.Operator{Name: *actor, ChangeRef: *changeRef},
	}
	if workspaceErr != nil || networkErr != nil || scopeErr != nil || !arguments.operator.Valid() ||
		changes == arguments.operator.IsWorker() {
		return kubernetesCAArguments{}, false
	}
	if arguments.operation == "retire-ca" {
		ca, err := publicid.Parse(*caID)
		if err != nil || *reason == "" {
			return kubernetesCAArguments{}, false
		}
		arguments.ca = ca
	} else if *caID != "" || *reason != "" {
		return kubernetesCAArguments{}, false
	}
	return arguments, true
}

// runKubernetesCA runs one operator command on a Network's CAs and prints
// its result as JSON. It never prints key material.
func runKubernetesCA(ctx context.Context, args []string, lookup config.LookupFunc, output,
	errorOutput io.Writer,
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	fail := func(code string, err error) int {
		logger.ErrorContext(ctx, "Kubernetes CA command failed", "error_code", code, "error", err)
		return 1
	}
	arguments, ok := parseKubernetesCAArguments(args)
	if !ok {
		if _, err := io.WriteString(errorOutput, usage); err != nil {
			return 1
		}
		return 2
	}
	processConfig, err := config.Load(lookup)
	if err != nil || processConfig.Storage == nil || processConfig.Storage.PostgreSQL.Worker == nil ||
		processConfig.KubernetesCAWorker == nil {
		return fail("invalid_kubernetes_ca_configuration", err)
	}
	settings := *processConfig.KubernetesCAWorker
	pool, err := openPostgresRolePool(ctx, postgresadapter.PoolRoleWorker, processConfig.Storage.PostgreSQL,
		*processConfig.Storage.PostgreSQL.Worker, processConfig.Dependencies.CheckTimeout)
	if err != nil {
		return fail("postgres_open_failure", err)
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = pool.Shutdown(shutdown)
	}()
	store, err := postgresadapter.NewKubernetesClusterCAStore(pool)
	if err != nil {
		return fail("invalid_kubernetes_ca_configuration", err)
	}
	result, err := kubernetesCAOperation(ctx, arguments, store, settings)
	if err != nil {
		return fail("kubernetes_ca_command_failure", err)
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return fail("kubernetes_ca_output_failure", err)
	}
	return 0
}

func kubernetesCAOperation(ctx context.Context, arguments kubernetesCAArguments,
	store *postgresadapter.KubernetesClusterCAStore, settings config.KubernetesCAWorkerConfig,
) (any, error) {
	installation, scope := settings.DeploymentID, arguments.scope
	if arguments.operation == "status" {
		read, err := store.Read(ctx, installation, scope)
		if err != nil {
			return nil, err
		}
		return kubernetesCAStatus(read), nil
	}
	if arguments.operation == "retire-ca" {
		// A worker pass may hold the Network for a moment: try a few times.
		var err error
		for attempt := 0; attempt < 10; attempt++ {
			err = lifecycle.RetireCA(ctx, store, installation, scope, arguments.ca, arguments.reason,
				arguments.operator)
			if !errors.Is(err, lifecycle.ErrBusy) {
				break
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
		if err != nil {
			return nil, err
		}
		return map[string]string{"retired": arguments.ca.String()}, nil
	}
	custody, _, err := fileCustodySource(settings)(ctx)
	if err != nil {
		return nil, err
	}
	if arguments.operation == "rewrap" {
		count, err := lifecycle.Rewrap(ctx, store, custody, installation, scope, arguments.operator)
		return map[string]int{"rewrapped": count}, err
	}
	id, err := lifecycle.RotateDataKey(ctx, store, custody, installation, scope, arguments.operator)
	return map[string]string{"data_key_id": id.String()}, err
}

type kubernetesCAStatusCA struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	IssuerID    string `json:"issuer_id,omitempty"`
	State       string `json:"state"`
	Name        string `json:"cluster_dns_name"`
	NotAfter    string `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
	DataKeyID   string `json:"data_key_id"`
}

type kubernetesCAStatusCluster struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Active       bool                   `json:"active"`
	NextActionAt string                 `json:"next_action_at"`
	Failures     int                    `json:"failures"`
	CAs          []kubernetesCAStatusCA `json:"cas"`
}

type kubernetesCAStatusKey struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	Active  bool   `json:"active"`
	Custody string `json:"custody"`
	KeyID   string `json:"key_id"`
}

func kubernetesCAStatus(read kubeca.Network) any {
	keys := make([]kubernetesCAStatusKey, 0, len(read.DataKeys))
	for _, key := range read.DataKeys {
		keys = append(keys, kubernetesCAStatusKey{
			ID: key.ID.String(), Version: key.Version, Active: key.Active,
			Custody: key.Wrapped.Custody, KeyID: key.Wrapped.KeyID,
		})
	}
	clusters := make([]kubernetesCAStatusCluster, 0, len(read.Clusters))
	for _, cluster := range read.Clusters {
		cas := make([]kubernetesCAStatusCA, 0, len(cluster.CAs))
		for _, ca := range cluster.CAs {
			fingerprint := sha256.Sum256(ca.Certificate)
			status := kubernetesCAStatusCA{
				ID: ca.ID.String(), Kind: ca.Kind.String(), State: string(ca.State),
				Name: ca.ClusterDNSName, NotAfter: ca.NotAfter.UTC().Format(time.RFC3339),
				Fingerprint: hex.EncodeToString(fingerprint[:]), DataKeyID: ca.DataKeyID.String(),
			}
			if ca.IssuerID.IsValid() {
				status.IssuerID = ca.IssuerID.String()
			}
			cas = append(cas, status)
		}
		clusters = append(clusters, kubernetesCAStatusCluster{
			ID: cluster.ID.String(), Name: cluster.Name,
			Active: cluster.Active, NextActionAt: cluster.NextActionAt.UTC().Format(time.RFC3339),
			Failures: cluster.Failures, CAs: cas,
		})
	}
	return map[string]any{"data_keys": keys, "clusters": clusters}
}
