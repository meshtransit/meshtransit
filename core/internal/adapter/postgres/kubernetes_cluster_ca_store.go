package postgres

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalidKubernetesClusterCAStore reports unsafe construction or
	// input.
	ErrInvalidKubernetesClusterCAStore = errors.New("invalid postgres Kubernetes cluster CA store")
	// ErrKubernetesClusterCAStore classifies a failed read or change.
	ErrKubernetesClusterCAStore = errors.New("postgres Kubernetes cluster CA store")
	// ErrKubernetesClusterCAStale reports a CA or data key that changed since
	// it was read; nothing of the change was applied.
	ErrKubernetesClusterCAStale = errors.New("postgres Kubernetes cluster CA changed since it was read")
	// ErrKubernetesClusterCABusy reports a Network another worker holds.
	ErrKubernetesClusterCABusy = errors.New("postgres Kubernetes cluster CA Network is busy")
)

const (
	listKubernetesCAWorkSQL        = `SELECT mesh_ops.read_kubernetes_ca_work_v1($1::UUID,$2::INTEGER)::TEXT`
	claimKubernetesCADNSSuffixSQL  = `SELECT mesh_ops.claim_kubernetes_ca_dns_suffix_v1($1::UUID,$2::TEXT)::TEXT`
	readKubernetesCANetworkSQL     = `SELECT mesh_ops.read_kubernetes_ca_network_v1($1::UUID,$2::UUID,$3::UUID)::TEXT`
	lockKubernetesCANetworkSQL     = `SELECT mesh_ops.lock_kubernetes_ca_network_v2($1::UUID,$2::UUID,$3::UUID)::TEXT`
	postponeKubernetesCANetworkSQL = `SELECT mesh_ops.postpone_kubernetes_ca_network_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::TIMESTAMPTZ)::TEXT`
	beatKubernetesCAWorkerSQL = `SELECT mesh_ops.beat_kubernetes_ca_worker_v2(
    $1::UUID,$2::UUID,$3::BOOLEAN,$4::TEXT,$5::TEXT,$6::TEXT[])`

	clusterCAMaximumDue = 256
	// The read holds at most 96 clusters, each with a handful of live CAs
	// of at most 8 KiB, hex encoded.
	clusterCAMaximumNetwork = 8 << 20
	clusterCAMaximumSteps   = 512
	// A change holds the Network's lock only to apply what the worker
	// prepared beforehand: keys are generated, sealed and unwrapped outside
	// any transaction (§17.3).
	clusterCAStatementTimeout = 10 * time.Second
	clusterCALockTimeout      = 2 * time.Second
	clusterCAIdleTimeout      = 10 * time.Second
)

// KubernetesClusterCAStore keeps the CAs of Kubernetes clusters for the
// worker and operator commands (schemas 238, 239): what is due, the
// Networks' data keys, CA changes under each Network's lock with their
// sealed audit events, schedules, the DNS suffix and heartbeats. It never
// sees a key in the clear.
type KubernetesClusterCAStore struct{ database outboxDatabase }

// NewKubernetesClusterCAStore accepts the worker pool only.
func NewKubernetesClusterCAStore(pool *Pool) (*KubernetesClusterCAStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidKubernetesClusterCAStore
	}
	return &KubernetesClusterCAStore{database: pool.outboxDatabase}, nil
}

func (store *KubernetesClusterCAStore) valid(ctx context.Context, installation deployment.ID) bool {
	return ctx != nil && store != nil && store.database != nil && installation.IsValid()
}

func (store *KubernetesClusterCAStore) begin(ctx context.Context) (outboxTransaction, error) {
	transaction, err := store.database.Begin(ctx, false)
	if err != nil || transaction == nil {
		return nil, errors.Join(ErrKubernetesClusterCAStore, err)
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, postgresTimeout(clusterCAStatementTimeout),
		postgresTimeout(clusterCALockTimeout), postgresTimeout(clusterCAIdleTimeout)); err != nil {
		return nil, errors.Join(ErrKubernetesClusterCAStore, err, rollbackOutboxTransaction(transaction))
	}
	return transaction, nil
}

// inTransaction runs work in one transaction and commits it unless work
// fails or says not to.
func (store *KubernetesClusterCAStore) inTransaction(ctx context.Context,
	work func(outboxTransaction) (bool, error),
) (resultErr error) {
	transaction, err := store.begin(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()
	commit, err := work(transaction)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	return nil
}

// queryText runs one statement that returns text in its own transaction.
func (store *KubernetesClusterCAStore) queryText(ctx context.Context, statement string, arguments ...any) (string,
	error,
) {
	var encoded string
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		if err := transaction.QueryRow(ctx, statement, arguments...).Scan(&encoded); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		return true, nil
	})
	return encoded, err
}

// ListDue lists the installation's Networks with a cluster due, earliest
// first.
func (store *KubernetesClusterCAStore) ListDue(ctx context.Context, installation deployment.ID,
	limit int,
) ([]network.Scope, error) {
	if !store.valid(ctx, installation) || limit < 1 || limit > clusterCAMaximumDue {
		return nil, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, listKubernetesCAWorkSQL, installation.String(), limit)
	if err != nil {
		return nil, err
	}
	var record struct {
		Now      time.Time `json:"now"`
		Networks []struct {
			WorkspaceID string `json:"workspace_id"`
			NetworkID   string `json:"network_id"`
		} `json:"networks"`
	}
	if err := decodeStrictJSON(encoded, 65536, &record); err != nil || record.Networks == nil ||
		len(record.Networks) > limit {
		return nil, ErrKubernetesClusterCAStore
	}
	scopes := make([]network.Scope, 0, len(record.Networks))
	for _, item := range record.Networks {
		scope, err := parseClusterCAScope(item.WorkspaceID, item.NetworkID)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func parseClusterCAScope(workspaceText, networkText string) (network.Scope, error) {
	workspaceID, workspaceErr := workspace.ParseID(workspaceText)
	networkID, networkErr := network.ParseID(networkText)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil {
		return network.Scope{}, ErrKubernetesClusterCAStore
	}
	return scope, nil
}

// ClaimDNSSuffix records the installation's DNS suffix the first time and
// returns the recorded one, and whether suffix is it (§17.1 C2).
func (store *KubernetesClusterCAStore) ClaimDNSSuffix(ctx context.Context, installation deployment.ID,
	suffix string,
) (string, bool, error) {
	if !store.valid(ctx, installation) || !kubeca.ValidDNSName(suffix) || len(suffix) > 160 {
		return "", false, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, claimKubernetesCADNSSuffixSQL, installation.String(), suffix)
	if err != nil {
		return "", false, err
	}
	var record struct {
		Outcome string `json:"outcome"`
		Suffix  string `json:"suffix"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil || record.Suffix == "" {
		return "", false, ErrKubernetesClusterCAStore
	}
	switch record.Outcome {
	case "recorded", "matched":
		return record.Suffix, record.Suffix == suffix, nil
	case "mismatched":
		return record.Suffix, false, nil
	}
	return "", false, ErrKubernetesClusterCAStore
}

// Read reads a Network's CAs without its lock, for the worker to prepare
// keys from outside any transaction that holds it.
func (store *KubernetesClusterCAStore) Read(ctx context.Context, installation deployment.ID,
	scope network.Scope,
) (kubeca.Network, error) {
	if !store.valid(ctx, installation) || !scope.IsValid() {
		return kubeca.Network{}, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, readKubernetesCANetworkSQL, installation.String(),
		scope.WorkspaceID().String(), scope.NetworkID().String())
	if err != nil {
		return kubeca.Network{}, err
	}
	read, outcome, err := decodeClusterCANetwork(encoded)
	if err != nil || outcome != "read" {
		return kubeca.Network{}, errors.Join(ErrKubernetesClusterCAStore, err)
	}
	return read, nil
}

// Change reads the Network under its CA lock, asks plan what to change and
// applies it in the same transaction: each step its own change with its
// sealed audit event, then the schedules. busy is true, and plan is not
// called, when another worker holds the Network. A plan error, a refused
// step or a stale move applies nothing. plan must not wait on I/O: it runs
// while the lock is held.
func (store *KubernetesClusterCAStore) Change(ctx context.Context, installation deployment.ID, scope network.Scope,
	plan func(kubeca.Network) (kubeca.Changes, error),
) (bool, error) {
	if !store.valid(ctx, installation) || !scope.IsValid() || plan == nil {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	// Another writer that moves the Network's revision or audit stream
	// between a step's proof and its evidence fails the change with 40001:
	// it is redone whole, the plan included, within a bounded budget.
	return retryReadConflict(ctx, func() (bool, error) {
		return store.changeOnce(ctx, installation, scope, plan)
	})
}

func (store *KubernetesClusterCAStore) changeOnce(ctx context.Context, installation deployment.ID,
	scope network.Scope, plan func(kubeca.Network) (kubeca.Changes, error),
) (busy bool, resultErr error) {
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		var encoded string
		if err := transaction.QueryRow(ctx, lockKubernetesCANetworkSQL, installation.String(),
			scope.WorkspaceID().String(), scope.NetworkID().String()).Scan(&encoded); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		read, outcome, err := decodeClusterCANetwork(encoded)
		if err != nil || outcome != "locked" {
			busy = err == nil && outcome == "busy"
			if err == nil && !busy {
				err = ErrKubernetesClusterCAStore
			}
			return false, err
		}
		changes, err := plan(read)
		if err != nil {
			return false, err
		}
		if len(changes.Steps)+len(changes.Schedules) > clusterCAMaximumSteps || !changes.Operator.Valid() {
			return false, ErrInvalidKubernetesClusterCAStore
		}
		apply := clusterCAChange{
			ctx: ctx, transaction: transaction, installation: installation, scope: scope,
			operator: changes.Operator,
		}
		for _, step := range changes.Steps {
			if err := apply.step(step); err != nil {
				return false, err
			}
		}
		for _, schedule := range changes.Schedules {
			if err := apply.schedule(schedule); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if errors.Is(err, ErrKubernetesClusterCABusy) {
		return true, nil
	}
	return busy, err
}

// Postpone puts off a Network's due clusters after a failed look, counting
// the failure, without reading them: a Network the worker cannot read or
// plan does not stay first in line. busy is true when another worker
// holds the Network.
func (store *KubernetesClusterCAStore) Postpone(ctx context.Context, installation deployment.ID,
	scope network.Scope, until time.Time,
) (bool, error) {
	if !store.valid(ctx, installation) || !scope.IsValid() || until.IsZero() {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, postponeKubernetesCANetworkSQL, installation.String(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), until)
	if err != nil {
		return false, err
	}
	var record struct {
		Outcome  string `json:"outcome"`
		Clusters *int   `json:"clusters"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil {
		return false, ErrKubernetesClusterCAStore
	}
	switch {
	case record.Outcome == "busy" && record.Clusters == nil:
		return true, nil
	case record.Outcome == "postponed" && record.Clusters != nil && *record.Clusters >= 0:
		return false, nil
	}
	return false, ErrKubernetesClusterCAStore
}

// Beat records what this worker process can do and whether it can sign,
// and returns until when control may count on it.
func (store *KubernetesClusterCAStore) Beat(ctx context.Context, installation deployment.ID, instance publicid.ID,
	ready bool, version, custody string, capabilities []string,
) (time.Time, error) {
	if !store.valid(ctx, installation) || !instance.IsValid() || version == "" || custody == "" ||
		capabilities == nil || len(capabilities) > 16 {
		return time.Time{}, ErrInvalidKubernetesClusterCAStore
	}
	var readyUntil time.Time
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		if err := transaction.QueryRow(ctx, beatKubernetesCAWorkerSQL, installation.String(), instance.String(), ready,
			version, custody, capabilities).Scan(&readyUntil); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		return true, nil
	})
	return readyUntil, err
}
