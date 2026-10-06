package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/internal/node/inventory"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	policyapproval "github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/workspace/creation"
	"github.com/meshtransit/meshtransit/internal/workspace/roles"
	"github.com/meshtransit/meshtransit/internal/workspace/settings"
)

// The production binding accepts no replacement clock or effect/service ports.
// Key/client-secret loading and process dependency readiness remain separate.
type privateIdentityFactoryOptions struct {
	Application privateIdentityOptions
	Discovery   oidc.Options
	Token       privateIdentityTokenOptions
}

type privateIdentityTokenOptions struct {
	Timeout, MaxTokenAge, ClockSkew time.Duration
}

type privateIdentityFactoryDependencies struct {
	Runtime *postgresadapter.Pool
	Redis   *redisadapter.Client
	Secret  oidc.BasicSecret
	Logger  *slog.Logger
}

// This owner closes only its HTTP clients. Admission/drain and borrowed pool/
// Redis lifecycles belong to the process; no listener or readiness is created.
type privateIdentityFactory struct {
	identity       *privateIdentity
	discovery      *oidc.Resolver
	provider       *oidc.Authenticator
	admission      *postgresadapter.AuthTransactionStore
	route          oidcauth.Route
	managementKeys managementCompositionKeys
}

func composePrivateIdentityFactory(
	ctx context.Context,
	keys *privateIdentityKeys,
	options privateIdentityFactoryOptions,
	dependencies privateIdentityFactoryDependencies,
) (*privateIdentityFactory, error) {
	validCaller := ctx != nil && ctx.Err() == nil
	completeDependencies := dependencies.Runtime != nil && dependencies.Redis != nil && dependencies.Logger != nil
	if !validCaller || !completeDependencies || !completePrivateIdentityKeys(keys) {
		return nil, errInvalidPrivateIdentityComposition
	}
	if err := dependencies.Redis.ValidateRateLimiter(); err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityConstructionTimeout)
	defer cancel()
	application := options.Application
	explicitDiscovery := options.Discovery.Timeout > 0 && options.Discovery.MaxMetadataBytes > 0
	discoveryWithinWork := options.Discovery.Timeout <= application.Start.RequestTimeout
	tokenWithinWork := options.Token.Timeout <= application.Callback.RequestTimeout
	if !explicitDiscovery || !discoveryWithinWork || !tokenWithinWork {
		return nil, errInvalidPrivateIdentityComposition
	}
	authOptions, err := privateIdentityDatabaseWindow(min(
		application.Start.RequestTimeout, application.Callback.RequestTimeout,
	))
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	managementOptions, err := privateIdentityDatabaseWindow(application.Management.RequestTimeout)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	transactions, err := postgresadapter.NewAuthTransactionStore(dependencies.Runtime, authOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	authority, err := postgresadapter.NewAccountSessionStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{
		StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	logoutStore, err := postgresadapter.NewAccountSessionLogoutStore(
		dependencies.Runtime,
		postgresadapter.AccountSessionLogoutOptions(managementOptions),
	)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	clock := oidcauth.SystemStartClock{}
	renameStore, err := postgresadapter.NewWorkspaceRenameStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	workspaceSettings, err := settings.NewService(renameStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	roleStore, err := postgresadapter.NewWorkspaceRoleStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	workspaceRoles, err := roles.NewService(roleStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	creationStore, err := postgresadapter.NewWorkspaceCreationStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	workspaceCreations, err := creation.NewService(creationStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	managementScopes, err := sessioncontext.NewService(authority, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	inventoryStore, err := postgresadapter.NewConsoleDeviceInventoryStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{
		StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceInventory, err := inventory.NewService(inventoryStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	managementCapabilities, err := sessioncontext.NewCapabilityService(authority, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	resources, err := newPrivateIdentityResourceServices(dependencies.Runtime, managementOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	revocations, policies, policyCompiler, policyExplainer, policySimulator,
		policyApprovals, policyApprovalCatalog, err :=
		privateIdentityManagementServices(
			dependencies.Runtime,
			managementOptions,
			clock,
			resources,
		)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	owner := &privateIdentityFactory{admission: transactions, route: application.Route,
		managementKeys: managementCompositionKeys{
			sessions: keys.sessions, idempotency: keys.idempotency, rateLimit: keys.rateLimit,
		},
	}
	activePolicies, err := postgresadapter.NewActivePolicyStore(dependencies.Runtime, postgresadapter.PolicySimulationOptions(managementOptions))
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	released := false
	defer func() {
		if !released {
			owner.Close()
		}
	}()
	owner.discovery, err = oidc.NewResolver(options.Discovery)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	owner.provider, err = oidc.NewAuthenticator(oidc.TokenOptions{
		Timeout: options.Token.Timeout, MaxTokenAge: options.Token.MaxTokenAge,
		ClockSkew: options.Token.ClockSkew, Clock: clock,
	}, application.Route, dependencies.Secret)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	owner.identity, err = composePrivateIdentity(ctx, keys, application, privateIdentityPorts{
		Admission: transactions, Metadata: owner.discovery, Creations: transactions, Committed: transactions,
		CreationClock: transactions, Pending: transactions, Claims: transactions, Failures: transactions, Issues: transactions,
		Provider: owner.provider, Subjects: transactions, SessionAuthority: authority, SessionRevocations: logoutStore,
		SessionScopes: managementScopes, DeviceInventory: deviceInventory, SessionCapabilities: managementCapabilities,
		StartIDs: oidcauth.SystemStartIDs{}, Secrets: oidcauth.SystemSecrets{},
		ClaimIDs: oidcauth.SystemClaimIDs{}, IssueMaterial: oidcauth.SystemIssueMaterial{},
		Revocations: revocations, PolicyPublications: policies, PolicyCompilations: policyCompiler,
		PolicyExplanations: policyExplainer, PolicySimulations: policySimulator,
		ActivePolicies: activePolicies, WorkspaceRenames: workspaceSettings, WorkspaceRoles: workspaceRoles, WorkspaceCreations: workspaceCreations,
		PolicyApprovals: policyApprovals, PolicyApprovalCatalog: policyApprovalCatalog,
		ResourceCreations: resources.creations, ResourceCatalog: resources.catalog, ResourceSharing: resources.sharing,
		RateLimiter:    dependencies.Redis,
		CorrelationIDs: httpapi.PublicCorrelationIDGenerator{}, Clock: clock, Logger: dependencies.Logger,
	})
	if err != nil || ctx.Err() != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	released = true
	return owner, nil
}

// Floor positive limits to SQL's millisecond resolution without disabling them.
// Caller context still owns acquisition and the full request deadline.
func privateIdentityDatabaseWindow(window time.Duration) (postgresadapter.AuthTransactionOptions, error) {
	if window < 2*time.Millisecond {
		return postgresadapter.AuthTransactionOptions{}, errInvalidPrivateIdentityComposition
	}
	statement := min(window, managementStatementTimeout) / time.Millisecond * time.Millisecond
	lock := min(statement/2, managementLockTimeout) / time.Millisecond * time.Millisecond
	idle := min(window, managementTransactionIdle) / time.Millisecond * time.Millisecond
	return postgresadapter.AuthTransactionOptions{
		StatementTimeout: statement, LockTimeout: lock, IdleTimeout: idle,
	}, nil
}

func privateIdentityManagementServices(
	pool *postgresadapter.Pool,
	options postgresadapter.AuthTransactionOptions,
	clock oidcauth.StartClock,
	resources privateIdentityResourceServices,
) (
	*revocation.Service,
	*policypublication.Service,
	*compilation.Service,
	*accessgraph.Service,
	*simulation.Service,
	*policyapproval.Service,
	*policyapproval.CatalogService,
	error,
) {
	revocationStore, err := postgresadapter.NewDeviceRevocationStore(
		pool, postgresadapter.DeviceRevocationOptions(options),
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	retry, err := revocation.NewExponentialBackoff(managementRetryInitial, managementRetryMaximum)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	revocations, err := revocation.NewService(revocation.Options{
		MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout, IdempotencyTTL: managementIdempotencyTTL,
	}, revocation.Dependencies{
		Transactions: revocationStore, CommittedResults: revocationStore,
		MutationIDs: revocation.PublicMutationIDGenerator{}, Clock: clock, Retry: retry,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyStore, err := postgresadapter.NewPolicyPublicationStore(pool, postgresadapter.PolicyPublicationOptions{
		StatementTimeout: options.StatementTimeout, LockTimeout: options.LockTimeout, IdleTimeout: options.IdleTimeout,
		ApprovalMode: postgresadapter.PolicyPublicationApprovalModePublisherAuthorized,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyRetry, err := policypublication.NewExponentialBackoff(managementRetryInitial, managementRetryMaximum)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policies, err := policypublication.NewService(policypublication.Options{
		MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
	}, policypublication.Dependencies{
		Transactions: policyStore, CommittedResults: policyStore,
		MutationIDs: policypublication.PublicMutationIDGenerator{}, Clock: clock, Retry: policyRetry,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyCompiler, err := compilation.NewService(resources.catalog, resources.imports)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	accessGraphStore, err := postgresadapter.NewAccessGraphStore(
		pool,
		postgresadapter.AccessGraphOptions(options),
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyExplainer, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: accessGraphStore, Clock: accessgraph.SystemClock{},
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policySimulationStore, err := postgresadapter.NewPolicySimulationStore(
		pool,
		postgresadapter.PolicySimulationOptions(options),
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policySimulator, err := simulation.NewService(simulation.Dependencies{
		Baselines: policySimulationStore, Compiler: policyCompiler, Clock: clock,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyApprovalStore, err := postgresadapter.NewPolicyApprovalStore(
		pool,
		postgresadapter.PolicyApprovalOptions(options),
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyApprovals, err := policyapproval.NewService(
		policyapproval.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyWindow: managementIdempotencyTTL,
		},
		policyapproval.Dependencies{
			Simulator:           policySimulator,
			RequestTransactions: policyApprovalStore, CommittedRequests: policyApprovalStore,
			ApprovalTransactions: policyApprovalStore, CommittedApprovals: policyApprovalStore,
			MutationIDs: policyapproval.PublicMutationIDGenerator{},
			Clock:       policyapproval.SystemClock{}, Retry: policyRetry,
		},
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyApprovalCatalog, err := policyapproval.NewCatalogService(
		policyApprovalStore,
		policyapproval.SystemClock{},
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	return revocations, policies, policyCompiler, policyExplainer, policySimulator,
		policyApprovals, policyApprovalCatalog, nil
}

// Close is repeatable idle cleanup, not an admission gate or active-request join.
func (factory *privateIdentityFactory) Close() {
	if factory == nil {
		return
	}
	factory.discovery.Close()
	factory.provider.Close()
}

func (privateIdentityFactoryOptions) String() string       { return "[REDACTED]" }
func (privateIdentityFactoryOptions) GoString() string     { return "[REDACTED]" }
func (privateIdentityFactoryOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
func (privateIdentityFactoryOptions) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}

func (privateIdentityFactoryDependencies) String() string   { return "[REDACTED]" }
func (privateIdentityFactoryDependencies) GoString() string { return "[REDACTED]" }
func (privateIdentityFactoryDependencies) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}
func (privateIdentityFactoryDependencies) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}

func (*privateIdentityFactory) String() string       { return "[REDACTED]" }
func (*privateIdentityFactory) GoString() string     { return "[REDACTED]" }
func (*privateIdentityFactory) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
func (*privateIdentityFactory) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}
