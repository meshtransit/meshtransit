package main

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/adapter/httpapi"
	"meshtransit.net/core/internal/adapter/oidc"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/ledger"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/audit/history"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/identity/sessioncontext"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/core/internal/domain/invitation"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network/addressusage"
	"meshtransit.net/core/internal/domain/network/aliasrange"
	"meshtransit.net/core/internal/domain/network/devicelifetime"
	"meshtransit.net/core/internal/domain/network/provisioning"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/node/revocation"
	policyapproval "meshtransit.net/core/internal/domain/policy/approval"
	"meshtransit.net/core/internal/domain/policy/compilation"
	policypublication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/sharing/target"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/core/internal/domain/workspace/creation"
	"meshtransit.net/core/internal/domain/workspace/roles"
	"meshtransit.net/core/internal/domain/workspace/selection"
	"meshtransit.net/core/internal/domain/workspace/settings"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/shared/key"
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
	// Mailer emails Workspace invitations; nil leaves them link-only.
	Mailer invitation.Mailer
	// Signup enables self sign-up with these limits; nil leaves it off.
	Signup *config.SignupConfig
	// Interchange is shown with the Private Interchange relay command.
	Interchange *config.InterchangeConfig
	// DNSSuffix names Devices and shares in Console responses
	// (MESHTRANSIT_DNS_SUFFIX); the zero value is the default.
	DNSSuffix dnsname.Suffix
	// EnrollmentKeys issues enrollment keys; nil reports them unavailable.
	EnrollmentKeys httpapi.EnrollmentKeyManager
	// ExitNodes lets Access Rules name Exit Pools
	// (MESHTRANSIT_EXIT_NODES_ENABLED).
	ExitNodes bool
	// SubnetRoutes lets Access Rules name Sites
	// (MESHTRANSIT_SUBNET_ROUTES_ENABLED).
	SubnetRoutes bool
	// SiteDenied are the addresses no Site may cover
	// (MESHTRANSIT_SITE_DENIED_CIDRS).
	SiteDenied []netip.Prefix
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
	application.Management.DNSSuffix = dependencies.DNSSuffix
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
	networkStore, err := postgresadapter.NewNetworkCreationStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	networkCreations, err := provisioning.NewService(networkStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	aliasRangeStore, err := postgresadapter.NewNetworkAliasRangeStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	aliasRanges, err := aliasrange.NewService(aliasRangeStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceLifetimeStore, err := postgresadapter.NewNetworkDeviceLifetimeStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceLifetimes, err := devicelifetime.NewService(deviceLifetimeStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	addressUsageStore, err := postgresadapter.NewNetworkAddressUsageStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	addressUsage, err := addressusage.NewService(addressUsageStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	auditHistoryStore, err := postgresadapter.NewAuditHistoryStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	auditHistory, err := history.NewService(auditHistoryStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	auditExports, err := history.NewExporter(auditHistoryStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	guardrailStore, err := postgresadapter.NewGuardrailStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	guardrails, err := guardrail.NewService(guardrailStore, clock, guardrail.SystemIDs{})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	interchangeStore, err := postgresadapter.NewPrivateInterchangeStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	// The API process has no relay map; the control plane leaves out a
	// relay that clashes with it when it builds maps.
	interchanges, err := interchange.NewService(interchangeStore, clock, interchange.SystemIDs{}, unknownSharedRelays{})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	var interchangeTrust httpapi.InterchangeRelayTrust
	if dependencies.Interchange != nil {
		interchangeTrust = httpapi.InterchangeRelayTrust{CoreURL: dependencies.Interchange.CoreURL,
			SigningKeys: dependencies.Interchange.SigningKeys()}
	}
	deviceGroupStore, err := postgresadapter.NewDeviceGroupStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceGroups, err := devicegroup.NewService(deviceGroupStore, clock, devicegroup.SystemIDs{})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	siteStore, err := postgresadapter.NewSiteStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	sites, err := site.NewService(siteStore, clock, site.SystemIDs{}, site.Config{Limits: site.DefaultLimits(), Denied: dependencies.SiteDenied})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	exitPoolStore, err := postgresadapter.NewExitPoolStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	exitPools, err := exitpool.NewService(exitPoolStore, clock, exitpool.SystemIDs{}, exitpool.DefaultLimits())
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	if exitPools, err = exitPools.WithPrimaryHistory(exitPoolStore); err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	catalogOptions := postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout}
	identityGroupStore, err := postgresadapter.NewIdentityGroupStore(dependencies.Runtime, catalogOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	identityGroups, err := identitygroup.NewService(identityGroupStore, clock, identitygroup.SystemIDs{})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceTagStore, err := postgresadapter.NewDeviceTagStore(dependencies.Runtime, catalogOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceTags, err := devicetag.NewService(deviceTagStore, clock, devicetag.SystemIDs{})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceLifecycleStore, err := postgresadapter.NewDeviceLifecycleStore(dependencies.Runtime, catalogOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceLifecycle, err := devicelifecycle.NewService(deviceLifecycleStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	logoutAllStore, err := postgresadapter.NewAccountSessionRevocationStore(dependencies.Runtime, catalogOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	memberLifecycleStore, err := postgresadapter.NewMemberLifecycleStore(dependencies.Runtime, catalogOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	memberLifecycle, err := memberlifecycle.NewService(memberLifecycleStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	networkMemberStore, err := postgresadapter.NewNetworkMemberStore(dependencies.Runtime, catalogOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	networkMembers, err := memberlifecycle.NewNetworkService(networkMemberStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	invitationStore, err := postgresadapter.NewInvitationStore(dependencies.Runtime, catalogOptions)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	var signups oidcauth.AccountSignupStore
	if dependencies.Signup != nil {
		signups, err = postgresadapter.NewAccountSignupStore(dependencies.Runtime, catalogOptions,
			postgresadapter.SignupLimits{
				SourcePerDay: dependencies.Signup.SourceDailyLimit, DeploymentPerHour: dependencies.Signup.HourlyLimit,
			})
		if err != nil {
			return nil, errInvalidPrivateIdentityComposition
		}
	}
	invitations, err := invitation.NewService(invitation.Options{
		Store: invitationStore, Mailer: dependencies.Mailer, Clock: clock, ConsoleOrigin: application.Origin,
		SendTimeout: 20 * time.Second, Logger: dependencies.Logger,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	sessionWorkspaceStore, err := postgresadapter.NewSessionWorkspaceStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	sessionWorkspaces, err := selection.NewService(sessionWorkspaceStore, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	shareTargetStore, err := postgresadapter.NewShareTargetStore(dependencies.Runtime, postgresadapter.AccountSessionOptions{StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	shareTargets, err := target.NewService(shareTargetStore, clock)
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
	distributionStore, err := postgresadapter.NewDeviceDistributionStore(dependencies.Runtime,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout,
		})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	deviceDistribution, err := distribution.NewService(distributionStore, dependencies.Redis, clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	historyStore, err := postgresadapter.NewAccessGraphHistoryStore(dependencies.Runtime,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout,
		})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	accessGraphHistory, err := ledger.NewService(historyStore)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	enforcementStore, err := postgresadapter.NewDeviceEnforcementHistoryStore(dependencies.Runtime,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: managementOptions.StatementTimeout, IdleTimeout: managementOptions.IdleTimeout,
		})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	enforcementHistory, err := enforcementledger.NewHistoryService(enforcementStore)
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
	if dependencies.SubnetRoutes {
		resources.sites = siteStore
	}
	if dependencies.ExitNodes {
		resources.exitPools = exitPoolStore
	}
	revocations, policies, policyCompiler, policyExplainer, policySimulator,
		policyApprovals, policyApprovalCatalog, err :=
		privateIdentityManagementServices(
			dependencies.Runtime,
			managementOptions,
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
		SessionLogoutAll: logoutAllStore,
		SessionScopes:    managementScopes, DeviceInventory: deviceInventory, DeviceDistribution: deviceDistribution,
		AccessGraphHistory: accessGraphHistory, EnforcementHistory: enforcementHistory,
		SessionCapabilities: managementCapabilities,
		StartIDs:            oidcauth.SystemStartIDs{}, Secrets: oidcauth.SystemSecrets{},
		ClaimIDs: oidcauth.SystemClaimIDs{}, IssueMaterial: oidcauth.SystemIssueMaterial{},
		Revocations: revocations, PolicyPublications: policies, PolicyCompilations: policyCompiler,
		PolicyExplanations: policyExplainer, AccessGraphs: policyExplainer, PolicySimulations: policySimulator,
		ActivePolicies: activePolicies, WorkspaceRenames: workspaceSettings, WorkspaceRoles: workspaceRoles, WorkspaceCreations: workspaceCreations, NetworkCreations: networkCreations, AliasRanges: aliasRanges, DeviceLifetimes: deviceLifetimes, AddressUsage: addressUsage, AuditHistory: auditHistory, AuditExports: auditExports, Guardrails: guardrails, Interchanges: interchanges, InterchangeTrust: interchangeTrust, DeviceGroups: deviceGroups, Sites: sites, ExitPools: exitPools, SiteRouterObservations: dependencies.Redis, SiteRouterUse: dependencies.Redis, ExitNodeUse: dependencies.Redis, IdentityGroups: identityGroups, DeviceTags: deviceTags, DeviceLifecycle: deviceLifecycle, MemberLifecycle: memberLifecycle, NetworkMembers: networkMembers, EnrollmentKeys: dependencies.EnrollmentKeys, Invitations: invitations, InvitationPreviews: invitations, InvitationAcceptor: invitationStore, AccountSignups: signups,
		SessionWorkspaces: sessionWorkspaces, ShareTargets: shareTargets,
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
		MutationIDs: revocation.PublicMutationIDGenerator{}, Retry: retry,
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
		MutationIDs: policypublication.PublicMutationIDGenerator{}, Retry: policyRetry,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyCompiler, err := compilation.NewService(resources.catalog, resources.imports)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	if resources.sites != nil {
		if policyCompiler, err = policyCompiler.WithSites(resources.sites); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
		}
	}
	if resources.exitPools != nil {
		if policyCompiler, err = policyCompiler.WithExitPools(resources.exitPools); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
		}
	}
	accessGraphStore, err := postgresadapter.NewAccessGraphStore(
		pool,
		postgresadapter.AccessGraphOptions(options),
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyExplainer, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: accessGraphStore, GraphReader: accessGraphStore,
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
		Baselines: policySimulationStore, Compiler: policyCompiler,
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
			Retry:       policyRetry,
		},
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, errInvalidPrivateIdentityComposition
	}
	policyApprovalCatalog, err := policyapproval.NewCatalogService(
		policyApprovalStore,
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

// unknownSharedRelays stands in for the shared relay map where the process
// has none: clashes are caught when the control plane builds maps.
type unknownSharedRelays struct{}

func (unknownSharedRelays) Uses(string, key.RelayPublic) bool { return false }
