package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/adapter/geoip"
	"meshtransit.net/core/internal/adapter/httpapi"
	oidcadapter "meshtransit.net/core/internal/adapter/oidc"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/control/rebalance"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/revisionworker"
	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/core/internal/domain/sharing/endpointpublication"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
	"meshtransit.net/core/internal/platform/profile"
)

func run(ctx context.Context, lookup config.LookupFunc, errorOutput io.Writer) (exitCode int) {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}

	processConfig, err := config.Load(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_configuration", "error", err)
		return 1
	}
	logger, err = observability.NewLogger(errorOutput, processConfig.LogLevel)
	if err != nil {
		return 1
	}

	roles, err := app.ExpandRole(processConfig.Role)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_role_selection", "error", err)
		return 1
	}
	var privateProfile *config.PrivateLoginConfig
	privateComponents := []app.Component{}
	if processConfig.PrivateLogin != nil {
		privateProfile, err = processConfig.PrivateLogin.Load(ctx, processConfig)
		if err != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "private_login_configuration_failure")
			return 1
		}
		privateComponents = append(privateComponents, app.ComponentPrivateLogin)
	}
	if processConfig.BrowserRegistration != nil && privateProfile != nil {
		browser := processConfig.BrowserRegistration
		if browser.Origin != privateProfile.Origin() ||
			browser.DeploymentID != privateProfile.Route().DeploymentID() ||
			browser.RecoveryEpoch != privateProfile.Route().RecoveryEpoch() {
			logger.ErrorContext(ctx, "startup failed", "error_code", "browser_registration_identity_mismatch")
			return 1
		}
	}
	var browserRegistrationKeys *enrollment.BrowserIntentKeyring
	if processConfig.BrowserRegistration != nil {
		browserRegistrationKeys, err = composeBrowserRegistrationKeys(processConfig.BrowserRegistration)
		if err != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "browser_registration_key_failure")
			return 1
		}
	}
	readiness, err := app.NewRuntimeState(roles, privateComponents...)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_runtime_state", "error", err)
		return 1
	}

	resources := &resourceOwner{}
	resourcesOwnedByApplication := false
	defer func() {
		if resourcesOwnedByApplication {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			processConfig.ShutdownTimeout,
		)
		defer cancel()
		if closeErr := resources.Close(cleanupCtx); closeErr != nil {
			logger.ErrorContext(
				context.WithoutCancel(ctx),
				"resource cleanup failed",
				"error_code", "resource_cleanup_failure",
				"error", closeErr,
			)
			exitCode = 1
		}
	}()

	checkers := make([]app.DependencyChecker, 0, len(readiness.RequiredComponents()))
	additionalMetrics := make([]prometheus.Collector, 0, 6)
	var scaleHandler http.Handler // control role only: the autoscaler's session total
	var storagePools postgresPools
	var storageServices []app.OwnedService
	var redisClient *redisadapter.Client
	if processConfig.Storage != nil {
		storagePools, err = openPostgresPools(
			ctx,
			processConfig.Storage.PostgreSQL,
			processConfig.Dependencies.CheckTimeout,
			resources,
			logger,
		)
		if err != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "postgres_open_failure", "error", err)
			return 1
		}
		postgresChecker, checkerErr := storagePools.healthChecker()
		if checkerErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "postgres_checker_failure", "error", checkerErr)
			return 1
		}
		checkers = append(checkers, postgresChecker)
		postgresMetrics, metricsErr := storagePools.metricsCollector()
		if metricsErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "postgres_metrics_failure", "error", metricsErr)
			return 1
		}
		additionalMetrics = append(additionalMetrics, postgresMetrics)
		clockSkew, composeErr := composeClockSkewObserver(storagePools, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "clock_skew_composition_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, clockSkew)
		storageServices = append(storageServices, app.OwnedService{Name: "postgres-clock-skew-observer", Service: clockSkew})

		redisClient, err = redisadapter.Open(ctx, redisadapter.Options{
			Address:        processConfig.Storage.Redis.Address,
			Username:       processConfig.Storage.Redis.Username,
			PasswordFile:   processConfig.Storage.Redis.PasswordFile,
			CAFile:         processConfig.Storage.Redis.CAFile,
			PoolSize:       processConfig.Storage.Redis.PoolSize,
			RequestTimeout: processConfig.Dependencies.CheckTimeout,
		})
		if err != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "redis_open_failure", "error", err)
			return 1
		}
		if ownErr := resources.Add("redis", redisClient.Shutdown); ownErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "redis_ownership_failure",
				"error", errors.Join(ownErr, redisClient.Shutdown(ctx)),
			)
			return 1
		}
		checkers = append(checkers, redisClient)
		additionalMetrics = append(additionalMetrics, redisClient.MetricsCollector())
	}
	if code, entitlementErr := recordDeploymentEntitlement(
		ctx, processConfig.DeploymentEntitlement, storagePools.runtime, logger, time.Now().UTC(),
	); entitlementErr != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", code)
		return 1
	}

	var revisionWorkerTelemetry *revisionworker.Telemetry
	roleServices := make([]app.OwnedService, 0, 7)
	if processConfig.Identity != nil {
		identityBroker, composeErr := composeIdentityBroker(
			ctx,
			*processConfig.Identity,
			resources,
			logger,
		)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "identity_broker_composition_failure")
			return 1
		}
		checkers = append(checkers, identityBroker.checkers...)
		roleServices = append(roleServices, identityBroker.services...)
		additionalMetrics = append(additionalMetrics, identityBroker.metrics...)
	}
	if processConfig.RevisionWorker != nil {
		revisionWorkerTelemetry = revisionworker.NewTelemetry()
		workerService, composeErr := composeRevisionWorker(
			*processConfig.RevisionWorker,
			storagePools.worker,
			redisClient,
			revisionWorkerTelemetry,
			logger,
		)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "worker_composition_failure", "error", composeErr)
			return 1
		}
		roleServices = append(
			roleServices,
			app.OwnedService{Name: "network-revision-worker", Service: workerService},
		)
		auditPartitions, composeErr := composeAuditPartitionMaintainer(storagePools.worker, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "audit_partition_composition_failure")
			return 1
		}
		roleServices = append(roleServices, app.OwnedService{Name: "audit-partition-maintainer", Service: auditPartitions})
		operationPartitions, operationMetrics, composeErr := composeKubeOperationPartitions(storagePools.worker, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "kubernetes_operation_partition_composition_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, operationMetrics...)
		roleServices = append(roleServices,
			app.OwnedService{Name: "kubernetes-operation-partition-maintainer", Service: operationPartitions})
		unroutedRetirer, composeErr := composeOutboxUnroutedRetirer(storagePools.worker, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "outbox_unrouted_composition_failure")
			return 1
		}
		roleServices = append(roleServices, app.OwnedService{Name: "outbox-unrouted-retirer", Service: unroutedRetirer})
	}
	if processConfig.PrivateEndpointWorker != nil {
		telemetry := endpointpublication.NewTelemetry()
		workerService, gateway, workerMetrics, composeErr := composePrivateEndpointWorker(
			*processConfig.PrivateEndpointWorker, storagePools.worker, telemetry, logger,
		)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "private_endpoint_worker_composition_failure")
			return 1
		}
		closeGateway := func(context.Context) error { gateway.CloseIdleConnections(); return nil }
		if ownErr := resources.Add("private-endpoint-route-agent", closeGateway); ownErr != nil {
			gateway.CloseIdleConnections()
			logger.ErrorContext(ctx, "startup failed", "error_code", "private_endpoint_route_agent_ownership_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, workerMetrics)
		roleServices = append(roleServices, app.OwnedService{
			Name: "private-endpoint-worker", Service: workerService,
		})
	}
	if processConfig.DeviceAliasWorker != nil {
		workerService, workerMetrics, composeErr := composeDeviceAliasWorker(*processConfig.DeviceAliasWorker, storagePools.worker, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "device_alias_worker_composition_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, workerMetrics)
		roleServices = append(roleServices, app.OwnedService{Name: "device-alias-worker", Service: workerService})
	}
	if processConfig.ContractExpiryWorker != nil {
		workers, composeErr := composeContractEndWorkers(*processConfig.ContractExpiryWorker, storagePools.worker, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "contract_expiry_worker_composition_failure")
			return 1
		}
		for _, composed := range workers {
			additionalMetrics = append(additionalMetrics, composed.metrics)
			roleServices = append(roleServices, app.OwnedService{Name: composed.name, Service: composed.worker})
		}
	}
	if processConfig.AccessLedgerWorker != nil {
		workerService, workerMetrics, composeErr := composeAccessLedgerWorker(*processConfig.AccessLedgerWorker, storagePools.worker, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "access_ledger_worker_composition_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, workerMetrics)
		roleServices = append(roleServices, app.OwnedService{Name: "access-ledger-worker", Service: workerService})
	}
	if processConfig.KubernetesCAWorker != nil {
		var marks lifecycle.MarkKeeper
		if redisClient != nil {
			marks = redisClient
		}
		workers, composeErr := composeKubernetesCAWorker(*processConfig.KubernetesCAWorker,
			processConfig.DNSSuffix, storagePools.worker, marks, redisClient, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "kubernetes_ca_worker_composition_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, workers.metrics...)
		roleServices = append(roleServices,
			app.OwnedService{Name: "kubernetes-ca-worker", Service: workers.lifecycle},
			app.OwnedService{Name: "kubernetes-certificate-signer", Service: workers.signer})
		if workers.hints != nil {
			roleServices = append(roleServices,
				app.OwnedService{Name: "kubernetes-certificate-wakeups", Service: workers.hints})
		}
	}
	if processConfig.EnforcementLedgerWorker != nil {
		workerService, workerMetrics, composeErr := composeEnforcementLedgerWorker(
			*processConfig.EnforcementLedgerWorker, storagePools.worker, redisClient, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "enforcement_ledger_worker_composition_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, workerMetrics)
		roleServices = append(roleServices, app.OwnedService{Name: "enforcement-ledger-worker", Service: workerService})
		if processConfig.SubnetRoutes {
			electionService, electionMetrics, composeErr := composeSiteElectionWorker(
				*processConfig.EnforcementLedgerWorker, storagePools.worker, redisClient, logger)
			if composeErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "site_election_worker_composition_failure")
				return 1
			}
			additionalMetrics = append(additionalMetrics, electionMetrics)
			roleServices = append(roleServices, app.OwnedService{Name: "site-election-worker", Service: electionService})
		}
		if processConfig.ExitNodes {
			exitElection, exitElectionMetrics, composeErr := composeExitPoolElectionWorker(
				*processConfig.EnforcementLedgerWorker, storagePools.worker, redisClient, processConfig.ExitSpread, logger)
			if composeErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "exit_pool_election_worker_composition_failure")
				return 1
			}
			additionalMetrics = append(additionalMetrics, exitElectionMetrics)
			roleServices = append(roleServices, app.OwnedService{Name: "exit-pool-election-worker",
				Service: exitElection})
		}
	}
	var enrollmentKeys httpapi.EnrollmentKeyManager
	if processConfig.API != nil {
		composed, composeErr := composeEnrollmentKeys(storagePools.runtime, processConfig.EnrollmentKeyDigest)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "enrollment_key_composition_failure")
			return 1
		}
		enrollmentKeys = composed
	}
	var kubernetesClusters httpapi.KubernetesClusterManager
	if processConfig.API != nil {
		composed, composeErr := composeKubernetesClusters(storagePools.runtime, processConfig.EnrollmentKeyDigest)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "kubernetes_cluster_composition_failure")
			return 1
		}
		kubernetesClusters = composed
	}
	var privateFactory *privateIdentityFactory
	if privateProfile != nil {
		var browserRuntime []browserRegistrationRuntime
		if processConfig.BrowserRegistration != nil {
			browserRuntime = append(browserRuntime, browserRegistrationRuntime{
				profile: processConfig.BrowserRegistration, keys: browserRegistrationKeys,
			})
		}
		mailer, mailErr := composeInvitationMailer(processConfig.Mail)
		if mailErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mail_composition_failure")
			return 1
		}
		var countries httpapi.CountryLookup
		if processConfig.GeoIPCountryFile != "" {
			table, openErr := geoip.Open(processConfig.GeoIPCountryFile)
			if openErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "geoip_country_table_failure",
					"error", openErr)
				return 1
			}
			countries = table
		}
		factory, loginService, composeErr := composePrivateIdentityRuntime(
			ctx,
			privateProfile,
			privateIdentityFactoryDependencies{Runtime: storagePools.runtime, Redis: redisClient, Logger: logger,
				Mailer: mailer, Signup: processConfig.Signup, Interchange: processConfig.Interchange,
				DNSSuffix: processConfig.DNSSuffix, EnrollmentKeys: enrollmentKeys,
				KubernetesClusters: kubernetesClusters,
				SubnetRoutes:       processConfig.SubnetRoutes, SiteDenied: processConfig.SiteDenied,
				ExitNodes: processConfig.ExitNodes, ExitSpread: processConfig.ExitSpread, Countries: countries,
				DNSZones: processConfig.DNSZones.Enabled, DNSProtectedNames: processConfig.DNSProtectedNames()},
			browserRuntime...,
		)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "private_login_composition_failure")
			return 1
		}
		closeFactory := func(context.Context) error { factory.Close(); return nil }
		if ownErr := resources.Add("private-login-factory", closeFactory); ownErr != nil {
			factory.Close()
			logger.ErrorContext(ctx, "startup failed", "error_code", "private_login_ownership_failure")
			return 1
		}
		checkers = append(checkers, factory)
		privateFactory = factory
		additionalMetrics = append(additionalMetrics, prometheus.WrapCollectorWith(
			prometheus.Labels{"auth_profile": "console_cookie_private_v1"}, factory.identity.metrics,
		))
		roleServices = append(roleServices, app.OwnedService{Name: "private-login", Service: loginService})
	}
	if processConfig.API != nil {
		var managementServer *httpapi.ManagementServer
		var managementMetrics prometheus.Collector
		var composeErr error
		if privateFactory != nil {
			managementServer, managementMetrics, composeErr = composeManagementAPIWithKeys(
				managementCompositionOptions{API: *processConfig.API, Keys: privateFactory.managementKeys,
					DNSSuffix: processConfig.DNSSuffix, EnrollmentKeys: enrollmentKeys,
					KubernetesClusters: kubernetesClusters,
					SubnetRoutes:       processConfig.SubnetRoutes, ExitNodes: processConfig.ExitNodes},
				storagePools.runtime,
				redisClient,
				logger,
			)
		} else {
			managementServer, managementMetrics, composeErr = composeManagementAPI(
				*processConfig.API,
				processConfig.DNSSuffix,
				enrollmentKeys,
				kubernetesClusters,
				processConfig.SubnetRoutes,
				processConfig.ExitNodes,
				storagePools.runtime,
				redisClient,
				logger,
			)
		}
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "management_api_composition_failure", "error", composeErr)
			return 1
		}
		if privateFactory != nil {
			managementMetrics = prometheus.WrapCollectorWith(
				prometheus.Labels{"auth_profile": "core_session_bearer_v1"}, managementMetrics,
			)
		}
		additionalMetrics = append(additionalMetrics, managementMetrics)
		roleServices = append(roleServices, app.OwnedService{Name: "management-api", Service: managementServer})
	}
	if processConfig.Control != nil {
		if processConfig.Enrollment == nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "control_configuration_failure")
			return 1
		}
		revisionFeed, revisionFeedTelemetry, composeErr := composeRevisionFeed(
			*processConfig.Control,
			redisClient,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "revision_feed_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		revisionFeedMetrics, metricsErr := httpapi.NewRevisionFeedMetricsCollector(
			revisionFeedTelemetry,
		)
		if metricsErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "revision_feed_metrics_failure",
				"error", metricsErr,
			)
			return 1
		}
		additionalMetrics = append(additionalMetrics, revisionFeedMetrics)
		roleServices = append(
			roleServices,
			app.OwnedService{Name: "network-revision-feed", Service: revisionFeed},
		)
		connectivityFeed, connectivityFeedTelemetry, composeErr := composeConnectivityFeed(
			*processConfig.Control,
			redisClient,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "connectivity_feed_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		connectivityFeedMetrics, metricsErr := httpapi.NewConnectivityFeedMetricsCollector(
			connectivityFeedTelemetry,
		)
		if metricsErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "connectivity_feed_metrics_failure",
				"error", metricsErr,
			)
			return 1
		}
		additionalMetrics = append(additionalMetrics, connectivityFeedMetrics)
		roleServices = append(
			roleServices,
			app.OwnedService{Name: "connectivity-feed", Service: connectivityFeed},
		)
		registrationService, composeErr := composeRegistration(
			*processConfig.Enrollment,
			storagePools.runtime,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "registration_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		var relayAuthorityHandler http.Handler
		var relayAccess mapsession.RelayAccess
		var relayAuthorityDirectory relay.Directory
		var relayDirectories func(network.ID) (relay.Directory, error)
		if processConfig.RelayAuthority != nil {
			authority, relayErr := composeRelayAuthority(ctx, *processConfig.RelayAuthority, storagePools.runtime, logger)
			if relayErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "relay_authority_composition_failure", "error", relayErr)
				return 1
			}
			relayAuthorityHandler, relayAccess = authority.handler, authority.access
			relayAuthorityDirectory = authority.directory
			relayDirectories = authority.directories
			additionalMetrics = append(additionalMetrics, authority.publisher.Metrics())
			// Started before the listener, so the first documents exist when it opens.
			roleServices = append(roleServices, app.OwnedService{Name: "relay-authority", Service: authority.publisher})
		}
		var relayDirectory relay.Directory
		if relayAuthorityDirectory.IsValid() {
			relayDirectory = relayAuthorityDirectory
			if processConfig.Control.Map.RelayDirectory != nil {
				logger.InfoContext(ctx, "relay directory file ignored: the relay map is the source of relay regions")
			}
		} else {
			relayDirectory, composeErr = loadRelayDirectory(ctx, processConfig.Control.Map.RelayDirectory)
		}
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "relay_directory_load_failure",
				"error", composeErr,
			)
			return 1
		}
		connectivityHub, streamConnectivity, hubMetrics, composeErr := composeConnectivityHub(
			processConfig.Control.Map,
			redisClient,
			connectivityFeed,
		)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "connectivity_hub_composition_failure", "error", composeErr)
			return 1
		}
		if hubMetrics != nil {
			additionalMetrics = append(additionalMetrics, hubMetrics)
		}
		mapSessionService, mapInventoryMetrics, kubernetesTrust, composeErr := composeMapSession(
			processConfig.Control.Map,
			storagePools.runtime,
			redisClient,
			redisClient,
			relayDirectory,
			relayDirectories,
			connectivityHub,
			processConfig.SubnetRoutes,
			processConfig.ExitNodes,
			processConfig.ExitSpread,
			processConfig.DNSZones.Enabled,
			processConfig.DNSProtectedNames(),
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "map_session_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		additionalMetrics = append(additionalMetrics, mapInventoryMetrics)
		mapStreamService, composeErr := composeMapStream(
			processConfig.Control.Map,
			mapSessionService,
			redisClient,
			revisionFeed,
			streamConnectivity,
			redisClient,
			relayAccess,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "map_stream_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		var browserControl []browserControlServices
		if processConfig.BrowserRegistration != nil {
			issuer, completion, browserErr := composeBrowserControl(
				processConfig.BrowserRegistration, browserRegistrationKeys,
				processConfig.Enrollment.Registration, storagePools.runtime,
			)
			if browserErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "browser_control_composition_failure")
				return 1
			}
			browserControl = append(browserControl, browserControlServices{
				issuer: issuer, completion: completion,
			})
		}
		// MTCP v1 is the control protocol; the listener also serves the relay
		// authority's documents.
		timestamps, storeErr := postgresadapter.NewMTCPTimestampStore(storagePools.runtime)
		if storeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", storeErr)
			return 1
		}
		// Kubernetes gateways' stale or contested keys enter the audit trail
		// (schema 229).
		gatewayKeyEvents, storeErr := postgresadapter.NewKubernetesGatewayKeyEventStore(storagePools.runtime)
		if storeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", storeErr)
			return 1
		}
		logout, logoutErr := composeDeviceLogout(processConfig.Control.Map, storagePools.runtime)
		if logoutErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", logoutErr)
			return 1
		}
		routeOffers, offerErr := postgresadapter.NewRouteOfferStore(storagePools.runtime, postgresadapter.AccountSessionOptions{
			StatementTimeout: processConfig.Control.Map.StatementTimeout,
			IdleTimeout:      processConfig.Control.Map.TransactionIdleLimit,
		})
		if offerErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", offerErr)
			return 1
		}
		exitOffers, offerErr := postgresadapter.NewExitOfferStore(storagePools.runtime, postgresadapter.AccountSessionOptions{
			StatementTimeout: processConfig.Control.Map.StatementTimeout,
			IdleTimeout:      processConfig.Control.Map.TransactionIdleLimit,
		})
		if offerErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", offerErr)
			return 1
		}
		deps := mtcpDependencies{streams: mapStreamService, sessions: mapSessionService,
			registrations: registrationService, logout: logout, paths: redisClient, connectivity: redisClient, guard: mtcpTimestampGuard{store: timestamps}, gatewayKeyEvents: gatewayKeyEvents, gatewayPresence: redisClient, logger: logger,
			dnsSuffix: processConfig.DNSSuffix, dnsInfrastructure: processConfig.DNSProtectedNames(),
			routeOffers:      routeOffers,
			subnetRoutes:     processConfig.SubnetRoutes && processConfig.Control.Map.SharedInventory,
			exitNodes:        processConfig.ExitNodes && processConfig.Control.Map.SharedInventory,
			dnsZones:         processConfig.DNSZones.Enabled && processConfig.Control.Map.SharedInventory,
			kubernetesAccess: processConfig.Control.Map.SharedInventory}
		if deps.exitNodes {
			// Exit offers are stored only while Core offers router.exit.v1:
			// then a node that no longer lists it withdraws its offer.
			deps.exitOffers = exitOffers
			// Consumers report the captive portal windows root opened
			// (captive.audit1); each enters the Network's audit trail.
			captiveWindows, captiveErr := postgresadapter.NewCaptiveWindowStore(storagePools.runtime)
			if captiveErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", captiveErr)
				return 1
			}
			deps.captiveWindows = captiveWindows
		}
		if len(browserControl) == 1 {
			deps.browser, deps.origin = &browserControl[0], processConfig.BrowserRegistration.Origin
		}
		gatewayKeys, keysErr := composeGatewayKeys(processConfig.Enrollment.Registration, storagePools.runtime)
		if keysErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", keysErr)
			return 1
		}
		deps.gatewayKeys = gatewayKeys
		if processConfig.KubernetesJoin {
			joins, joinErr := composeClusterJoins(*processConfig.Enrollment, storagePools.runtime)
			if joinErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", joinErr)
				return 1
			}
			deps.clusterJoins = joins
		}
		// Nodes take the clusters they may reach and their roots (kube.ca1,
		// K1a4d) once the runtime role may read them; probed once, as the
		// capability list is fixed for the process.
		if processConfig.KubernetesJoin && processConfig.Control.Map.SharedInventory {
			probeCtx, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
			granted, grantErr := kubernetesTrust(probeCtx)
			cancelProbe()
			if grantErr != nil || !granted {
				logger.WarnContext(ctx, "Kubernetes cluster roots not offered to clients",
					"error_code", "kubernetes_cluster_trust_unavailable", "error", grantErr)
			}
			deps.kubernetesClusters = granted && grantErr == nil
		}
		// Gateways ask for their replica certificates where their maps are
		// built from the shared inventory (gateway.cert1, a3b).
		if processConfig.KubernetesJoin && processConfig.Control.Map.SharedInventory {
			certificates, hints, certErr := composeKubeCertificates(processConfig.Enrollment.Registration,
				storagePools.runtime, redisClient, logger)
			if certErr != nil {
				logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", certErr)
				return 1
			}
			deps.kubeCertificates = certificates
			if hints != nil {
				roleServices = append(roleServices,
					app.OwnedService{Name: "kubernetes-certificate-hints", Service: hints})
			}
		}
		// Gateways have Core record their type A operations before
		// forwarding them (gateway.audit1, K1b0) once the runtime role may
		// write them; probed once, as the capability list is fixed. Before
		// the listener: shut down after it drained the sessions.
		if processConfig.KubernetesJoin && processConfig.Control.Map.SharedInventory {
			probeCtx, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
			audit, auditErr := composeKubeAudit(probeCtx, storagePools.runtime, redisClient)
			cancelProbe()
			switch {
			case errors.Is(auditErr, errInvalidKubeAuditComposition):
				logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", auditErr)
				return 1
			case audit == nil:
				logger.WarnContext(ctx, "Kubernetes operation records not offered to gateways",
					"error_code", "kubernetes_operations_unavailable", "error", auditErr)
			default:
				deps.kubeAudit = audit
				additionalMetrics = append(additionalMetrics, audit.metrics...)
				roleServices = append(roleServices,
					app.OwnedService{Name: "kubernetes-operation-writer", Service: audit})
			}
		}
		if relay := processConfig.RelayAuthority; relay != nil && relay.TicketDeployment != nil {
			deps.relayZones = relay.TicketZonesV2
		}
		mtcpServer, mtcpMetrics, mtcpErr := composeMTCP(*processConfig.Control, deps)
		if mtcpErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "mtcp_composition_failure", "error", mtcpErr)
			return 1
		}
		additionalMetrics = append(additionalMetrics, mtcpMetrics.Collectors()...)
		controlListener, composeErr := composeControlListener(*processConfig.Control, relayAuthorityHandler, mtcpServer)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "control_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		additionalMetrics = append(additionalMetrics, controlListener.MetricsCollector())
		roleServices = append(roleServices, app.OwnedService{Name: "control", Service: controlListener})
		// After the listener: started once sessions can exist, stopped (and
		// withdrawn from the registry) before the listener drains them.
		balancer, composeErr := composeRebalance(*processConfig.Control, redisClient, mtcpServer, logger)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "rebalance_composition_failure", "error", composeErr)
			return 1
		}
		roleServices = append(roleServices, app.OwnedService{Name: "control-rebalance", Service: balancer})
		scaleHandler = rebalance.ScaleHandler(redisClient)
	}

	// Last service: reverse shutdown cancels and joins expiry before drains/storage.
	if processConfig.AuthExpiry != nil {
		telemetry := oidcadapter.NewExpiryTelemetry()
		worker, composeErr := composeAuthExpiry(
			*processConfig.AuthExpiry,
			storagePools.worker,
			telemetry,
			logger,
		)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "browser_expiry_composition_failure")
			return 1
		}
		additionalMetrics = append(additionalMetrics, telemetry)
		roleServices = append(roleServices, app.OwnedService{Name: "browser-auth-expiry-worker", Service: worker})
	}

	monitor, err := app.NewDependencyMonitor(
		app.MonitorOptions{
			CheckTimeout:  processConfig.Dependencies.CheckTimeout,
			CheckInterval: processConfig.Dependencies.CheckInterval,
		},
		readiness,
		checkers...,
	)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_dependency_monitor", "error", err)
		return 1
	}
	build := buildinfo.Current()
	healthServer, err := httpapi.NewHealthServer(httpapi.HealthServerOptions{
		Address: processConfig.HealthAddress,
		State:   readiness,
		Logger:  logger,
		Build: httpapi.BuildInfo{
			Version:             build.Version,
			Revision:            build.Revision,
			GoVersion:           build.GoVersion,
			ConfigSchemaVersion: config.SchemaVersion,
		},
		RevisionWorkerTelemetry: revisionWorkerTelemetry,
		AdditionalMetrics:       additionalMetrics,
		ScaleHandler:            scaleHandler,
	})
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_health_server", "error", err)
		return 1
	}
	services := make([]app.OwnedService, 0, len(storageServices)+len(roleServices)+2)
	services = append(services, app.OwnedService{Name: "health", Service: healthServer})
	if processConfig.ProfileAddress != "" {
		profiler, profileErr := profile.NewServer(processConfig.ProfileAddress)
		if profileErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_profile_server", "error", profileErr)
			return 1
		}
		services = append(services, app.OwnedService{Name: "profile", Service: profiler})
	}
	services = append(services, storageServices...)
	services = append(services, roleServices...)
	application, err := app.New(
		app.Options{
			Roles:           roles,
			ShutdownTimeout: processConfig.ShutdownTimeout,
		},
		readiness,
		monitor,
		resources,
		logger,
		services...,
	)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_application", "error", err)
		return 1
	}
	resourcesOwnedByApplication = true

	if err := application.Run(ctx); err != nil {
		logger.ErrorContext(
			context.WithoutCancel(ctx),
			"runtime failed",
			"error_code", "runtime_failure",
			"unavailable_dependencies", unavailableDependencies(readiness),
			"failure_phase", runtimeFailurePhase(err),
			"error", err,
		)
		return 1
	}
	return 0
}

func runtimeFailurePhase(err error) string {
	switch {
	case errors.Is(err, errPrivateIdentityAdmissionCheck):
		return "private_login_admission"
	case errors.Is(err, errPrivateIdentityDiscoveryDeadline):
		return "private_login_discovery_deadline"
	case errors.Is(err, errPrivateIdentityDiscoveryMetadata):
		return "private_login_discovery_metadata"
	case errors.Is(err, errPrivateIdentityDiscoveryTransport):
		return "private_login_discovery_transport"
	case errors.Is(err, errPrivateIdentityDiscoveryCheck):
		return "private_login_discovery"
	default:
		return "unclassified"
	}
}

func unavailableDependencies(state *app.RuntimeState) []string {
	if state == nil {
		return nil
	}
	snapshot := state.Snapshot()
	unavailable := make([]string, 0, len(snapshot.Components))
	for _, component := range state.RequiredComponents() {
		name := component.String()
		if snapshot.Components[name] != app.ComponentStatusReady.String() {
			unavailable = append(unavailable, name)
		}
	}
	return unavailable
}
