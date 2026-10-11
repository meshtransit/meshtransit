package postgres

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

type postgresOperation string

const (
	postgresOperationPing                      postgresOperation = "ping"
	postgresOperationWritableCheck             postgresOperation = "writable_check"
	postgresOperationSchemaCheck               postgresOperation = "schema_check"
	postgresOperationRegistrationReplay        postgresOperation = "registration_replay"
	postgresOperationRegistrationBegin         postgresOperation = "registration_begin"
	postgresOperationRegistrationResolve       postgresOperation = "registration_resolve"
	postgresOperationRegistrationApply         postgresOperation = "registration_apply"
	postgresOperationRegistrationCommit        postgresOperation = "registration_commit"
	postgresOperationRegistrationRollback      postgresOperation = "registration_rollback"
	postgresOperationIntakeBegin               postgresOperation = "registration_intake_begin"
	postgresOperationIntakeResolve             postgresOperation = "registration_intake_resolve"
	postgresOperationIntakeApply               postgresOperation = "registration_intake_apply"
	postgresOperationIntakeCommit              postgresOperation = "registration_intake_commit"
	postgresOperationIntakeRollback            postgresOperation = "registration_intake_rollback"
	postgresOperationIntakeReplay              postgresOperation = "registration_intake_replay"
	postgresOperationMapSessionSnapshot        postgresOperation = "map_session_snapshot"
	postgresOperationMapSessionClientVersion   postgresOperation = "map_session_client_version"
	postgresOperationMapSessionInventory       postgresOperation = "map_session_inventory"
	postgresOperationPolicyPublicationBegin    postgresOperation = "policy_publication_begin"
	postgresOperationPolicyPublicationResolve  postgresOperation = "policy_publication_resolve"
	postgresOperationPolicyPublicationApply    postgresOperation = "policy_publication_apply"
	postgresOperationPolicyPublicationCommit   postgresOperation = "policy_publication_commit"
	postgresOperationPolicyPublicationRollback postgresOperation = "policy_publication_rollback"
	postgresOperationPolicyPublicationReplay   postgresOperation = "policy_publication_replay"
)

const (
	postgresOperationPolicyApprovalRequestBegin     postgresOperation = "policy_approval_request_begin"
	postgresOperationPolicyApprovalRequestResolve   postgresOperation = "policy_approval_request_resolve"
	postgresOperationPolicyApprovalRequestApply     postgresOperation = "policy_approval_request_apply"
	postgresOperationPolicyApprovalRequestCommit    postgresOperation = "policy_approval_request_commit"
	postgresOperationPolicyApprovalRequestRollback  postgresOperation = "policy_approval_request_rollback"
	postgresOperationPolicyApprovalRequestReplay    postgresOperation = "policy_approval_request_replay"
	postgresOperationPolicyApprovalDecisionBegin    postgresOperation = "policy_approval_decision_begin"
	postgresOperationPolicyApprovalDecisionResolve  postgresOperation = "policy_approval_decision_resolve"
	postgresOperationPolicyApprovalDecisionApply    postgresOperation = "policy_approval_decision_apply"
	postgresOperationPolicyApprovalDecisionCommit   postgresOperation = "policy_approval_decision_commit"
	postgresOperationPolicyApprovalDecisionRollback postgresOperation = "policy_approval_decision_rollback"
	postgresOperationPolicyApprovalDecisionReplay   postgresOperation = "policy_approval_decision_replay"
	postgresOperationPolicyApprovalCatalogRead      postgresOperation = "policy_approval_catalog_read"
	postgresOperationPolicyApprovalCatalogList      postgresOperation = "policy_approval_catalog_list"
)

const (
	postgresOperationResourceAuthorityBegin    postgresOperation = "resource_authority_begin"
	postgresOperationResourceAuthorityResolve  postgresOperation = "resource_authority_resolve"
	postgresOperationResourceAuthorityApply    postgresOperation = "resource_authority_apply"
	postgresOperationResourceAuthorityCommit   postgresOperation = "resource_authority_commit"
	postgresOperationResourceAuthorityRollback postgresOperation = "resource_authority_rollback"
	postgresOperationResourceAuthorityReplay   postgresOperation = "resource_authority_replay"
	postgresOperationDeviceRevocationBegin     postgresOperation = "device_revocation_begin"
	postgresOperationDeviceRevocationResolve   postgresOperation = "device_revocation_resolve"
	postgresOperationDeviceRevocationApply     postgresOperation = "device_revocation_apply"
	postgresOperationDeviceRevocationCommit    postgresOperation = "device_revocation_commit"
	postgresOperationDeviceRevocationRollback  postgresOperation = "device_revocation_rollback"
	postgresOperationDeviceRevocationReplay    postgresOperation = "device_revocation_replay"
	postgresOperationAuthTransactionBegin      postgresOperation = "auth_transaction_begin"
	postgresOperationAuthTransactionCreate     postgresOperation = "auth_transaction_create"
	postgresOperationAuthTransactionCommit     postgresOperation = "auth_transaction_commit"
	postgresOperationAuthTransactionRollback   postgresOperation = "auth_transaction_rollback"
	postgresOperationAuthTransactionReplay     postgresOperation = "auth_transaction_replay"
	postgresOperationAuthTransactionAdmission  postgresOperation = "auth_transaction_admission"
	postgresOperationAuthCreationClock         postgresOperation = "auth_transaction_creation_clock"
	postgresOperationAuthTransactionPending    postgresOperation = "auth_transaction_pending"
	postgresOperationAuthClaimBegin            postgresOperation = "auth_claim_begin"
	postgresOperationAuthClaimApply            postgresOperation = "auth_claim_apply"
	postgresOperationAuthClaimCommit           postgresOperation = "auth_claim_commit"
	postgresOperationAuthClaimRollback         postgresOperation = "auth_claim_rollback"
	postgresOperationAuthFailureBegin          postgresOperation = "auth_failure_begin"
	postgresOperationAuthFailureApply          postgresOperation = "auth_failure_apply"
	postgresOperationAuthFailureCommit         postgresOperation = "auth_failure_commit"
	postgresOperationAuthFailureRollback       postgresOperation = "auth_failure_rollback"
	postgresOperationAuthSubjectResolve        postgresOperation = "auth_subject_resolve"
	postgresOperationAuthIssueBegin            postgresOperation = "auth_issue_begin"
	postgresOperationAuthIssueApply            postgresOperation = "auth_issue_apply"
	postgresOperationAuthIssueCommit           postgresOperation = "auth_issue_commit"
	postgresOperationAuthIssueRollback         postgresOperation = "auth_issue_rollback"
	postgresOperationAuthExpiryList            postgresOperation = "auth_expiry_list"
	postgresOperationAuthExpiryBegin           postgresOperation = "auth_expiry_begin"
	postgresOperationAuthExpiryApply           postgresOperation = "auth_expiry_apply"
	postgresOperationAuthExpiryCommit          postgresOperation = "auth_expiry_commit"
	postgresOperationAuthExpiryRollback        postgresOperation = "auth_expiry_rollback"
	postgresOperationNodeKeyRotationBegin      postgresOperation = "node_key_rotation_begin"
	postgresOperationNodeKeyRotationResolve    postgresOperation = "node_key_rotation_resolve"
	postgresOperationNodeKeyRotationApply      postgresOperation = "node_key_rotation_apply"
	postgresOperationNodeKeyRotationCommit     postgresOperation = "node_key_rotation_commit"
	postgresOperationNodeKeyRotationRollback   postgresOperation = "node_key_rotation_rollback"
	postgresOperationAccountSessionResolve     postgresOperation = "account_session_resolve"
	postgresOperationAccountSessionScopes      postgresOperation = "account_session_scopes"
	postgresOperationConsoleDeviceInventory    postgresOperation = "console_device_inventory"
	postgresOperationDeviceDistribution        postgresOperation = "device_distribution"
	postgresOperationRelayRevocations          postgresOperation = "relay_revocations"
	postgresOperationAccessGraphHistory        postgresOperation = "access_graph_history"
	postgresOperationEnforcementHistory        postgresOperation = "enforcement_history"
	postgresOperationMTCPTimestamp             postgresOperation = "mtcp_timestamp"
	postgresOperationActivePolicyRead          postgresOperation = "active_policy_read"
	postgresOperationAccountSessionCaps        postgresOperation = "account_session_capabilities"
	postgresOperationAccountSessionLogout      postgresOperation = "account_session_logout"
	postgresOperationOutboxBacklog             postgresOperation = "outbox_backlog"
	postgresOperationOutboxClaim               postgresOperation = "outbox_claim"
	postgresOperationOutboxLoadRevision        postgresOperation = "outbox_load_revision"
	postgresOperationOutboxMarkDelivered       postgresOperation = "outbox_mark_delivered"
	postgresOperationOutboxRetry               postgresOperation = "outbox_retry"
)

var (
	// ErrInvalidMetrics indicates missing, duplicate, or uninitialized pools.
	ErrInvalidMetrics  = errors.New("invalid postgres metrics")
	postgresOperations = [...]postgresOperation{
		postgresOperationPing,
		postgresOperationWritableCheck,
		postgresOperationSchemaCheck,
		postgresOperationRegistrationReplay,
		postgresOperationRegistrationBegin,
		postgresOperationRegistrationResolve,
		postgresOperationRegistrationApply,
		postgresOperationRegistrationCommit,
		postgresOperationRegistrationRollback,
		postgresOperationIntakeBegin,
		postgresOperationIntakeResolve,
		postgresOperationIntakeApply,
		postgresOperationIntakeCommit,
		postgresOperationIntakeRollback,
		postgresOperationIntakeReplay,
		postgresOperationMapSessionSnapshot,
		postgresOperationMapSessionClientVersion,
		postgresOperationMapSessionInventory,
		postgresOperationPolicyPublicationBegin,
		postgresOperationPolicyPublicationResolve,
		postgresOperationPolicyPublicationApply,
		postgresOperationPolicyPublicationCommit,
		postgresOperationPolicyPublicationRollback,
		postgresOperationPolicyPublicationReplay,
		postgresOperationPolicyApprovalRequestBegin,
		postgresOperationPolicyApprovalRequestResolve,
		postgresOperationPolicyApprovalRequestApply,
		postgresOperationPolicyApprovalRequestCommit,
		postgresOperationPolicyApprovalRequestRollback,
		postgresOperationPolicyApprovalRequestReplay,
		postgresOperationPolicyApprovalDecisionBegin,
		postgresOperationPolicyApprovalDecisionResolve,
		postgresOperationPolicyApprovalDecisionApply,
		postgresOperationPolicyApprovalDecisionCommit,
		postgresOperationPolicyApprovalDecisionRollback,
		postgresOperationPolicyApprovalDecisionReplay,
		postgresOperationPolicyApprovalCatalogRead,
		postgresOperationPolicyApprovalCatalogList,
		postgresOperationResourceAuthorityBegin,
		postgresOperationResourceAuthorityResolve,
		postgresOperationResourceAuthorityApply,
		postgresOperationResourceAuthorityCommit,
		postgresOperationResourceAuthorityRollback,
		postgresOperationResourceAuthorityReplay,
		postgresOperationDeviceRevocationBegin,
		postgresOperationDeviceRevocationResolve,
		postgresOperationDeviceRevocationApply,
		postgresOperationDeviceRevocationCommit,
		postgresOperationDeviceRevocationRollback,
		postgresOperationDeviceRevocationReplay,
		postgresOperationAuthTransactionBegin,
		postgresOperationAuthTransactionCreate,
		postgresOperationAuthTransactionCommit,
		postgresOperationAuthTransactionRollback,
		postgresOperationAuthTransactionReplay,
		postgresOperationAuthTransactionAdmission,
		postgresOperationAuthCreationClock,
		postgresOperationAuthTransactionPending,
		postgresOperationAuthClaimBegin,
		postgresOperationAuthClaimApply,
		postgresOperationAuthClaimCommit,
		postgresOperationAuthClaimRollback,
		postgresOperationAuthFailureBegin,
		postgresOperationAuthFailureApply,
		postgresOperationAuthFailureCommit,
		postgresOperationAuthFailureRollback,
		postgresOperationAuthSubjectResolve,
		postgresOperationAuthIssueBegin,
		postgresOperationAuthIssueApply,
		postgresOperationAuthIssueCommit,
		postgresOperationAuthIssueRollback,
		postgresOperationAuthExpiryList,
		postgresOperationAuthExpiryBegin,
		postgresOperationAuthExpiryApply,
		postgresOperationAuthExpiryCommit,
		postgresOperationAuthExpiryRollback,
		postgresOperationNodeKeyRotationBegin,
		postgresOperationNodeKeyRotationResolve,
		postgresOperationNodeKeyRotationApply,
		postgresOperationNodeKeyRotationCommit,
		postgresOperationNodeKeyRotationRollback,
		postgresOperationAccountSessionResolve,
		postgresOperationAccountSessionScopes,
		postgresOperationConsoleDeviceInventory,
		postgresOperationDeviceDistribution,
		postgresOperationRelayRevocations,
		postgresOperationAccessGraphHistory,
		postgresOperationEnforcementHistory,
		postgresOperationMTCPTimestamp,
		postgresOperationActivePolicyRead,
		postgresOperationAccountSessionCaps,
		postgresOperationAccountSessionLogout,
		postgresOperationOutboxBacklog,
		postgresOperationOutboxClaim,
		postgresOperationOutboxLoadRevision,
		postgresOperationOutboxMarkDelivered,
		postgresOperationOutboxRetry,
	}
)

type postgresPoolStats struct {
	AcquireSuccessTotal  int64
	AcquireCanceledTotal int64
	EmptyAcquireTotal    int64
	AcquireDuration      time.Duration
	EmptyAcquireWait     time.Duration
	AcquiredConnections  int32
	IdleConnections      int32
	ConstructingConns    int32
	MaxConnections       int32
	NewConnectionsTotal  int64
	IdleDestroyedTotal   int64
	LifetimeDestroyed    int64
}

type postgresPoolMetrics struct {
	role                 PoolRole
	operationTotal       *prometheus.CounterVec
	operationDuration    *prometheus.HistogramVec
	poolStats            func() postgresPoolStats
	poolConnectionsDesc  *prometheus.Desc
	poolLimitDesc        *prometheus.Desc
	poolAcquiresDesc     *prometheus.Desc
	emptyAcquiresDesc    *prometheus.Desc
	acquireDurationDesc  *prometheus.Desc
	emptyAcquireWaitDesc *prometheus.Desc
	connectionsNewDesc   *prometheus.Desc
	connectionsGoneDesc  *prometheus.Desc
}

func newPostgresPoolMetrics(
	role PoolRole,
	poolStats func() postgresPoolStats,
) *postgresPoolMetrics {
	if !role.valid() || poolStats == nil {
		return nil
	}
	// Dashboard: sum by (pool_role, operation, result) (rate(meshtransit_postgres_operations_total[5m]))
	// Alert: sum by (pool_role) (rate(meshtransit_postgres_operations_total{result="error"}[5m])) > 0
	operationTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_postgres_operations_total",
		Help: "Total PostgreSQL operations by fixed pool role, operation, and result.",
	}, []string{"pool_role", "operation", "result"})
	// Dashboard: histogram_quantile(0.99, sum(rate(meshtransit_postgres_operation_duration_seconds_bucket[5m])) by (le, pool_role, operation))
	// Alert: histogram_quantile(0.99, sum(rate(meshtransit_postgres_operation_duration_seconds_bucket[5m])) by (le, pool_role, operation)) > 1
	operationDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_postgres_operation_duration_seconds",
		Help:    "PostgreSQL operation duration in seconds by fixed pool role, operation, and result.",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	}, []string{"pool_role", "operation", "result"})
	for _, operation := range postgresOperations {
		if !operation.validForRole(role) {
			continue
		}
		for _, result := range [...]string{"success", "error"} {
			operationTotal.WithLabelValues(string(role), string(operation), result)
			operationDuration.WithLabelValues(string(role), string(operation), result)
		}
	}

	return &postgresPoolMetrics{
		role:              role,
		operationTotal:    operationTotal,
		operationDuration: operationDuration,
		poolStats:         poolStats,
		// Dashboard: meshtransit_postgres_pool_connections
		// Alert: meshtransit_postgres_pool_connections{state="acquired"} / meshtransit_postgres_pool_connections_max > 0.9
		poolConnectionsDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_connections",
			"Current PostgreSQL pool connections by fixed role and state.",
			[]string{"pool_role", "state"},
			nil,
		),
		// Dashboard: meshtransit_postgres_pool_connections_max
		poolLimitDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_connections_max",
			"Configured maximum PostgreSQL pool connections by fixed role.",
			[]string{"pool_role"},
			nil,
		),
		// Dashboard: sum by (pool_role, result) (rate(meshtransit_postgres_pool_acquires_total[5m]))
		// Alert: rate(meshtransit_postgres_pool_acquires_total{result="canceled"}[5m]) > 0
		poolAcquiresDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_acquires_total",
			"Total PostgreSQL pool acquisition attempts by fixed role and result.",
			[]string{"pool_role", "result"},
			nil,
		),
		// Dashboard: rate(meshtransit_postgres_pool_empty_acquires_total[5m])
		emptyAcquiresDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_empty_acquires_total",
			"Total successful PostgreSQL acquires that waited on an empty pool.",
			[]string{"pool_role"},
			nil,
		),
		// Dashboard: rate(meshtransit_postgres_pool_acquire_duration_seconds_total[5m]) / rate(meshtransit_postgres_pool_acquires_total{result="success"}[5m])
		acquireDurationDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_acquire_duration_seconds_total",
			"Total duration in seconds of successful PostgreSQL pool acquires.",
			[]string{"pool_role"},
			nil,
		),
		// Dashboard: rate(meshtransit_postgres_pool_empty_acquire_wait_seconds_total[5m]) / rate(meshtransit_postgres_pool_empty_acquires_total[5m])
		emptyAcquireWaitDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_empty_acquire_wait_seconds_total",
			"Total wait time in seconds for successful acquires from an empty PostgreSQL pool.",
			[]string{"pool_role"},
			nil,
		),
		// Dashboard: rate(meshtransit_postgres_pool_connections_created_total[5m])
		connectionsNewDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_connections_created_total",
			"Total PostgreSQL pool connections created by fixed role.",
			[]string{"pool_role"},
			nil,
		),
		// Dashboard: sum by (pool_role, reason) (rate(meshtransit_postgres_pool_connections_destroyed_total[5m]))
		connectionsGoneDesc: prometheus.NewDesc(
			"meshtransit_postgres_pool_connections_destroyed_total",
			"Total PostgreSQL pool connections destroyed by fixed role and reason.",
			[]string{"pool_role", "reason"},
			nil,
		),
	}
}

// NewMetricsCollector combines the configured serving pools into one
// process-local collector. Each fixed pool role may appear at most once.
func NewMetricsCollector(pools ...*Pool) (prometheus.Collector, error) {
	if len(pools) == 0 {
		return nil, ErrInvalidMetrics
	}
	metrics := make([]*postgresPoolMetrics, 0, len(pools))
	roles := make(map[PoolRole]struct{}, len(pools))
	for _, pool := range pools {
		if pool == nil || !pool.role.valid() || pool.metrics == nil ||
			pool.metrics.role != pool.role {
			return nil, ErrInvalidMetrics
		}
		if _, exists := roles[pool.metrics.role]; exists {
			return nil, ErrInvalidMetrics
		}
		roles[pool.metrics.role] = struct{}{}
		metrics = append(metrics, pool.metrics)
	}
	return &postgresMetricsCollector{pools: metrics}, nil
}

type postgresMetricsCollector struct {
	pools []*postgresPoolMetrics
}

func (collector *postgresMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	collector.pools[0].describe(descriptions)
}

func (collector *postgresMetricsCollector) Collect(output chan<- prometheus.Metric) {
	for _, metrics := range collector.pools {
		metrics.collect(output)
	}
}

func (metrics *postgresPoolMetrics) describe(descriptions chan<- *prometheus.Desc) {
	metrics.operationTotal.Describe(descriptions)
	metrics.operationDuration.Describe(descriptions)
	descriptions <- metrics.poolConnectionsDesc
	descriptions <- metrics.poolLimitDesc
	descriptions <- metrics.poolAcquiresDesc
	descriptions <- metrics.emptyAcquiresDesc
	descriptions <- metrics.acquireDurationDesc
	descriptions <- metrics.emptyAcquireWaitDesc
	descriptions <- metrics.connectionsNewDesc
	descriptions <- metrics.connectionsGoneDesc
}

func (metrics *postgresPoolMetrics) collect(output chan<- prometheus.Metric) {
	metrics.operationTotal.Collect(output)
	metrics.operationDuration.Collect(output)

	stats := metrics.poolStats()
	role := string(metrics.role)
	collectGauge(output, metrics.poolConnectionsDesc, stats.AcquiredConnections, role, "acquired")
	collectGauge(output, metrics.poolConnectionsDesc, stats.IdleConnections, role, "idle")
	collectGauge(output, metrics.poolConnectionsDesc, stats.ConstructingConns, role, "constructing")
	collectGauge(output, metrics.poolLimitDesc, stats.MaxConnections, role)
	collectCounter(output, metrics.poolAcquiresDesc, stats.AcquireSuccessTotal, role, "success")
	collectCounter(output, metrics.poolAcquiresDesc, stats.AcquireCanceledTotal, role, "canceled")
	collectCounter(output, metrics.emptyAcquiresDesc, stats.EmptyAcquireTotal, role)
	collectDurationCounter(output, metrics.acquireDurationDesc, stats.AcquireDuration, role)
	collectDurationCounter(output, metrics.emptyAcquireWaitDesc, stats.EmptyAcquireWait, role)
	collectCounter(output, metrics.connectionsNewDesc, stats.NewConnectionsTotal, role)
	collectCounter(output, metrics.connectionsGoneDesc, stats.IdleDestroyedTotal, role, "idle")
	collectCounter(output, metrics.connectionsGoneDesc, stats.LifetimeDestroyed, role, "lifetime")
}

func (metrics *postgresPoolMetrics) observeOperation(
	operation postgresOperation,
	duration time.Duration,
	err error,
) {
	if metrics == nil {
		return
	}
	if !operation.validForRole(metrics.role) {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	labels := []string{string(metrics.role), string(operation), result}
	metrics.operationTotal.WithLabelValues(labels...).Inc()
	metrics.operationDuration.WithLabelValues(labels...).Observe(max(duration.Seconds(), 0))
}

func (operation postgresOperation) validForRole(role PoolRole) bool {
	if operation == postgresOperationPing || operation == postgresOperationWritableCheck ||
		operation == postgresOperationSchemaCheck {
		return role.valid()
	}
	if role == PoolRoleRuntime {
		return operation == postgresOperationRegistrationReplay ||
			operation == postgresOperationRegistrationBegin ||
			operation == postgresOperationRegistrationResolve ||
			operation == postgresOperationRegistrationApply ||
			operation == postgresOperationRegistrationCommit ||
			operation == postgresOperationRegistrationRollback ||
			operation == postgresOperationIntakeBegin ||
			operation == postgresOperationIntakeResolve ||
			operation == postgresOperationIntakeApply ||
			operation == postgresOperationIntakeCommit ||
			operation == postgresOperationIntakeRollback ||
			operation == postgresOperationIntakeReplay ||
			operation == postgresOperationMapSessionSnapshot || operation == postgresOperationMapSessionClientVersion ||
			operation == postgresOperationMapSessionInventory ||
			operation == postgresOperationPolicyPublicationBegin ||
			operation == postgresOperationPolicyPublicationResolve ||
			operation == postgresOperationPolicyPublicationApply ||
			operation == postgresOperationPolicyPublicationCommit ||
			operation == postgresOperationPolicyPublicationRollback ||
			operation == postgresOperationPolicyPublicationReplay ||
			operation == postgresOperationPolicyApprovalRequestBegin ||
			operation == postgresOperationPolicyApprovalRequestResolve ||
			operation == postgresOperationPolicyApprovalRequestApply ||
			operation == postgresOperationPolicyApprovalRequestCommit ||
			operation == postgresOperationPolicyApprovalRequestRollback ||
			operation == postgresOperationPolicyApprovalRequestReplay ||
			operation == postgresOperationPolicyApprovalDecisionBegin ||
			operation == postgresOperationPolicyApprovalDecisionResolve ||
			operation == postgresOperationPolicyApprovalDecisionApply ||
			operation == postgresOperationPolicyApprovalDecisionCommit ||
			operation == postgresOperationPolicyApprovalDecisionRollback ||
			operation == postgresOperationPolicyApprovalDecisionReplay ||
			operation == postgresOperationResourceAuthorityBegin ||
			operation == postgresOperationResourceAuthorityResolve ||
			operation == postgresOperationResourceAuthorityApply ||
			operation == postgresOperationResourceAuthorityCommit ||
			operation == postgresOperationResourceAuthorityRollback ||
			operation == postgresOperationResourceAuthorityReplay ||
			operation == postgresOperationDeviceRevocationBegin ||
			operation == postgresOperationDeviceRevocationResolve ||
			operation == postgresOperationDeviceRevocationApply ||
			operation == postgresOperationDeviceRevocationCommit ||
			operation == postgresOperationDeviceRevocationRollback ||
			operation == postgresOperationDeviceRevocationReplay ||
			operation == postgresOperationAuthTransactionBegin ||
			operation == postgresOperationAuthTransactionCreate ||
			operation == postgresOperationAuthTransactionCommit ||
			operation == postgresOperationAuthTransactionRollback ||
			operation == postgresOperationAuthTransactionReplay ||
			operation == postgresOperationAuthTransactionAdmission ||
			operation == postgresOperationAuthCreationClock ||
			operation == postgresOperationAuthTransactionPending ||
			operation == postgresOperationAuthClaimBegin ||
			operation == postgresOperationAuthClaimApply ||
			operation == postgresOperationAuthClaimCommit ||
			operation == postgresOperationAuthClaimRollback ||
			operation == postgresOperationAuthFailureBegin ||
			operation == postgresOperationAuthFailureApply ||
			operation == postgresOperationAuthFailureCommit ||
			operation == postgresOperationAuthFailureRollback ||
			operation == postgresOperationAuthSubjectResolve ||
			operation == postgresOperationAuthIssueBegin ||
			operation == postgresOperationAuthIssueApply ||
			operation == postgresOperationAuthIssueCommit ||
			operation == postgresOperationAuthIssueRollback ||
			operation == postgresOperationNodeKeyRotationBegin ||
			operation == postgresOperationNodeKeyRotationResolve ||
			operation == postgresOperationNodeKeyRotationApply ||
			operation == postgresOperationNodeKeyRotationCommit ||
			operation == postgresOperationNodeKeyRotationRollback ||
			operation == postgresOperationAccountSessionResolve ||
			operation == postgresOperationAccountSessionScopes ||
			operation == postgresOperationConsoleDeviceInventory ||
			operation == postgresOperationDeviceDistribution ||
			operation == postgresOperationRelayRevocations ||
			operation == postgresOperationAccessGraphHistory ||
			operation == postgresOperationEnforcementHistory ||
			operation == postgresOperationMTCPTimestamp ||
			operation == postgresOperationActivePolicyRead ||
			operation == postgresOperationAccountSessionCaps ||
			operation == postgresOperationAccountSessionLogout
	}
	if role != PoolRoleWorker {
		return false
	}
	return operation == postgresOperationAuthExpiryList ||
		operation == postgresOperationAuthExpiryBegin ||
		operation == postgresOperationAuthExpiryApply ||
		operation == postgresOperationAuthExpiryCommit ||
		operation == postgresOperationAuthExpiryRollback ||
		operation == postgresOperationOutboxBacklog ||
		operation == postgresOperationOutboxClaim ||
		operation == postgresOperationOutboxLoadRevision ||
		operation == postgresOperationOutboxMarkDelivered ||
		operation == postgresOperationOutboxRetry
}

func collectGauge(
	output chan<- prometheus.Metric,
	description *prometheus.Desc,
	value int32,
	labels ...string,
) {
	output <- prometheus.MustNewConstMetric(
		description,
		prometheus.GaugeValue,
		float64(max(value, 0)),
		labels...,
	)
}

func collectCounter(
	output chan<- prometheus.Metric,
	description *prometheus.Desc,
	value int64,
	labels ...string,
) {
	output <- prometheus.MustNewConstMetric(
		description,
		prometheus.CounterValue,
		float64(max(value, 0)),
		labels...,
	)
}

func collectDurationCounter(
	output chan<- prometheus.Metric,
	description *prometheus.Desc,
	value time.Duration,
	labels ...string,
) {
	output <- prometheus.MustNewConstMetric(
		description,
		prometheus.CounterValue,
		max(value.Seconds(), 0),
		labels...,
	)
}

func snapshotPostgresPoolStats(stats *pgxpool.Stat) postgresPoolStats {
	if stats == nil {
		return postgresPoolStats{}
	}
	return postgresPoolStats{
		AcquireSuccessTotal:  stats.AcquireCount(),
		AcquireCanceledTotal: stats.CanceledAcquireCount(),
		EmptyAcquireTotal:    stats.EmptyAcquireCount(),
		AcquireDuration:      stats.AcquireDuration(),
		EmptyAcquireWait:     stats.EmptyAcquireWaitTime(),
		AcquiredConnections:  stats.AcquiredConns(),
		IdleConnections:      stats.IdleConns(),
		ConstructingConns:    stats.ConstructingConns(),
		MaxConnections:       stats.MaxConns(),
		NewConnectionsTotal:  stats.NewConnsCount(),
		IdleDestroyedTotal:   stats.MaxIdleDestroyCount(),
		LifetimeDestroyed:    stats.MaxLifetimeDestroyCount(),
	}
}
