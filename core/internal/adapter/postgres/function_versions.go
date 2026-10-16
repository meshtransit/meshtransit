package postgres

import (
	"context"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	postgresmapsession "meshtransit.net/core/internal/adapter/postgres/mapsession"
	"meshtransit.net/core/migrations"
)

// functionPath names one runtime path that picks the newest function version
// its role may execute, so a pending operator step silently keeps an older,
// more limited version. Values are stable metric labels.
type functionPath string

const (
	functionPathPolicyPublication          functionPath = "policy_publication"
	functionPathImportedPolicyDestinations functionPath = "imported_policy_destinations"
	functionPathShareDecision              functionPath = "share_decision"
	functionPathDeviceAliasWorker          functionPath = "device_alias_worker"
	functionPathAliasMapEdges              functionPath = postgresmapsession.FunctionPathAliasMapEdges
	functionPathSharingDependencies        functionPath = postgresmapsession.FunctionPathSharingDependencies
)

type functionPathSpec struct {
	// newest is the version this binary uses once everything is granted.
	newest int
	// step is the operator step that grants newest, or empty when its
	// migration grants it.
	step string
}

var functionPathSpecs = map[functionPath]functionPathSpec{
	// publish_compiled_policy_v2 (10000 Imported Resources instead of 256).
	functionPathPolicyPublication: {newest: 2},
	// resolve_imported_policy_destinations_v2 (10000 instead of 256).
	functionPathImportedPolicyDestinations: {newest: 2, step: "000148_policy_imported_resource_scale_ownership"},
	// decide_resource_share_offer_v6 (one live share of a Device per Network, MT013).
	functionPathShareDecision: {newest: 6, step: "000151_device_shared_once_ownership"},
	// prepare_device_alias_change_v5 with load_device_alias_work_v4.
	functionPathDeviceAliasWorker: {newest: 5, step: "000171_device_alias_provider_readmission_ownership"},
	// load_device_alias_map_edges_v7 (the map peer limit, key lookup).
	functionPathAliasMapEdges: {newest: 7, step: "000155_share_reader_key_lookup_ownership"},
	// load_device_sharing_dependencies_v6 (each remote Network once).
	functionPathSharingDependencies: {newest: 6, step: "000156_dependency_reader_network_once_ownership"},
}

// ObserveFunctionVersion records the reader version a map load selected.
func (metrics *postgresPoolMetrics) ObserveFunctionVersion(ctx context.Context, path string, version int) {
	metrics.observeFunctionVersion(ctx, functionPath(path), version)
}

func newFunctionVersionGauge() *prometheus.GaugeVec {
	// Dashboard: meshtransit_postgres_function_version
	// Alert: a path below its newest version for hours after a rollout means an operator step is pending.
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "meshtransit_postgres_function_version",
		Help: "Function version the last call of each runtime path selected, by fixed pool role and path.",
	}, []string{"pool_role", "path"})
}

func newOperatorStepsPendingGauge() *prometheus.GaugeVec {
	// Dashboard: meshtransit_postgres_operator_steps_pending
	// Alert: max(meshtransit_postgres_operator_steps_pending) > 0 for 24h
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "meshtransit_postgres_operator_steps_pending",
		Help: "Operator SQL steps of applied migrations that do not hold, by fixed pool role.",
	}, []string{"pool_role"})
}

// observeFunctionVersion records the version a path selected and logs when
// it changes: a warning naming the operator step while it is not the newest.
func (metrics *postgresPoolMetrics) observeFunctionVersion(ctx context.Context, path functionPath, version int) {
	if metrics == nil || metrics.functionVersion == nil {
		return
	}
	spec, known := functionPathSpecs[path]
	if !known {
		return
	}
	metrics.functionVersion.WithLabelValues(string(metrics.role), string(path)).Set(float64(version))
	metrics.stateMu.Lock()
	previous, seen := metrics.functionVersions[path]
	metrics.functionVersions[path] = version
	metrics.stateMu.Unlock()
	if seen && previous == version || metrics.logger == nil {
		return
	}
	if version >= spec.newest {
		metrics.logger.InfoContext(ctx, "postgres function version selected",
			"pool_role", string(metrics.role), "path", string(path), "version", version)
		return
	}
	attributes := []any{"pool_role", string(metrics.role), "path", string(path), "version", version,
		"newest_version", spec.newest}
	if spec.step != "" {
		attributes = append(attributes, "operator_step", spec.step)
	}
	metrics.logger.WarnContext(ctx, "postgres function version below newest; operator step pending", attributes...)
}

// operatorStepSnapshot is one background read: the pending operator steps
// and the role memberships MeshTransit roles take part in.
type operatorStepSnapshot struct {
	Pending     []string
	Memberships []string
}

// observeOperatorSteps records one background read. It logs when the
// pending steps or the memberships change, and once per failing streak.
func (metrics *postgresPoolMetrics) observeOperatorSteps(ctx context.Context, snapshot operatorStepSnapshot, err error) {
	if metrics == nil || metrics.operatorStepsPending == nil || metrics.roleMemberships == nil {
		return
	}
	role := string(metrics.role)
	metrics.stateMu.Lock()
	wasFailing := metrics.operatorCheckFailing
	metrics.operatorCheckFailing = err != nil
	pendingKey := strings.Join(snapshot.Pending, ",")
	membershipKey := strings.Join(snapshot.Memberships, ",")
	pendingChanged := err == nil && (!metrics.operatorStepsKnown || metrics.operatorStepsKey != pendingKey)
	membershipsChanged := err == nil && (!metrics.operatorStepsKnown || metrics.membershipsKey != membershipKey)
	if err == nil {
		metrics.operatorStepsKnown = true
		metrics.operatorStepsKey = pendingKey
		metrics.membershipsKey = membershipKey
	}
	metrics.stateMu.Unlock()
	if err != nil {
		// -1: unknown, so a stale count never reads as "nothing pending".
		metrics.operatorStepsPending.WithLabelValues(role).Set(-1)
		metrics.roleMemberships.WithLabelValues(role).Set(-1)
		if !wasFailing && metrics.logger != nil {
			metrics.logger.WarnContext(ctx, "postgres operator step check failed",
				"pool_role", role, "error_code", "operator_step_check_failure", "error", err)
		}
		return
	}
	metrics.operatorStepsPending.WithLabelValues(role).Set(float64(len(snapshot.Pending)))
	metrics.roleMemberships.WithLabelValues(role).Set(float64(len(snapshot.Memberships)))
	if metrics.logger == nil {
		return
	}
	switch {
	case pendingChanged && len(snapshot.Pending) == 0:
		metrics.logger.InfoContext(ctx, "postgres operator steps applied", "pool_role", role)
	case pendingChanged:
		metrics.logger.WarnContext(ctx, "postgres operator steps pending", "pool_role", role,
			"pending_count", len(snapshot.Pending), "pending_steps", slices.Clone(snapshot.Pending))
	}
	switch {
	case membershipsChanged && len(snapshot.Memberships) != 0:
		metrics.logger.WarnContext(ctx, "postgres role memberships of MeshTransit roles", "pool_role", role,
			"error_code", "role_membership_found", "role_memberships", slices.Clone(snapshot.Memberships))
	case membershipsChanged && membershipKey == "" && metrics.membershipsSeen:
		metrics.logger.InfoContext(ctx, "postgres role memberships cleared", "pool_role", role)
	}
	if len(snapshot.Memberships) != 0 {
		metrics.stateMu.Lock()
		metrics.membershipsSeen = true
		metrics.stateMu.Unlock()
	}
}

func newRoleMembershipsGauge() *prometheus.GaugeVec {
	// Dashboard: meshtransit_postgres_role_memberships
	// Alert: max(meshtransit_postgres_role_memberships) > 0
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "meshtransit_postgres_role_memberships",
		Help: "Role memberships MeshTransit roles take part in (there must be none), by fixed pool role.",
	}, []string{"pool_role"})
}

// checkOperatorSteps names the pending steps of a schema the binary checked
// as current: every catalog step's migration is applied.
func checkOperatorSteps(ctx context.Context, queryRow operatorQueryRow) (operatorStepSnapshot, error) {
	catalog := migrations.Catalog()
	if len(catalog) == 0 {
		return operatorStepSnapshot{}, ErrOperatorCatalog
	}
	report, err := readOperatorReport(ctx, queryRow, catalog[len(catalog)-1].Version)
	if err != nil {
		return operatorStepSnapshot{}, err
	}
	pending := report.Pending()
	names := make([]string, len(pending))
	for index, step := range pending {
		names[index] = step.Name
	}
	return operatorStepSnapshot{Pending: names, Memberships: slices.Clone(report.Memberships)}, nil
}
