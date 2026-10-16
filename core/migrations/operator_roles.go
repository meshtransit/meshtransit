package migrations

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var (
	// operatorApplicationRoles log in: the migrator and the serving roles.
	// A step may grant to or revoke from them, never own with or reset them.
	operatorApplicationRoles = []string{"mesh_migrator", "mesh_runtime", "mesh_worker", "mesh_observer"}
	// operatorInstallOwnerRoles are NOLOGIN owners the installation creates
	// before any migration (see the deployment guide); later owners come
	// from role steps.
	operatorInstallOwnerRoles = []string{"mesh_audit_writer", "mesh_share_writer"}
)

// operatorFunctionOwners maps each function family (the name without its
// _vN suffix) to the one owner role an operator step may hand it to. A new
// family needs a reviewed line here; nothing else can own it.
var operatorFunctionOwners = map[string]string{
	"load_device_alias_map_edges":                         "mesh_device_alias_map_reader",
	"load_device_alias_map_endpoint_edges":                "mesh_device_alias_map_reader",
	"load_device_sharing_dependencies":                    "mesh_device_alias_map_reader",
	"observe_device_alias_version":                        "mesh_device_alias_observer",
	"derive_device_alias_worker_scope":                    "mesh_device_alias_writer",
	"device_alias_change_proof_internal":                  "mesh_device_alias_writer",
	"device_alias_withdrawal_proof_internal":              "mesh_device_alias_writer",
	"finalize_device_alias_change":                        "mesh_device_alias_writer",
	"finalize_device_alias_withdrawal":                    "mesh_device_alias_writer",
	"load_device_alias_work":                              "mesh_device_alias_writer",
	"prepare_device_alias_change":                         "mesh_device_alias_writer",
	"prepare_device_alias_resource_quarantine":            "mesh_device_alias_writer",
	"prepare_device_alias_withdrawal":                     "mesh_device_alias_writer",
	"restore_device_alias_worker_context":                 "mesh_device_alias_writer",
	"save_device_alias_worker_context":                    "mesh_device_alias_writer",
	"load_direct_share_map_edges":                         "mesh_direct_map_reader",
	"activate_resource_share":                             "mesh_share_writer",
	"assert_private_endpoint_scope_internal":              "mesh_share_writer",
	"create_resource_share_offer":                         "mesh_share_writer",
	"decide_resource_share_offer":                         "mesh_share_writer",
	"decide_resource_share_offer_base":                    "mesh_share_writer",
	"finalize_trust_contract_expiry":                      "mesh_share_writer",
	"finalize_trust_contract_device_removal":              "mesh_share_writer",
	"list_trust_contract_device_removals":                 "mesh_share_writer",
	"prepare_trust_contract_device_removal":               "mesh_share_writer",
	"list_expired_trust_contracts":                        "mesh_share_writer",
	"lock_and_resolve_policy_imported_resources_internal": "mesh_share_writer",
	"prepare_trust_contract_expiry":                       "mesh_share_writer",
	"read_compiled_imported_policy_evidence_internal":     "mesh_share_writer",
	"resolve_imported_policy_destinations":                "mesh_share_writer",
	"revoke_resource_share":                               "mesh_share_writer",
	"set_share_scope":                                     "mesh_share_writer",
	"withdraw_direct_device_endpoint_on_contract_end":     "mesh_share_writer",
}

var operatorFunctionVersion = regexp.MustCompile(`_v[0-9]+$`)

// operatorFunctionOwner returns the owner role the family of a signature
// may have, or "" for an unknown family.
func operatorFunctionOwner(signature string) string {
	name, _, _ := strings.Cut(strings.TrimPrefix(signature, "mesh_ops."), "(")
	return operatorFunctionOwners[operatorFunctionVersion.ReplaceAllString(name, "")]
}

// OperatorManagedRoles returns every MeshTransit role: the application
// roles, the install owners and the owner roles the role steps create. It
// fails when the catalog does not parse, so a caller never works from a
// partial list.
func OperatorManagedRoles() ([]string, error) {
	steps, err := parsedOperatorSteps()
	if err != nil {
		return nil, err
	}
	roles := append(slices.Clone(operatorApplicationRoles), operatorInstallOwnerRoles...)
	return append(roles, operatorStepRoles(steps)...), nil
}

// OperatorApplicationRoles returns the roles that log in: the migrator and
// the serving roles.
func OperatorApplicationRoles() []string { return slices.Clone(operatorApplicationRoles) }

func operatorStepRoles(steps []OperatorStep) []string {
	roles := []string{}
	for _, step := range steps {
		for _, effect := range step.Effects {
			if effect.Kind == OperatorEffectRole && !slices.Contains(roles, effect.Role) {
				roles = append(roles, effect.Role)
			}
		}
	}
	return roles
}

// validateOperatorRoles keeps every role of the catalog in fixed sets: a
// role step never names an application or install role, an owner is the
// owner role its function family maps to, a grantee a MeshTransit role, and
// PUBLIC appears only in a REVOKE. A step can therefore never hand a function to, or reset, a
// superuser or any role outside MeshTransit.
func validateOperatorRoles(steps []OperatorStep) error {
	owners := append(slices.Clone(operatorInstallOwnerRoles), operatorStepRoles(steps)...)
	grantees := append(slices.Clone(operatorApplicationRoles), owners...)
	for _, step := range steps {
		for _, effect := range step.Effects {
			allowed := false
			switch effect.Kind {
			case OperatorEffectRole:
				allowed = step.Kind == OperatorStepRole && operatorRoleName.MatchString(effect.Role) &&
					!slices.Contains(operatorApplicationRoles, effect.Role) &&
					!slices.Contains(operatorInstallOwnerRoles, effect.Role)
			case OperatorEffectOwner:
				allowed = slices.Contains(owners, effect.Role) && operatorFunctionOwner(effect.Function) == effect.Role
			case OperatorEffectExecute:
				allowed = slices.Contains(grantees, effect.Role)
			case OperatorEffectNoExecute:
				allowed = effect.Role == "public" || slices.Contains(grantees, effect.Role)
			}
			if !allowed {
				return fmt.Errorf("%w: %s: %s %s outside the role allowlist", ErrInvalidOperatorStep, step.Name,
					effect.Kind, effect.Role)
			}
		}
	}
	return nil
}
