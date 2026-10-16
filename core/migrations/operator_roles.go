package migrations

import (
	"fmt"
	"slices"
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
// role step never names an application or install role, an owner is an
// owner role, a grantee a MeshTransit role, and PUBLIC appears only in a
// REVOKE. A step can therefore never hand a function to, or reset, a
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
				allowed = slices.Contains(owners, effect.Role)
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
