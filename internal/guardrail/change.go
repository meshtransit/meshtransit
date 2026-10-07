package guardrail

import (
	"slices"

	"github.com/meshtransit/meshtransit/internal/authorization"
)

func superset[T comparable](wider, narrower []T) bool {
	for _, value := range narrower {
		if !slices.Contains(wider, value) {
			return false
		}
	}
	return true
}

// covers reports whether next blocks at least everything previous blocked.
func covers(previous, next Spec) bool {
	if previous.Kind != next.Kind {
		return false
	}
	switch previous.Kind {
	case KindNetworkIsolation:
		return superset(next.Isolation.From, previous.Isolation.From) &&
			superset(next.Isolation.To, previous.Isolation.To) &&
			(!previous.Isolation.BothDirections || next.Isolation.BothDirections)
	case KindNetworkSharing:
		return superset(next.Sharing.Networks, previous.Sharing.Networks) &&
			previous.Sharing.Direction.within(next.Sharing.Direction)
	case KindExternalSharing:
		allNetworks := len(next.External.Networks) == 0 ||
			len(previous.External.Networks) > 0 && superset(next.External.Networks, previous.External.Networks)
		return previous.External.Direction.within(next.External.Direction) && allNetworks &&
			superset(previous.External.AllowedWorkspaces, next.External.AllowedWorkspaces)
	default:
		return false
	}
}

// RequiredPermission is the permission a change needs. Adding a guardrail or
// making one stricter needs guardrail.manage; deleting it, switching it from
// enforce to audit, or letting anything through that it used to block needs
// guardrail.weaken. previous is nil for a new guardrail and next is nil for a
// deletion.
func RequiredPermission(previous, next *Spec) authorization.Permission {
	switch {
	case previous == nil:
		return authorization.PermissionGuardrailManage
	case next == nil:
		return authorization.PermissionGuardrailWeaken
	case previous.Mode == ModeEnforce && next.Mode == ModeAudit, !covers(*previous, *next):
		return authorization.PermissionGuardrailWeaken
	default:
		return authorization.PermissionGuardrailManage
	}
}
