package enrollment

import (
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

// BrowserEnrollmentNetworkChoice is a current enrollment option, not a grant.
type BrowserEnrollmentNetworkChoice struct {
	NetworkID   network.ID
	DisplayName string
}

// BrowserEnrollmentChoices is the current, SSO Session-bound Network inventory.
type BrowserEnrollmentChoices struct {
	WorkspaceID          workspace.ID
	WorkspaceDisplayName string
	Networks             []BrowserEnrollmentNetworkChoice
}

// IsValid checks the bounded, ordered Network projection and Session scope.
func (choices BrowserEnrollmentChoices) IsValid() bool {
	if !choices.WorkspaceID.IsValid() || choices.Networks == nil || len(choices.Networks) > 101 {
		return false
	}
	previous := network.ID{}
	for _, choice := range choices.Networks {
		if !choice.NetworkID.IsValid() || choice.DisplayName == "" ||
			(previous.IsValid() && choice.NetworkID.String() <= previous.String()) {
			return false
		}
		previous = choice.NetworkID
	}
	return true
}
