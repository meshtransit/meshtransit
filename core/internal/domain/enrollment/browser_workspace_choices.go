package enrollment

import "github.com/meshtransit/meshtransit/core/internal/domain/workspace"

// BrowserEnrollmentWorkspaceChoice is a current membership view, never a grant.
type BrowserEnrollmentWorkspaceChoice struct {
	WorkspaceID workspace.ID
	DisplayName string
}

// BrowserEnrollmentWorkspaceChoices lists Workspaces admitted by the current
// Account Session, including memberships in Workspaces owned by other accounts.
type BrowserEnrollmentWorkspaceChoices struct {
	Workspaces []BrowserEnrollmentWorkspaceChoice
}

// IsValid checks the bounded, strictly ordered Workspace inventory.
func (choices BrowserEnrollmentWorkspaceChoices) IsValid() bool {
	if choices.Workspaces == nil || len(choices.Workspaces) > 101 {
		return false
	}
	previous := workspace.ID{}
	for _, choice := range choices.Workspaces {
		if !choice.WorkspaceID.IsValid() || choice.DisplayName == "" ||
			(previous.IsValid() && choice.WorkspaceID.String() <= previous.String()) {
			return false
		}
		previous = choice.WorkspaceID
	}
	return true
}
