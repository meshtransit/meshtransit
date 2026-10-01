package control

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// BrowserWorkspaceChoiceReader reads current Session-bound Workspace membership
// and exact enrollment eligibility within one explicitly selected Workspace.
type BrowserWorkspaceChoiceReader interface {
	ReadBrowserEnrollmentWorkspaces(context.Context, deployment.ID, int64,
		accountsession.Digest, workspace.ID, int) (enrollment.BrowserEnrollmentWorkspaceChoices, bool, error)
	ReadBrowserEnrollmentNetworksInWorkspace(context.Context, deployment.ID, int64,
		accountsession.Digest, workspace.ID, network.ID, int) (enrollment.BrowserEnrollmentChoices, bool, error)
}

// BrowserWorkspaceChoicePage is the first, read-only stage of device enrollment.
type BrowserWorkspaceChoicePage struct {
	Landing enrollment.BrowserIntentLanding
	Choices enrollment.BrowserEnrollmentWorkspaceChoices
	HasMore bool
}

// BrowserWorkspaceChoiceService requires an explicit Workspace before reading
// Networks. Account Session login context is preserved across Workspace choices.
type BrowserWorkspaceChoiceService struct {
	landing      BrowserLandingReader
	choices      BrowserWorkspaceChoiceReader
	deploymentID deployment.ID
	epoch        int64
}

// NewBrowserWorkspaceChoiceService binds both stages to one recovery epoch.
func NewBrowserWorkspaceChoiceService(landing BrowserLandingReader, choices BrowserWorkspaceChoiceReader,
	deploymentID deployment.ID, epoch int64,
) (*BrowserWorkspaceChoiceService, error) {
	if landing == nil || choices == nil || !deploymentID.IsValid() || epoch <= 0 {
		return nil, ErrInvalidBrowserChoiceService
	}
	return &BrowserWorkspaceChoiceService{landing: landing, choices: choices,
		deploymentID: deploymentID, epoch: epoch}, nil
}

// ReadWorkspaces returns current memberships without choosing one automatically.
func (service *BrowserWorkspaceChoiceService) ReadWorkspaces(ctx context.Context,
	digest accountsession.Digest, token string, after workspace.ID, limit int,
) (BrowserWorkspaceChoicePage, bool, error) {
	if !after.IsValid() && after != (workspace.ID{}) {
		return BrowserWorkspaceChoicePage{}, false, ErrInvalidBrowserChoice
	}
	landing, found, err := service.readLanding(ctx, digest, token, limit)
	if err != nil || !found || landing.State == "approved" {
		return BrowserWorkspaceChoicePage{Landing: landing}, found, err
	}
	choices, found, err := service.choices.ReadBrowserEnrollmentWorkspaces(ctx,
		service.deploymentID, service.epoch, digest, after, limit+1)
	if err != nil {
		return BrowserWorkspaceChoicePage{}, false, errors.Join(ErrBrowserChoiceUnavailable, err)
	}
	if !found {
		return BrowserWorkspaceChoicePage{}, false, nil
	}
	if !choices.IsValid() || len(choices.Workspaces) > limit+1 ||
		(after.IsValid() && len(choices.Workspaces) > 0 && choices.Workspaces[0].WorkspaceID.String() <= after.String()) {
		return BrowserWorkspaceChoicePage{}, false, ErrBrowserChoiceUnavailable
	}
	hasMore := len(choices.Workspaces) > limit
	if hasMore {
		choices.Workspaces = choices.Workspaces[:limit]
	}
	return BrowserWorkspaceChoicePage{Landing: landing, Choices: choices, HasMore: hasMore}, true, nil
}

// ReadNetworks treats the selected Workspace as a filter. Storage independently
// admits its membership and provider acceptance before exposing any Network.
func (service *BrowserWorkspaceChoiceService) ReadNetworks(ctx context.Context,
	digest accountsession.Digest, token string, selected workspace.ID, after network.ID, limit int,
) (BrowserChoicePage, bool, error) {
	if !selected.IsValid() || (!after.IsValid() && after != (network.ID{})) {
		return BrowserChoicePage{}, false, ErrInvalidBrowserChoice
	}
	landing, found, err := service.readLanding(ctx, digest, token, limit)
	if err != nil || !found || landing.State == "approved" {
		return BrowserChoicePage{Landing: landing}, found, err
	}
	choices, found, err := service.choices.ReadBrowserEnrollmentNetworksInWorkspace(ctx,
		service.deploymentID, service.epoch, digest, selected, after, limit+1)
	if err != nil {
		return BrowserChoicePage{}, false, errors.Join(ErrBrowserChoiceUnavailable, err)
	}
	if !found {
		return BrowserChoicePage{}, false, nil
	}
	if !choices.IsValid() || choices.WorkspaceID != selected || choices.WorkspaceDisplayName == "" ||
		len(choices.Networks) > limit+1 ||
		(after.IsValid() && len(choices.Networks) > 0 && choices.Networks[0].NetworkID.String() <= after.String()) {
		return BrowserChoicePage{}, false, ErrBrowserChoiceUnavailable
	}
	hasMore := len(choices.Networks) > limit
	if hasMore {
		choices.Networks = choices.Networks[:limit]
	}
	return BrowserChoicePage{Landing: landing, Choices: choices, HasMore: hasMore}, true, nil
}

func (service *BrowserWorkspaceChoiceService) readLanding(ctx context.Context,
	digest accountsession.Digest, token string, limit int,
) (enrollment.BrowserIntentLanding, bool, error) {
	if ctx == nil || service == nil || service.landing == nil || service.choices == nil {
		return enrollment.BrowserIntentLanding{}, false, ErrInvalidBrowserChoiceService
	}
	if !digest.IsValid() || limit < 1 || limit > 100 {
		return enrollment.BrowserIntentLanding{}, false, ErrInvalidBrowserChoice
	}
	if _, err := enrollment.DigestPresentedBrowserIntentToken(token); err != nil {
		return enrollment.BrowserIntentLanding{}, false, ErrInvalidBrowserChoice
	}
	if err := ctx.Err(); err != nil {
		return enrollment.BrowserIntentLanding{}, false, errors.Join(ErrBrowserChoiceUnavailable, err)
	}
	landing, found, err := service.landing.ReadLanding(ctx, service.deploymentID, service.epoch, digest, token)
	if err != nil {
		return enrollment.BrowserIntentLanding{}, false, errors.Join(ErrBrowserChoiceUnavailable, err)
	}
	if !found {
		return enrollment.BrowserIntentLanding{}, false, nil
	}
	if !landing.IsValid() || !landing.ExpiresAt.After(time.Now()) {
		return enrollment.BrowserIntentLanding{}, false, ErrBrowserChoiceUnavailable
	}
	return landing, true, nil
}
