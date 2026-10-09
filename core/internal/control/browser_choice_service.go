package control

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

var (
	// ErrInvalidBrowserChoiceService reports invalid choice-reader composition.
	ErrInvalidBrowserChoiceService = errors.New("control: invalid browser choice service")
	// ErrInvalidBrowserChoice reports malformed choice pagination or token input.
	ErrInvalidBrowserChoice = errors.New("control: invalid browser choice request")
	// ErrBrowserChoiceUnavailable reports a failed SSO-bound choice read.
	ErrBrowserChoiceUnavailable = errors.New("control: browser choice unavailable")
)

// BrowserLandingReader resolves an intent only for the current SSO Session.
type BrowserLandingReader interface {
	ReadLanding(context.Context, deployment.ID, int64, accountsession.Digest, string) (
		enrollment.BrowserIntentLanding, bool, error)
}

// BrowserNetworkChoiceReader projects current enrollment memberships for SSO.
type BrowserNetworkChoiceReader interface {
	ReadBrowserEnrollmentNetworks(context.Context, deployment.ID, int64,
		accountsession.Digest, network.ID, int) (enrollment.BrowserEnrollmentChoices, bool, error)
}

// BrowserChoicePage is a read-only SSO projection. Its Networks are choices,
// not authority to enroll; approval must recheck them in one write transaction.
type BrowserChoicePage struct {
	Landing enrollment.BrowserIntentLanding
	Choices enrollment.BrowserEnrollmentChoices
	HasMore bool
}

// BrowserChoiceService combines an SSO-bound intent and current Network choices.
type BrowserChoiceService struct {
	landing      BrowserLandingReader
	networks     BrowserNetworkChoiceReader
	deploymentID deployment.ID
	epoch        int64
}

// NewBrowserChoiceService binds both readers to one Deployment recovery epoch.
func NewBrowserChoiceService(
	landing BrowserLandingReader, networks BrowserNetworkChoiceReader,
	deploymentID deployment.ID, epoch int64,
) (*BrowserChoiceService, error) {
	if landing == nil || networks == nil || !deploymentID.IsValid() || epoch <= 0 {
		return nil, ErrInvalidBrowserChoiceService
	}
	return &BrowserChoiceService{
		landing: landing, networks: networks, deploymentID: deploymentID, epoch: epoch,
	}, nil
}

// Read verifies the same SSO Session against the URL token and exact current
// Network memberships. It never auto-selects a Network, even if only one exists.
func (service *BrowserChoiceService) Read(
	ctx context.Context, sessionDigest accountsession.Digest,
	encodedToken string, after network.ID, limit int,
) (BrowserChoicePage, bool, error) {
	if ctx == nil || service == nil || service.landing == nil || service.networks == nil {
		return BrowserChoicePage{}, false, ErrInvalidBrowserChoiceService
	}
	if !sessionDigest.IsValid() ||
		(!after.IsValid() && after != (network.ID{})) || limit < 1 || limit > 100 {
		return BrowserChoicePage{}, false, ErrInvalidBrowserChoice
	}
	if _, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken); err != nil {
		return BrowserChoicePage{}, false, ErrInvalidBrowserChoice
	}
	if err := ctx.Err(); err != nil {
		return BrowserChoicePage{}, false, errors.Join(ErrBrowserChoiceUnavailable, err)
	}
	landing, found, err := service.landing.ReadLanding(ctx, service.deploymentID,
		service.epoch, sessionDigest, encodedToken)
	if err != nil {
		return BrowserChoicePage{}, false, errors.Join(ErrBrowserChoiceUnavailable, err)
	}
	if !found {
		return BrowserChoicePage{}, false, nil
	}
	if !landing.IsValid() || !landing.ExpiresAt.After(time.Now()) {
		return BrowserChoicePage{}, false, ErrBrowserChoiceUnavailable
	}
	choices, found, err := service.networks.ReadBrowserEnrollmentNetworks(ctx,
		service.deploymentID, service.epoch, sessionDigest, after, limit)
	if err != nil {
		return BrowserChoicePage{}, false, errors.Join(ErrBrowserChoiceUnavailable, err)
	}
	if !found {
		return BrowserChoicePage{}, false, nil
	}
	if !choices.IsValid() || len(choices.Networks) > limit {
		return BrowserChoicePage{}, false, ErrBrowserChoiceUnavailable
	}
	return BrowserChoicePage{Landing: landing, Choices: choices}, true, nil
}
