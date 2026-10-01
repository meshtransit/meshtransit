package control

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const browserRegistrationPath = "/register/v1/"

var (
	// ErrInvalidBrowserRegistrationService reports invalid issuance composition.
	ErrInvalidBrowserRegistrationService = errors.New("control: invalid browser registration service")
	// ErrInvalidBrowserRegistration reports invalid authenticated registration input.
	ErrInvalidBrowserRegistration = errors.New("control: invalid browser registration")
	// ErrBrowserRegistrationUnavailable reports failed issuance or follow-up reads.
	ErrBrowserRegistrationUnavailable = errors.New("control: browser registration unavailable")
)

// BrowserIntentRepository binds URL issuance and polling to durable machine
// evidence. Approval and Device registration are separate operations.
type BrowserIntentRepository interface {
	Issue(context.Context, deployment.ID, int64, node.RegistrationIdentity,
		node.Hostname, enrollment.BrowserIntentID, enrollment.BrowserIntentNonce,
		time.Time) (enrollment.BrowserIntentToken, error)
	ReadFollowup(context.Context, deployment.ID, int64, node.RegistrationIdentity,
		node.Hostname, string) (enrollment.BrowserIntentFollowup, bool, error)
}

// BrowserRegistrationService issues a server-owned AuthURL and checks the
// client's later poll against its Noise-authenticated machine identity.
type BrowserRegistrationService struct {
	intents      BrowserIntentRepository
	deploymentID deployment.ID
	epoch        int64
	origin       string
	ttl          time.Duration
}

// NewBrowserRegistrationService binds intent issuance to one HTTPS origin.
func NewBrowserRegistrationService(
	intents BrowserIntentRepository, deploymentID deployment.ID, epoch int64,
	origin string, ttl time.Duration,
) (*BrowserRegistrationService, error) {
	parsed, err := url.Parse(origin)
	if intents == nil || !deploymentID.IsValid() || epoch <= 0 ||
		ttl < time.Minute || ttl > 15*time.Minute || err != nil ||
		parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Port() != "" || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.String() != origin {
		return nil, ErrInvalidBrowserRegistrationService
	}
	return &BrowserRegistrationService{
		intents: intents, deploymentID: deploymentID, epoch: epoch,
		origin: origin, ttl: ttl,
	}, nil
}

// RegisterBrowser returns the same URL for an initial retry or an uncompleted
// follow-up. An approved intent still needs authoritative Device registration;
// this method never reports MachineAuthorized.
func (service *BrowserRegistrationService) RegisterBrowser(
	ctx context.Context, machine AuthenticatedMachine, nodeKey node.Key,
	hostname node.Hostname, followupURL string,
) (string, error) {
	if ctx == nil || service == nil || service.intents == nil {
		return "", ErrInvalidBrowserRegistrationService
	}
	if !machine.IsValid() || !nodeKey.IsValid() || !hostname.IsValid() {
		return "", ErrInvalidBrowserRegistration
	}
	identity, err := node.NewRegistrationIdentity(machine.key, nodeKey)
	if err != nil {
		return "", ErrInvalidBrowserRegistration
	}
	if err := ctx.Err(); err != nil {
		return "", errors.Join(ErrBrowserRegistrationUnavailable, err)
	}
	if followupURL != "" {
		prefix := service.origin + browserRegistrationPath
		encoded, ok := strings.CutPrefix(followupURL, prefix)
		if !ok || strings.Contains(encoded, "/") {
			return "", ErrInvalidBrowserRegistration
		}
		if _, err := enrollment.DigestPresentedBrowserIntentToken(encoded); err != nil {
			return "", ErrInvalidBrowserRegistration
		}
		state, found, err := service.intents.ReadFollowup(ctx, service.deploymentID,
			service.epoch, identity, hostname, encoded)
		if err != nil {
			return "", errors.Join(ErrBrowserRegistrationUnavailable, err)
		}
		if !found || !state.IsValid() || !state.ExpiresAt.After(time.Now()) {
			return "", ErrInvalidBrowserRegistration
		}
		return followupURL, nil
	}
	publicID, err := publicid.New()
	if err != nil {
		return "", errors.Join(ErrBrowserRegistrationUnavailable, err)
	}
	intentID, err := enrollment.ParseBrowserIntentID(publicID.String())
	if err != nil {
		return "", ErrBrowserRegistrationUnavailable
	}
	nonce, err := enrollment.NewBrowserIntentNonce()
	if err != nil {
		return "", errors.Join(ErrBrowserRegistrationUnavailable, err)
	}
	token, err := service.intents.Issue(ctx, service.deploymentID, service.epoch,
		identity, hostname, intentID, nonce, time.Now().Add(service.ttl))
	if err != nil {
		return "", errors.Join(ErrBrowserRegistrationUnavailable, err)
	}
	encoded := token.Encoded()
	if _, err := enrollment.DigestPresentedBrowserIntentToken(encoded); err != nil {
		return "", ErrBrowserRegistrationUnavailable
	}
	return service.origin + browserRegistrationPath + encoded, nil
}
