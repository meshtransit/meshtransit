package control

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

// ErrInvalidBrowserCompletionService reports invalid completion composition.
var ErrInvalidBrowserCompletionService = errors.New("control: invalid browser completion service")

// BrowserCompletionRepository commits or replays only an approved, machine-bound
// registration. The repository owns the authoritative database rechecks.
type BrowserCompletionRepository interface {
	Complete(context.Context, node.RegistrationIdentity, node.Hostname, string) (
		registration.Result, bool, error)
}

// BrowserCompletionService binds Noise follow-up completion to one HTTPS origin.
type BrowserCompletionService struct {
	store  BrowserCompletionRepository
	origin string
}

// NewBrowserCompletionService validates the completion repository and origin.
func NewBrowserCompletionService(
	store BrowserCompletionRepository, origin string,
) (*BrowserCompletionService, error) {
	parsed, err := url.Parse(origin)
	if store == nil || err != nil || parsed.Scheme != "https" ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.Port() != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Opaque != "" || parsed.String() != origin {
		return nil, ErrInvalidBrowserCompletionService
	}
	return &BrowserCompletionService{store: store, origin: origin}, nil
}

// CompleteBrowser checks an exact server-origin FollowupURL against the Noise
// machine and requested Node before exposing a committed Device result.
func (service *BrowserCompletionService) CompleteBrowser(
	ctx context.Context, machine AuthenticatedMachine, nodeKey node.Key,
	hostname node.Hostname, followupURL string,
) (registration.Result, bool, error) {
	if ctx == nil || service == nil || service.store == nil || service.origin == "" {
		return registration.Result{}, false, ErrInvalidBrowserCompletionService
	}
	if !machine.IsValid() || !nodeKey.IsValid() || !hostname.IsValid() {
		return registration.Result{}, false, ErrInvalidBrowserRegistration
	}
	encoded, ok := strings.CutPrefix(followupURL, service.origin+browserRegistrationPath)
	if !ok || strings.Contains(encoded, "/") {
		return registration.Result{}, false, ErrInvalidBrowserRegistration
	}
	if _, err := enrollment.DigestPresentedBrowserIntentToken(encoded); err != nil {
		return registration.Result{}, false, ErrInvalidBrowserRegistration
	}
	identity, err := node.NewRegistrationIdentity(machine.key, nodeKey)
	if err != nil {
		return registration.Result{}, false, ErrInvalidBrowserRegistration
	}
	result, found, err := service.store.Complete(ctx, identity, hostname, encoded)
	if err != nil {
		return registration.Result{}, false, errors.Join(ErrBrowserRegistrationUnavailable, err)
	}
	if found && !result.IsValid() {
		return registration.Result{}, false, ErrBrowserRegistrationUnavailable
	}
	return result, found, nil
}
