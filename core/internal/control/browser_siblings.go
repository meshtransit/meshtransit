package control

import (
	"context"
	"errors"
	"strings"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

// BrowserSiblingRepository keeps a pending sign-in's proven sibling machine
// keys (duplicate-device design §6.1). Optional on BrowserIntentRepository.
type BrowserSiblingRepository interface {
	RecordSiblings(context.Context, deployment.ID, int64, node.RegistrationIdentity, string, [][32]byte) error
}

// BrowserSiblingCompletionRepository completes with the siblings proven in
// the completing session (design §8.4). Optional on
// BrowserCompletionRepository.
type BrowserSiblingCompletionRepository interface {
	CompleteWithSiblings(context.Context, node.RegistrationIdentity, node.Hostname, string, [][32]byte) (
		registration.Result, bool, error)
}

// RecordSiblings keeps the sibling machine keys the node proved for the
// pending sign-in at approvalURL. Without a repository that keeps them it
// does nothing.
func (service *BrowserRegistrationService) RecordSiblings(
	ctx context.Context, machine AuthenticatedMachine, nodeKey node.Key, approvalURL string, siblings [][32]byte,
) error {
	if ctx == nil || service == nil || service.intents == nil {
		return ErrInvalidBrowserRegistrationService
	}
	repository, ok := service.intents.(BrowserSiblingRepository)
	if !ok || len(siblings) == 0 {
		return nil
	}
	encoded, ok := strings.CutPrefix(approvalURL, service.origin+browserRegistrationPath)
	if !ok || strings.Contains(encoded, "/") || !machine.IsValid() || !nodeKey.IsValid() {
		return ErrInvalidBrowserRegistration
	}
	if _, err := enrollment.DigestPresentedBrowserIntentToken(encoded); err != nil {
		return ErrInvalidBrowserRegistration
	}
	identity, err := node.NewRegistrationIdentity(machine.key, nodeKey)
	if err != nil {
		return ErrInvalidBrowserRegistration
	}
	if err := repository.RecordSiblings(ctx, service.deploymentID, service.epoch, identity, encoded,
		siblings); err != nil {
		return errors.Join(ErrBrowserRegistrationUnavailable, err)
	}
	return nil
}

// CompleteBrowserWithSiblings is CompleteBrowser with the siblings proven in
// the completing session. A sign-in the approver ended with "Use that
// account" returns *registration.JoinedExistingError.
func (service *BrowserCompletionService) CompleteBrowserWithSiblings(
	ctx context.Context, machine AuthenticatedMachine, nodeKey node.Key,
	hostname node.Hostname, followupURL string, siblings [][32]byte,
) (registration.Result, bool, error) {
	repository, ok := service.storeWithSiblings()
	if !ok {
		return service.CompleteBrowser(ctx, machine, nodeKey, hostname, followupURL)
	}
	return service.complete(ctx, machine, nodeKey, hostname, followupURL,
		func(identity node.RegistrationIdentity, encoded string) (registration.Result, bool, error) {
			return repository.CompleteWithSiblings(ctx, identity, hostname, encoded, siblings)
		})
}

func (service *BrowserCompletionService) storeWithSiblings() (BrowserSiblingCompletionRepository, bool) {
	if service == nil {
		return nil, false
	}
	repository, ok := service.store.(BrowserSiblingCompletionRepository)
	return repository, ok
}
