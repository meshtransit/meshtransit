package main

import (
	"encoding/base64"
	"errors"
	"time"

	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/platform/config"
)

const browserRegistrationTTL = 15 * time.Minute

var errInvalidBrowserRegistrationComposition = errors.New("invalid browser registration composition")

func composeBrowserRegistrationKeys(
	profile *config.BrowserRegistrationConfig,
) (*enrollment.BrowserIntentKeyring, error) {
	if profile == nil || !profile.DeploymentID.IsValid() ||
		profile.RecoveryEpoch <= 0 || !profile.KeyID.IsValid() {
		return nil, errInvalidBrowserRegistrationComposition
	}
	encoded, err := profile.KeyFile.Read()
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	material, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	defer clear(material)
	key, err := enrollment.NewBrowserIntentKey(profile.KeyID, material)
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	keys, err := enrollment.NewBrowserIntentKeyring(key)
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	return keys, nil
}

func composeBrowserControl(
	profile *config.BrowserRegistrationConfig,
	keys *enrollment.BrowserIntentKeyring,
	registrationConfig config.RegistrationConfig,
	runtime *postgresadapter.Pool,
) (*control.BrowserRegistrationService, *control.BrowserCompletionService, error) {
	if profile == nil || keys == nil || runtime == nil {
		return nil, nil, errInvalidBrowserRegistrationComposition
	}
	database := registrationConfig.Database
	intent, err := postgresadapter.NewBrowserIntentStore(runtime,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: database.StatementTimeout,
			IdleTimeout:      database.IdleTimeout,
		}, keys)
	if err != nil {
		return nil, nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	issuer, err := control.NewBrowserRegistrationService(
		intent, profile.DeploymentID, profile.RecoveryEpoch,
		profile.Origin, browserRegistrationTTL,
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	completionStore, err := postgresadapter.NewBrowserCompletionStore(runtime,
		postgresadapter.RegistrationTransactionOptions{
			StatementTimeout: database.StatementTimeout,
			LockTimeout:      database.LockTimeout, IdleTimeout: database.IdleTimeout,
			AddressCandidateLimit: registrationConfig.AddressCandidateLimit,
		}, profile.DeploymentID, profile.RecoveryEpoch)
	if err != nil {
		return nil, nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	completion, err := control.NewBrowserCompletionService(completionStore, profile.Origin)
	if err != nil {
		return nil, nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	return issuer, completion, nil
}

func composeBrowserRegistrationPage(
	profile *config.BrowserRegistrationConfig,
	keys *enrollment.BrowserIntentKeyring,
	factory *privateIdentityFactory,
	runtime *postgresadapter.Pool,
) (*httpapi.BrowserRegistrationPage, error) {
	if profile == nil || keys == nil || factory == nil || factory.identity == nil ||
		factory.identity.management == nil || factory.managementKeys.sessions == nil ||
		runtime == nil {
		return nil, errInvalidBrowserRegistrationComposition
	}
	options := postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second,
	}
	intent, err := postgresadapter.NewBrowserIntentStore(runtime, options, keys)
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	sessions, err := postgresadapter.NewAccountSessionStore(runtime, options)
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	choices, err := control.NewBrowserWorkspaceChoiceService(
		intent, sessions, profile.DeploymentID, profile.RecoveryEpoch,
	)
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	approval, err := postgresadapter.NewBrowserApprovalStore(
		runtime, options, profile.DeploymentID, profile.RecoveryEpoch,
	)
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	page, err := httpapi.NewBrowserRegistrationPage(httpapi.BrowserRegistrationPageOptions{
		Origin: profile.Origin, SessionKeys: factory.managementKeys.sessions,
		Choices: choices, Management: factory.identity.management, Approval: approval,
		Timeout: 5 * time.Second, Concurrency: 16,
	})
	if err != nil {
		return nil, errors.Join(errInvalidBrowserRegistrationComposition, err)
	}
	return page, nil
}
