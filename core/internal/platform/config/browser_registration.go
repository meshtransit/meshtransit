package config

import (
	"net/url"
	"strconv"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
)

const (
	envBrowserRegistrationOrigin        = "MESHTRANSIT_BROWSER_REGISTRATION_ORIGIN"
	envBrowserRegistrationDeploymentID  = "MESHTRANSIT_BROWSER_REGISTRATION_DEPLOYMENT_ID"
	envBrowserRegistrationRecoveryEpoch = "MESHTRANSIT_BROWSER_REGISTRATION_RECOVERY_EPOCH"
	envBrowserRegistrationKeyID         = "MESHTRANSIT_BROWSER_REGISTRATION_KEY_ID"
	envBrowserRegistrationKeyFile       = "MESHTRANSIT_BROWSER_REGISTRATION_KEY_FILE"
)

// BrowserRegistrationConfig enables the same URL and token derivation on the
// public control and private browser listeners. It is opt-in for each role.
type BrowserRegistrationConfig struct {
	Origin        string
	DeploymentID  deployment.ID
	RecoveryEpoch int64
	KeyID         enrollment.BrowserIntentKeyID
	KeyFile       SecretFile
}

func loadBrowserRegistrationConfig(lookup LookupFunc) (*BrowserRegistrationConfig, error) {
	settings := []string{
		envBrowserRegistrationOrigin, envBrowserRegistrationDeploymentID,
		envBrowserRegistrationRecoveryEpoch, envBrowserRegistrationKeyID,
		envBrowserRegistrationKeyFile,
	}
	present := 0
	for _, setting := range settings {
		if _, ok := lookup(setting); ok {
			present++
		}
	}
	if present == 0 {
		return nil, nil
	}
	if present != len(settings) {
		return nil, settingError(envBrowserRegistrationOrigin)
	}
	origin, _ := lookup(envBrowserRegistrationOrigin)
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Port() != "" || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.String() != origin {
		return nil, settingError(envBrowserRegistrationOrigin)
	}
	deploymentValue, _ := lookup(envBrowserRegistrationDeploymentID)
	deploymentID, err := deployment.ParseID(deploymentValue)
	if err != nil {
		return nil, settingError(envBrowserRegistrationDeploymentID)
	}
	epochValue, _ := lookup(envBrowserRegistrationRecoveryEpoch)
	epoch, err := strconv.ParseInt(epochValue, 10, 64)
	if err != nil || epoch <= 0 {
		return nil, settingError(envBrowserRegistrationRecoveryEpoch)
	}
	keyValue, _ := lookup(envBrowserRegistrationKeyID)
	keyID, err := enrollment.NewBrowserIntentKeyID(keyValue)
	if err != nil {
		return nil, settingError(envBrowserRegistrationKeyID)
	}
	keyPath, _ := lookup(envBrowserRegistrationKeyFile)
	keyFile, err := NewSecretFile(keyPath)
	if err != nil {
		return nil, settingError(envBrowserRegistrationKeyFile)
	}
	return &BrowserRegistrationConfig{
		Origin: origin, DeploymentID: deploymentID, RecoveryEpoch: epoch,
		KeyID: keyID, KeyFile: keyFile,
	}, nil
}
