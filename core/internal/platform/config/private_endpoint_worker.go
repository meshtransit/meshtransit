package config

import (
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/platform/app"
)

const (
	envPrivateEndpointWorkerEnabled     = "MESHTRANSIT_PRIVATE_ENDPOINT_WORKER_ENABLED"
	envPrivateEndpointDeploymentID      = "MESHTRANSIT_PRIVATE_ENDPOINT_DEPLOYMENT_PUBLIC_ID"
	envPrivateEndpointReconcilerID      = "MESHTRANSIT_PRIVATE_ENDPOINT_RECONCILER_ID"
	envPrivateEndpointBatchSize         = "MESHTRANSIT_PRIVATE_ENDPOINT_BATCH_SIZE"
	envPrivateEndpointPollInterval      = "MESHTRANSIT_PRIVATE_ENDPOINT_POLL_INTERVAL"
	envPrivateEndpointOperationTimeout  = "MESHTRANSIT_PRIVATE_ENDPOINT_OPERATION_TIMEOUT"
	envPrivateEndpointInitialRetryDelay = "MESHTRANSIT_PRIVATE_ENDPOINT_INITIAL_RETRY_DELAY"
	envPrivateEndpointMaximumRetryDelay = "MESHTRANSIT_PRIVATE_ENDPOINT_MAXIMUM_RETRY_DELAY"
	envPrivateEndpointAgentOrigin       = "MESHTRANSIT_PRIVATE_ENDPOINT_AGENT_ORIGIN"
	envPrivateEndpointAgentCAFile       = "MESHTRANSIT_PRIVATE_ENDPOINT_AGENT_CA_FILE"
	envPrivateEndpointAgentCertificate  = "MESHTRANSIT_PRIVATE_ENDPOINT_AGENT_CERTIFICATE_FILE"
	envPrivateEndpointAgentPrivateKey   = "MESHTRANSIT_PRIVATE_ENDPOINT_AGENT_PRIVATE_KEY_FILE"
)

// PrivateEndpointWorkerConfig binds a worker to one Deployment and one exact
// mutually authenticated route-agent origin.
type PrivateEndpointWorkerConfig struct {
	DeploymentID      deployment.ID
	ReconcilerID      string
	BatchSize         int
	PollInterval      time.Duration
	OperationTimeout  time.Duration
	InitialRetryDelay time.Duration
	MaximumRetryDelay time.Duration
	AgentOrigin       string
	AgentCAFile       TrustFile
	AgentCertificate  TrustFile
	AgentPrivateKey   PrivateKeyFile
}

// String redacts assignment and trust-file metadata.
func (PrivateEndpointWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (PrivateEndpointWorkerConfig) GoString() string {
	return "config.PrivateEndpointWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (PrivateEndpointWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadPrivateEndpointWorkerConfig(
	lookup LookupFunc,
	role app.Role,
) (*PrivateEndpointWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envPrivateEndpointWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envPrivateEndpointWorkerEnabled)
	}
	settings := []string{
		envPrivateEndpointDeploymentID, envPrivateEndpointReconcilerID,
		envPrivateEndpointBatchSize, envPrivateEndpointPollInterval,
		envPrivateEndpointOperationTimeout, envPrivateEndpointInitialRetryDelay,
		envPrivateEndpointMaximumRetryDelay, envPrivateEndpointAgentOrigin,
		envPrivateEndpointAgentCAFile, envPrivateEndpointAgentCertificate,
		envPrivateEndpointAgentPrivateKey,
	}
	if enabled == "false" {
		for _, key := range settings {
			if _, present := lookup(key); present {
				return nil, settingError(key)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envPrivateEndpointWorkerEnabled)
	}
	deploymentID, err := deployment.ParseID(valueOrDefault(lookup, envPrivateEndpointDeploymentID, ""))
	if err != nil {
		return nil, settingError(envPrivateEndpointDeploymentID)
	}
	reconcilerID, err := requiredValue(lookup, envPrivateEndpointReconcilerID, validateReconcilerID)
	if err != nil {
		return nil, err
	}
	batchSize, err := parseIntInRange(
		valueOrDefault(lookup, envPrivateEndpointBatchSize, strconv.Itoa(8)), 1, 128,
	)
	if err != nil {
		return nil, settingError(envPrivateEndpointBatchSize)
	}
	pollInterval, err := parseDurationInRange(
		valueOrDefault(lookup, envPrivateEndpointPollInterval, time.Second.String()),
		100*time.Millisecond, time.Minute,
	)
	if err != nil {
		return nil, settingError(envPrivateEndpointPollInterval)
	}
	operationTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envPrivateEndpointOperationTimeout, (5*time.Second).String()),
		100*time.Millisecond, 30*time.Second,
	)
	if err != nil {
		return nil, settingError(envPrivateEndpointOperationTimeout)
	}
	initialRetryDelay, err := parseDurationInRange(
		valueOrDefault(lookup, envPrivateEndpointInitialRetryDelay, time.Second.String()),
		100*time.Millisecond, time.Hour,
	)
	if err != nil {
		return nil, settingError(envPrivateEndpointInitialRetryDelay)
	}
	maximumRetryDelay, err := parseDurationInRange(
		valueOrDefault(lookup, envPrivateEndpointMaximumRetryDelay, time.Minute.String()),
		100*time.Millisecond, time.Hour,
	)
	if err != nil || maximumRetryDelay < initialRetryDelay {
		return nil, settingError(envPrivateEndpointMaximumRetryDelay)
	}
	agentOrigin, err := requiredValue(lookup, envPrivateEndpointAgentOrigin, validateRouteAgentOrigin)
	if err != nil {
		return nil, err
	}
	caPath, err := requiredFile(lookup, envPrivateEndpointAgentCAFile)
	if err != nil {
		return nil, err
	}
	certificatePath, err := requiredFile(lookup, envPrivateEndpointAgentCertificate)
	if err != nil {
		return nil, err
	}
	privateKeyPath, err := requiredFile(lookup, envPrivateEndpointAgentPrivateKey)
	if err != nil {
		return nil, err
	}
	return &PrivateEndpointWorkerConfig{
		DeploymentID: deploymentID, ReconcilerID: reconcilerID, BatchSize: batchSize,
		PollInterval: pollInterval, OperationTimeout: operationTimeout,
		InitialRetryDelay: initialRetryDelay, MaximumRetryDelay: maximumRetryDelay,
		AgentOrigin: agentOrigin, AgentCAFile: TrustFile{path: caPath},
		AgentCertificate: TrustFile{path: certificatePath},
		AgentPrivateKey:  PrivateKeyFile{path: privateKeyPath},
	}, nil
}

func validateReconcilerID(value string) error {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return ErrInvalid
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' ||
			character == ':' || character == '-' {
			continue
		}
		return ErrInvalid
	}
	return nil
}

func validateRouteAgentOrigin(value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return ErrInvalid
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(parsed.Host, ":") {
		return ErrInvalid
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || value == 0 {
			return ErrInvalid
		}
	}
	return nil
}
