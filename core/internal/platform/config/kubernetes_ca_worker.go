package config

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envKubernetesCAWorkerEnabled    = "MESHTRANSIT_KUBERNETES_CA_WORKER_ENABLED"
	envKubernetesCAWorkerDeployment = "MESHTRANSIT_KUBERNETES_CA_WORKER_DEPLOYMENT_PUBLIC_ID"
	envKubernetesCAWorkerBatch      = "MESHTRANSIT_KUBERNETES_CA_WORKER_BATCH_SIZE"
	envKubernetesCAWorkerPoll       = "MESHTRANSIT_KUBERNETES_CA_WORKER_POLL_INTERVAL"
	envKubernetesCAWorkerTimeout    = "MESHTRANSIT_KUBERNETES_CA_WORKER_OPERATION_TIMEOUT"
	envKubernetesCACustody          = "MESHTRANSIT_KUBERNETES_CA_CUSTODY"
	envKubernetesCAWrapKeyFile      = "MESHTRANSIT_KUBERNETES_CA_WRAP_KEY_FILE"
	envKubernetesCAPreviousKeyFiles = "MESHTRANSIT_KUBERNETES_CA_PREVIOUS_WRAP_KEY_FILES"

	// KubernetesCACustodyFile keeps the wrap key in a secret file.
	KubernetesCACustodyFile = "file"
	// maximumPreviousWrapKeys bounds the older wrap keys kept for opening.
	maximumPreviousWrapKeys = 8
)

// KubernetesCAWorkerConfig assigns the lifecycle of Kubernetes cluster CAs
// (K1a4 §17) to the worker of one installation. Only file custody is wired
// for now; a KMS custody comes before GA (§17.4). Key files are read when
// the worker builds its custody, never here.
type KubernetesCAWorkerConfig struct {
	DeploymentID                   deployment.ID
	BatchSize                      int
	PollInterval, OperationTimeout time.Duration
	Custody                        string
	WrapKeyFile                    SecretFile
	PreviousWrapKeyFiles           []SecretFile
}

// String redacts the trusted assignment in generic formatting.
func (KubernetesCAWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (KubernetesCAWorkerConfig) GoString() string {
	return "config.KubernetesCAWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (KubernetesCAWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadKubernetesCAWorkerConfig(lookup LookupFunc, role app.Role) (*KubernetesCAWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envKubernetesCAWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envKubernetesCAWorkerEnabled)
	}
	settings := []string{
		envKubernetesCAWorkerDeployment, envKubernetesCAWorkerBatch, envKubernetesCAWorkerPoll,
		envKubernetesCAWorkerTimeout, envKubernetesCACustody, envKubernetesCAWrapKeyFile,
		envKubernetesCAPreviousKeyFiles,
	}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envKubernetesCAWorkerEnabled)
	}
	// The worker records the suffix it names clusters under once for the
	// installation; a defaulted one must never be recorded (review a2a M1).
	if _, present := lookup(envDNSSuffix); !present {
		return nil, settingError(envDNSSuffix)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envKubernetesCAWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envKubernetesCAWorkerDeployment)
	}
	batch, err := parseIntInRange(valueOrDefault(lookup, envKubernetesCAWorkerBatch, strconv.Itoa(16)), 1, 64)
	if err != nil {
		return nil, settingError(envKubernetesCAWorkerBatch)
	}
	poll, err := parseDurationInRange(valueOrDefault(lookup, envKubernetesCAWorkerPoll, "30s"), time.Second,
		5*time.Minute)
	if err != nil {
		return nil, settingError(envKubernetesCAWorkerPoll)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envKubernetesCAWorkerTimeout, "20s"), time.Second,
		time.Minute)
	if err != nil {
		return nil, settingError(envKubernetesCAWorkerTimeout)
	}
	if valueOrDefault(lookup, envKubernetesCACustody, KubernetesCACustodyFile) != KubernetesCACustodyFile {
		return nil, settingError(envKubernetesCACustody)
	}
	wrapKey, err := NewSecretFile(valueOrDefault(lookup, envKubernetesCAWrapKeyFile, ""))
	if err != nil {
		return nil, settingError(envKubernetesCAWrapKeyFile)
	}
	previous, err := loadPreviousWrapKeyFiles(lookup)
	if err != nil {
		return nil, err
	}
	return &KubernetesCAWorkerConfig{
		DeploymentID: installation, BatchSize: batch, PollInterval: poll, OperationTimeout: timeout,
		Custody: KubernetesCACustodyFile, WrapKeyFile: wrapKey, PreviousWrapKeyFiles: previous,
	}, nil
}

// loadPreviousWrapKeyFiles reads a comma-separated list of absolute paths
// of wrap keys kept after rotations, at most eight.
func loadPreviousWrapKeyFiles(lookup LookupFunc) ([]SecretFile, error) {
	value, present := lookup(envKubernetesCAPreviousKeyFiles)
	if !present {
		return nil, nil
	}
	paths := strings.Split(value, ",")
	if value == "" || len(paths) > maximumPreviousWrapKeys {
		return nil, settingError(envKubernetesCAPreviousKeyFiles)
	}
	files := make([]SecretFile, 0, len(paths))
	for _, path := range paths {
		file, err := NewSecretFile(path)
		if err != nil {
			return nil, settingError(envKubernetesCAPreviousKeyFiles)
		}
		files = append(files, file)
	}
	return files, nil
}
