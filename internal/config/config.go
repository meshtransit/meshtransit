// Package config parses and validates the process configuration boundary.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
)

const (
	// SchemaVersion identifies the validated environment configuration contract.
	SchemaVersion = 13

	envRole            = "MESHTRANSIT_ROLE"
	envHealthAddress   = "MESHTRANSIT_HEALTH_ADDRESS"
	envShutdownTimeout = "MESHTRANSIT_SHUTDOWN_TIMEOUT"
	envLogLevel        = "MESHTRANSIT_LOG_LEVEL"

	envDependencyCheckTimeout  = "MESHTRANSIT_DEPENDENCY_CHECK_TIMEOUT"
	envDependencyCheckInterval = "MESHTRANSIT_DEPENDENCY_CHECK_INTERVAL"

	defaultRole            = "all"
	defaultHealthAddress   = "127.0.0.1:8081"
	defaultShutdownTimeout = 15 * time.Second
	minShutdownTimeout     = time.Second
	maxShutdownTimeout     = 5 * time.Minute

	defaultDependencyCheckTimeout  = 2 * time.Second
	defaultDependencyCheckInterval = 10 * time.Second
	minDependencyCheckTimeout      = 100 * time.Millisecond
	maxDependencyCheckTimeout      = 30 * time.Second
	minDependencyCheckInterval     = time.Second
	maxDependencyCheckInterval     = 5 * time.Minute
)

// ErrInvalid indicates that process configuration is unsafe or malformed.
var ErrInvalid = errors.New("invalid configuration")

// LookupFunc returns an environment value and whether it was explicitly set.
type LookupFunc func(string) (string, bool)

// Config is the fully validated process configuration.
type Config struct {
	Role            app.Role
	HealthAddress   string
	ShutdownTimeout time.Duration
	LogLevel        slog.Level
	Dependencies    DependencyConfig
	Storage         *StorageConfig
	API             *APIConfig
	Control         *ControlConfig
	Enrollment      *EnrollmentConfig
	RevisionWorker  *RevisionWorkerConfig
}

// DependencyConfig bounds startup and periodic infrastructure checks.
type DependencyConfig struct {
	CheckTimeout  time.Duration
	CheckInterval time.Duration
}

// Load reads the allowlisted process settings through lookup and validates all
// values before any listener or background work can start.
func Load(lookup LookupFunc) (Config, error) {
	if lookup == nil {
		return Config{}, fmt.Errorf("%w: environment lookup is required", ErrInvalid)
	}

	role, err := app.ParseRole(valueOrDefault(lookup, envRole, defaultRole))
	if err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, envRole)
	}

	healthAddress := valueOrDefault(lookup, envHealthAddress, defaultHealthAddress)
	if err := validateAddress(healthAddress); err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, envHealthAddress)
	}

	shutdownTimeout, err := parseShutdownTimeout(
		valueOrDefault(lookup, envShutdownTimeout, defaultShutdownTimeout.String()),
	)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, envShutdownTimeout)
	}

	logLevel, err := parseLogLevel(valueOrDefault(lookup, envLogLevel, "info"))
	if err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, envLogLevel)
	}

	dependencyConfig, err := loadDependencyConfig(lookup)
	if err != nil {
		return Config{}, err
	}

	var storageConfig *StorageConfig
	var apiConfig *APIConfig
	var controlConfig *ControlConfig
	var enrollmentConfig *EnrollmentConfig
	var revisionWorkerConfig *RevisionWorkerConfig
	if role != app.RoleRelay {
		loadedStorage, loadErr := loadStorageConfig(lookup, role)
		if loadErr != nil {
			return Config{}, loadErr
		}
		storageConfig = &loadedStorage
	}
	if role == app.RoleAll || role == app.RoleControl {
		loadedControl, loadErr := loadControlConfig(lookup)
		if loadErr != nil {
			return Config{}, loadErr
		}
		loadedEnrollment, loadErr := loadEnrollmentConfig(lookup, shutdownTimeout)
		if loadErr != nil {
			return Config{}, loadErr
		}
		if loadErr := validateControlSecretOwnership(loadedControl, loadedEnrollment); loadErr != nil {
			return Config{}, loadErr
		}
		controlConfig = &loadedControl
		enrollmentConfig = &loadedEnrollment
	}
	if role == app.RoleAll || role == app.RoleAPI {
		loadedAPI, loadErr := loadAPIConfig(lookup)
		if loadErr != nil {
			return Config{}, loadErr
		}
		if addressesConflict(healthAddress, loadedAPI.Address) ||
			controlConfig != nil && addressesConflict(controlConfig.Address, loadedAPI.Address) {
			return Config{}, settingError(envAPIAddress)
		}
		if loadErr := validateAPIExternalSecretOwnership(loadedAPI, controlConfig, enrollmentConfig); loadErr != nil {
			return Config{}, loadErr
		}
		apiConfig = &loadedAPI
	}
	if role == app.RoleAll || role == app.RoleWorker {
		loadedWorker, loadErr := loadRevisionWorkerConfig(lookup)
		if loadErr != nil {
			return Config{}, loadErr
		}
		revisionWorkerConfig = &loadedWorker
	}

	return Config{
		Role:            role,
		HealthAddress:   healthAddress,
		ShutdownTimeout: shutdownTimeout,
		LogLevel:        logLevel,
		Dependencies:    dependencyConfig,
		Storage:         storageConfig,
		API:             apiConfig,
		Control:         controlConfig,
		Enrollment:      enrollmentConfig,
		RevisionWorker:  revisionWorkerConfig,
	}, nil
}

func loadDependencyConfig(lookup LookupFunc) (DependencyConfig, error) {
	checkTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envDependencyCheckTimeout, defaultDependencyCheckTimeout.String()),
		minDependencyCheckTimeout,
		maxDependencyCheckTimeout,
	)
	if err != nil {
		return DependencyConfig{}, settingError(envDependencyCheckTimeout)
	}
	checkInterval, err := parseDurationInRange(
		valueOrDefault(lookup, envDependencyCheckInterval, defaultDependencyCheckInterval.String()),
		minDependencyCheckInterval,
		maxDependencyCheckInterval,
	)
	if err != nil {
		return DependencyConfig{}, settingError(envDependencyCheckInterval)
	}
	if checkTimeout >= checkInterval {
		return DependencyConfig{}, settingError(envDependencyCheckTimeout)
	}
	return DependencyConfig{CheckTimeout: checkTimeout, CheckInterval: checkInterval}, nil
}

func parseShutdownTimeout(value string) (time.Duration, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, ErrInvalid
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout < minShutdownTimeout || timeout > maxShutdownTimeout {
		return 0, ErrInvalid
	}
	return timeout, nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, ErrInvalid
	}
}
