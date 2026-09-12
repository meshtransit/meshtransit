// Package config parses and validates the process configuration boundary.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
)

const (
	envRole            = "MESHTRANSIT_ROLE"
	envHealthAddress   = "MESHTRANSIT_HEALTH_ADDRESS"
	envShutdownTimeout = "MESHTRANSIT_SHUTDOWN_TIMEOUT"
	envLogLevel        = "MESHTRANSIT_LOG_LEVEL"

	defaultRole            = "all"
	defaultHealthAddress   = "127.0.0.1:8081"
	defaultShutdownTimeout = 15 * time.Second
	minShutdownTimeout     = time.Second
	maxShutdownTimeout     = 5 * time.Minute
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

	return Config{
		Role:            role,
		HealthAddress:   healthAddress,
		ShutdownTimeout: shutdownTimeout,
		LogLevel:        logLevel,
	}, nil
}

func valueOrDefault(lookup LookupFunc, key, fallback string) string {
	value, ok := lookup(key)
	if !ok {
		return fallback
	}
	return value
}

func validateAddress(address string) error {
	if address == "" || strings.TrimSpace(address) != address {
		return ErrInvalid
	}

	host, portValue, err := net.SplitHostPort(address)
	if err != nil {
		return ErrInvalid
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return ErrInvalid
	}
	if host != "" && !validHost(host) {
		return ErrInvalid
	}
	return nil
}

func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if len(host) > 253 {
		return false
	}

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for index, character := range label {
			isLetter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
			isDigit := character >= '0' && character <= '9'
			if !isLetter && !isDigit && (character != '-' || index == 0 || index == len(label)-1) {
				return false
			}
		}
	}
	return true
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
