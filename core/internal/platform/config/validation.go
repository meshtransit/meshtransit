package config

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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

func addressesConflict(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr != nil || rightErr != nil || leftPort != rightPort {
		return false
	}
	if leftHost == rightHost {
		return true
	}
	return isWildcardHost(leftHost) || isWildcardHost(rightHost)
}

func isWildcardHost(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
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

func requiredValue(lookup LookupFunc, key string, validate func(string) error) (string, error) {
	value, ok := lookup(key)
	if !ok || validate(value) != nil {
		return "", settingError(key)
	}
	return value, nil
}

func requiredFile(lookup LookupFunc, key string) (string, error) {
	return requiredValue(lookup, key, validateFilePath)
}

func validateDependencyAddress(address string) error {
	if err := validateAddress(address); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return ErrInvalid
	}
	return nil
}

func validateIdentifier(value string) error {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return ErrInvalid
	}
	for _, character := range value {
		if character <= ' ' || character == 127 {
			return ErrInvalid
		}
	}
	return nil
}

func validateFilePath(path string) error {
	if path == "" || strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	if path == string(filepath.Separator) {
		return ErrInvalid
	}
	return nil
}

func parsePoolSize(value string) (int, error) {
	return parseIntInRange(value, minPoolSize, maxPoolSize)
}

func parseIntInRange(value string, minimum, maximum int) (int, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, ErrInvalid
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, ErrInvalid
	}
	return parsed, nil
}

func parsePostgreSQLMaxConnections(value string) (int32, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, ErrInvalid
	}
	poolSize, err := strconv.ParseInt(value, 10, 32)
	if err != nil || poolSize < minPoolSize || poolSize > maxPoolSize {
		return 0, ErrInvalid
	}
	return int32(poolSize), nil
}

func parseDurationInRange(value string, minimum, maximum time.Duration) (time.Duration, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, ErrInvalid
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < minimum || duration > maximum {
		return 0, ErrInvalid
	}
	return duration, nil
}

func settingError(key string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, key)
}
