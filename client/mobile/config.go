package mobile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	// DefaultListenPort is the local UDP port of the encrypted packet path,
	// the same default as the desktop packages.
	DefaultListenPort = 41641
	// DefaultMTU is the TUN MTU the engine asks the platform for: the
	// smallest MTU every mesh path carries without fragmentation.
	DefaultMTU = 1280

	// maxDeviceNameBytes bounds the name the person gave the device; the
	// hostname made from it is shorter (hostnameFor).
	maxDeviceNameBytes = 255
)

// errInvalidConfig reports a Config the engine cannot start from.
var errInvalidConfig = errors.New("mobile: invalid config")

// Config is the app-provided configuration of one Engine.
type Config struct {
	// StateDir is a directory private to the app (Android filesDir, iOS App
	// Group container) where profiles and sealed identities are kept.
	StateDir string
	// DeviceName is the name the person gave the device, or its model. The
	// Device registers with a hostname made from it (hostnameFor).
	DeviceName string
	// ListenPort is the local UDP port; 0 means DefaultListenPort.
	ListenPort int
}

// NewConfig returns a Config with the given state directory and Device name
// and the default port. gomobile exposes it as the Config constructor.
func NewConfig(stateDir, deviceName string) *Config {
	return &Config{StateDir: stateDir, DeviceName: deviceName, ListenPort: DefaultListenPort}
}

// validated returns the config with defaults applied, or errInvalidConfig.
func (config *Config) validated() (Config, error) {
	if config == nil {
		return Config{}, fmt.Errorf("%w: config is required", errInvalidConfig)
	}
	resolved := *config
	resolved.StateDir = strings.TrimSpace(resolved.StateDir)
	resolved.DeviceName = strings.TrimSpace(resolved.DeviceName)
	if resolved.StateDir == "" || !filepath.IsAbs(resolved.StateDir) {
		return Config{}, fmt.Errorf("%w: state directory must be an absolute path", errInvalidConfig)
	}
	resolved.StateDir = filepath.Clean(resolved.StateDir)
	if resolved.DeviceName == "" || len(resolved.DeviceName) > maxDeviceNameBytes ||
		!utf8.ValidString(resolved.DeviceName) || strings.ContainsAny(resolved.DeviceName, "\x00\r\n") {
		return Config{}, fmt.Errorf("%w: device name must be 1 to %d bytes of text", errInvalidConfig,
			maxDeviceNameBytes)
	}
	if resolved.ListenPort == 0 {
		resolved.ListenPort = DefaultListenPort
	}
	if resolved.ListenPort < 1024 || resolved.ListenPort > 65535 {
		return Config{}, fmt.Errorf("%w: listen port must be 1024 to 65535", errInvalidConfig)
	}
	return resolved, nil
}
