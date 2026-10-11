package config

import "time"

const (
	envControlAddress             = "MESHTRANSIT_CONTROL_ADDRESS"
	envControlTLSCertificateFile  = "MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE"
	envControlTLSPrivateKeyFile   = "MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE"
	envControlNoisePrivateKeyFile = "MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE"
	// envControlNoiseNextPrivateKeyFile names the next control key during a
	// rotation (mtcp-v1 §11): Core announces it to every session and
	// answers handshakes made with it.
	envControlNoiseNextPrivateKeyFile = "MESHTRANSIT_CONTROL_NOISE_NEXT_PRIVATE_KEY_FILE"
	envControlMaxSessions             = "MESHTRANSIT_CONTROL_MAX_SESSIONS"
	envControlHandshakeTimeout        = "MESHTRANSIT_CONTROL_HANDSHAKE_TIMEOUT"
	envControlReadIdleTimeout         = "MESHTRANSIT_CONTROL_READ_IDLE_TIMEOUT"
	envControlDrainWindow             = "MESHTRANSIT_CONTROL_DRAIN_WINDOW"
	envControlRebalance               = "MESHTRANSIT_CONTROL_REBALANCE"
	envControlRebalanceInterval       = "MESHTRANSIT_CONTROL_REBALANCE_INTERVAL"
	defaultControlDrainWindow         = 30 * time.Second
	defaultControlRebalanceEvery      = 15 * time.Second
	maxControlDrainWindow             = 5 * time.Minute
	defaultControlAddress             = "0.0.0.0:8443"
	defaultControlMaxSessions         = 1024
	defaultControlHandshakeTimeout    = 5 * time.Second
	defaultControlReadIdleTimeout     = time.Minute
	minControlTimeout                 = 100 * time.Millisecond
	maxControlHandshakeTimeout        = 30 * time.Second
	maxControlSessionTimeout          = 5 * time.Minute
	minControlSessions                = 1
	maxControlSessions                = 16384
)

var retiredControlSettings = []string{
	"MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION",
	"MESHTRANSIT_CONTROL_PING_TIMEOUT",
	"MESHTRANSIT_CONTROL_WRITE_TIMEOUT",
}

// ControlConfig contains the public authenticated control-listener contract.
// Secret-bearing file references format only as redacted values.
type ControlConfig struct {
	Address             string
	TLSCertificateFile  TrustFile
	TLSPrivateKeyFile   PrivateKeyFile
	NoisePrivateKeyFile SecretFile
	// NextNoisePrivateKeyFile is the next control key during a rotation.
	NextNoisePrivateKeyFile *SecretFile
	MaxSessions             int
	HandshakeTimeout        time.Duration
	ReadIdleTimeout         time.Duration
	// DrainWindow spreads the sessions' reconnects when the replica stops.
	DrainWindow time.Duration
	// Rebalance lets a replica shed sessions above its fair share;
	// RebalanceInterval is how often replicas publish their load.
	Rebalance         bool
	RebalanceInterval time.Duration
	Map               ControlMapConfig
	MTCP              ControlMTCPConfig
}

func loadControlConfig(lookup LookupFunc) (ControlConfig, error) {
	address := valueOrDefault(lookup, envControlAddress, defaultControlAddress)
	if err := validateAddress(address); err != nil {
		return ControlConfig{}, settingError(envControlAddress)
	}
	certificatePath, err := requiredFile(lookup, envControlTLSCertificateFile)
	if err != nil {
		return ControlConfig{}, err
	}
	privateKeyPath, err := requiredFile(lookup, envControlTLSPrivateKeyFile)
	if err != nil {
		return ControlConfig{}, err
	}
	noiseKeyPath, err := requiredFile(lookup, envControlNoisePrivateKeyFile)
	if err != nil {
		return ControlConfig{}, err
	}
	if privateKeyPath == noiseKeyPath {
		return ControlConfig{}, settingError(envControlNoisePrivateKeyFile)
	}
	var nextNoiseKey *SecretFile
	if _, present := lookup(envControlNoiseNextPrivateKeyFile); present {
		nextPath, err := requiredFile(lookup, envControlNoiseNextPrivateKeyFile)
		if err != nil || nextPath == noiseKeyPath || nextPath == privateKeyPath {
			return ControlConfig{}, settingError(envControlNoiseNextPrivateKeyFile)
		}
		nextNoiseKey = &SecretFile{path: nextPath}
	}

	maxSessions, err := parseIntInRange(
		valueOrDefault(lookup, envControlMaxSessions, "1024"),
		minControlSessions,
		maxControlSessions,
	)
	if err != nil {
		return ControlConfig{}, settingError(envControlMaxSessions)
	}
	handshakeTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envControlHandshakeTimeout, defaultControlHandshakeTimeout.String()),
		minControlTimeout,
		maxControlHandshakeTimeout,
	)
	if err != nil {
		return ControlConfig{}, settingError(envControlHandshakeTimeout)
	}
	readIdleTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envControlReadIdleTimeout, defaultControlReadIdleTimeout.String()),
		minControlTimeout,
		maxControlSessionTimeout,
	)
	if err != nil {
		return ControlConfig{}, settingError(envControlReadIdleTimeout)
	}
	drainWindow, err := parseDurationInRange(
		valueOrDefault(lookup, envControlDrainWindow, defaultControlDrainWindow.String()), 0, maxControlDrainWindow)
	if err != nil {
		return ControlConfig{}, settingError(envControlDrainWindow)
	}
	rebalance := valueOrDefault(lookup, envControlRebalance, "true")
	if rebalance != "true" && rebalance != "false" {
		return ControlConfig{}, settingError(envControlRebalance)
	}
	rebalanceInterval, err := parseDurationInRange(
		valueOrDefault(lookup, envControlRebalanceInterval, defaultControlRebalanceEvery.String()),
		time.Second, maxControlSessionTimeout)
	if err != nil {
		return ControlConfig{}, settingError(envControlRebalanceInterval)
	}
	// Settings of the retired legacy control server are refused rather than ignored,
	// so a deployment that still sets them notices.
	for _, name := range retiredControlSettings {
		if _, present := lookup(name); present {
			return ControlConfig{}, settingError(name)
		}
	}
	mapConfig, err := loadControlMapConfig(lookup)
	if err != nil {
		return ControlConfig{}, err
	}
	mtcpConfig, err := loadControlMTCPConfig(lookup, time.Now(), nextNoiseKey != nil)
	if err != nil {
		return ControlConfig{}, err
	}

	return ControlConfig{
		Address:                 address,
		TLSCertificateFile:      TrustFile{path: certificatePath},
		TLSPrivateKeyFile:       PrivateKeyFile{path: privateKeyPath},
		NoisePrivateKeyFile:     SecretFile{path: noiseKeyPath},
		NextNoisePrivateKeyFile: nextNoiseKey,
		MaxSessions:             maxSessions,
		HandshakeTimeout:        handshakeTimeout,
		ReadIdleTimeout:         readIdleTimeout,
		DrainWindow:             drainWindow,
		Rebalance:               rebalance == "true",
		RebalanceInterval:       rebalanceInterval,
		Map:                     mapConfig,
		MTCP:                    mtcpConfig,
	}, nil
}

func validateControlSecretOwnership(control ControlConfig, enrollment EnrollmentConfig) error {
	controlPaths := []struct {
		setting string
		path    string
	}{
		{setting: envControlTLSPrivateKeyFile, path: control.TLSPrivateKeyFile.path},
		{setting: envControlNoisePrivateKeyFile, path: control.NoisePrivateKeyFile.path},
	}
	if control.NextNoisePrivateKeyFile != nil {
		controlPaths = append(controlPaths, struct {
			setting string
			path    string
		}{setting: envControlNoiseNextPrivateKeyFile, path: control.NextNoisePrivateKeyFile.path})
	}
	enrollmentPaths := []string{enrollment.CredentialDigest.Active.MaterialFile.path}
	if enrollment.CredentialDigest.Previous != nil {
		enrollmentPaths = append(enrollmentPaths, enrollment.CredentialDigest.Previous.MaterialFile.path)
	}
	for _, controlPath := range controlPaths {
		for _, enrollmentPath := range enrollmentPaths {
			if controlPath.path == enrollmentPath {
				return settingError(controlPath.setting)
			}
		}
	}
	return nil
}
