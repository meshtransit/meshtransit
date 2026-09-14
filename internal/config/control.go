package config

import "time"

const (
	envControlAddress              = "MESHTRANSIT_CONTROL_ADDRESS"
	envControlTLSCertificateFile   = "MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE"
	envControlTLSPrivateKeyFile    = "MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE"
	envControlNoisePrivateKeyFile  = "MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE"
	envControlMaxSessions          = "MESHTRANSIT_CONTROL_MAX_SESSIONS"
	envControlMaxStreamsPerSession = "MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION"
	envControlHandshakeTimeout     = "MESHTRANSIT_CONTROL_HANDSHAKE_TIMEOUT"
	envControlReadIdleTimeout      = "MESHTRANSIT_CONTROL_READ_IDLE_TIMEOUT"
	envControlPingTimeout          = "MESHTRANSIT_CONTROL_PING_TIMEOUT"
	envControlWriteTimeout         = "MESHTRANSIT_CONTROL_WRITE_TIMEOUT"
	defaultControlAddress          = "0.0.0.0:8443"
	defaultControlMaxSessions      = 1024
	defaultControlMaxStreams       = 8
	defaultControlHandshakeTimeout = 5 * time.Second
	defaultControlReadIdleTimeout  = time.Minute
	defaultControlPingTimeout      = 15 * time.Second
	defaultControlWriteTimeout     = 15 * time.Second
	minControlTimeout              = 100 * time.Millisecond
	maxControlHandshakeTimeout     = 30 * time.Second
	maxControlSessionTimeout       = 5 * time.Minute
	minControlSessions             = 1
	maxControlSessions             = 4096
	minControlStreams              = 1
	maxControlStreams              = 64
)

// ControlConfig contains the public authenticated control-listener contract.
// Secret-bearing file references format only as redacted values.
type ControlConfig struct {
	Address              string
	TLSCertificateFile   TrustFile
	TLSPrivateKeyFile    PrivateKeyFile
	NoisePrivateKeyFile  SecretFile
	MaxSessions          int
	MaxStreamsPerSession uint32
	HandshakeTimeout     time.Duration
	ReadIdleTimeout      time.Duration
	PingTimeout          time.Duration
	WriteTimeout         time.Duration
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

	maxSessions, err := parseIntInRange(
		valueOrDefault(lookup, envControlMaxSessions, "1024"),
		minControlSessions,
		maxControlSessions,
	)
	if err != nil {
		return ControlConfig{}, settingError(envControlMaxSessions)
	}
	maxStreams, err := parseIntInRange(
		valueOrDefault(lookup, envControlMaxStreamsPerSession, "8"),
		minControlStreams,
		maxControlStreams,
	)
	if err != nil {
		return ControlConfig{}, settingError(envControlMaxStreamsPerSession)
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
	pingTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envControlPingTimeout, defaultControlPingTimeout.String()),
		minControlTimeout,
		readIdleTimeout,
	)
	if err != nil {
		return ControlConfig{}, settingError(envControlPingTimeout)
	}
	writeTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envControlWriteTimeout, defaultControlWriteTimeout.String()),
		minControlTimeout,
		maxControlSessionTimeout,
	)
	if err != nil {
		return ControlConfig{}, settingError(envControlWriteTimeout)
	}

	return ControlConfig{
		Address:             address,
		TLSCertificateFile:  TrustFile{path: certificatePath},
		TLSPrivateKeyFile:   PrivateKeyFile{path: privateKeyPath},
		NoisePrivateKeyFile: SecretFile{path: noiseKeyPath},
		MaxSessions:         maxSessions,
		// #nosec G115 -- validation above bounds the value to 1..64.
		MaxStreamsPerSession: uint32(maxStreams),
		HandshakeTimeout:     handshakeTimeout,
		ReadIdleTimeout:      readIdleTimeout,
		PingTimeout:          pingTimeout,
		WriteTimeout:         writeTimeout,
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
