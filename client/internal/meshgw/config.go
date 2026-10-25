package meshgw

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultStateDir     = "/var/lib/meshgw/state"
	defaultEnvelopeDir  = "/etc/meshgw/envelope"
	defaultEnrollDir    = "/etc/meshgw/enroll"
	defaultSecretPrefix = "meshgw-state" //nolint:gosec // G101: a Secret name, not a credential
	defaultProbeAddress = ":9090"
	defaultListenPort   = 41641
	defaultKubeAPIPort  = 443
	envelopeKeyBytes    = 32
	// maxHostnameBytes is a DNS label's limit, which Core's names keep.
	maxHostnameBytes = 63
)

// Config is one gateway replica's configuration, from its pod. A
// StatefulSet gives every pod the same template, so each per-replica value
// is chosen by the ordinal in the pod's name: the key files are key-N in
// their mounted Secrets, and the state Secret is <prefix>-N.
type Config struct {
	Ordinal int
	// ControlURL is Core's https URL, and ControlFingerprint the pin of its
	// key, checked on every start; the gateway never trusts on first use.
	ControlURL         string
	ControlFingerprint string
	// Hostname is the Device's name: the cluster's and the ordinal.
	Hostname string
	// StateDir is a directory under the pod's emptyDir, rebuilt from the
	// state Secret on every start.
	StateDir          string
	EnvelopeKeyFile   string
	EnrollmentKeyFile string
	StateSecret       string
	// ProbeAddress serves /healthz, /readyz and /metrics.
	ProbeAddress string
	// ListenPort is the encrypted path's UDP port.
	ListenPort int
	// KubeAPIPort is where the gateway takes kubectl on its mesh address,
	// and KubeAPIBackend the API server it passes the connections to.
	KubeAPIPort    int
	KubeAPIBackend string
}

// LoadConfig reads the pod's configuration from its environment.
func LoadConfig(getenv func(string) string) (Config, error) {
	value := func(name, fallback string) string {
		if got := strings.TrimSpace(getenv(name)); got != "" {
			return got
		}
		return fallback
	}
	ordinal, err := podOrdinal(getenv("POD_NAME"))
	if err != nil {
		return Config{}, err
	}
	controlURL := value("MESHGW_CONTROL_URL", "")
	if err := checkControlURL(controlURL); err != nil {
		return Config{}, err
	}
	fingerprint := value("MESHGW_CONTROL_FINGERPRINT", "")
	if fingerprint == "" {
		return Config{}, errors.New("meshgw: MESHGW_CONTROL_FINGERPRINT, the pin of Core's key, is required")
	}
	cluster := value("MESHGW_CLUSTER", "")
	if !isDNSLabel(cluster) || len(cluster) > 40 {
		return Config{}, fmt.Errorf("meshgw: MESHGW_CLUSTER %q must be a DNS label of up to 40 characters", cluster)
	}
	stateDir := value("MESHGW_STATE_DIR", defaultStateDir)
	if !filepath.IsAbs(stateDir) {
		return Config{}, fmt.Errorf("meshgw: MESHGW_STATE_DIR %q must be absolute", stateDir)
	}
	listenPort, err := port(value("MESHGW_LISTEN_PORT", strconv.Itoa(defaultListenPort)), 1024)
	if err != nil {
		return Config{}, fmt.Errorf("meshgw: MESHGW_LISTEN_PORT: %w", err)
	}
	kubeAPIPort, err := port(value("MESHGW_KUBE_API_PORT", strconv.Itoa(defaultKubeAPIPort)), 1)
	if err != nil {
		return Config{}, fmt.Errorf("meshgw: MESHGW_KUBE_API_PORT: %w", err)
	}
	apiHost, apiPort := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	if apiHost == "" || apiPort == "" {
		return Config{}, errors.New("meshgw: not in a pod: KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT is unset")
	}
	hostname := "meshgw-" + cluster + "-" + strconv.Itoa(ordinal)
	if len(hostname) > maxHostnameBytes {
		return Config{}, fmt.Errorf("meshgw: the Device name %q is over %d bytes", hostname, maxHostnameBytes)
	}
	keyName := "key-" + strconv.Itoa(ordinal)
	return Config{
		Ordinal:            ordinal,
		ControlURL:         controlURL,
		ControlFingerprint: fingerprint,
		Hostname:           hostname,
		StateDir:           filepath.Clean(stateDir),
		EnvelopeKeyFile:    filepath.Join(value("MESHGW_ENVELOPE_DIR", defaultEnvelopeDir), keyName),
		EnrollmentKeyFile:  filepath.Join(value("MESHGW_ENROLLMENT_DIR", defaultEnrollDir), keyName),
		StateSecret:        value("MESHGW_STATE_SECRET_PREFIX", defaultSecretPrefix) + "-" + strconv.Itoa(ordinal),
		ProbeAddress:       value("MESHGW_PROBE_ADDRESS", defaultProbeAddress),
		ListenPort:         listenPort,
		KubeAPIPort:        kubeAPIPort,
		KubeAPIBackend:     net.JoinHostPort(apiHost, apiPort),
	}, nil
}

// ReadEnvelopeKey reads the key that seals the identity records: exactly
// the 32 bytes the replica's entry in the envelope Secret holds. Another key
// leaves the restored identity unreadable and the replica fails to start;
// the runbook then has the identity.* keys removed from its state Secret, so
// it enrolls again with a new enrollment key.
func ReadEnvelopeKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path) //nolint:gosec // G304: the mounted envelope Secret
	if err != nil {
		return nil, fmt.Errorf("meshgw: reading the envelope key: %w", err)
	}
	if len(key) != envelopeKeyBytes {
		clear(key)
		return nil, fmt.Errorf("meshgw: the envelope key in %s must be %d bytes", path, envelopeKeyBytes)
	}
	return key, nil
}

// podOrdinal is the StatefulSet ordinal at the end of a pod's name.
func podOrdinal(podName string) (int, error) {
	index := strings.LastIndexByte(podName, '-')
	if index < 0 {
		return 0, fmt.Errorf("meshgw: POD_NAME %q has no StatefulSet ordinal", podName)
	}
	ordinal, err := strconv.Atoi(podName[index+1:])
	if err != nil || ordinal < 0 || strconv.Itoa(ordinal) != podName[index+1:] {
		return 0, fmt.Errorf("meshgw: POD_NAME %q has no StatefulSet ordinal", podName)
	}
	return ordinal, nil
}

// checkControlURL accepts only the canonical form the profile store keeps,
// https://host, so a restored profile compares equal.
func checkControlURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) ||
		parsed.Port() != "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.User != nil || parsed.String() != raw {
		return fmt.Errorf("meshgw: MESHGW_CONTROL_URL %q must be https://host, in lower case", raw)
	}
	return nil
}

func port(raw string, lowest int) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value < lowest || value > 65535 {
		return 0, fmt.Errorf("%q must be a port from %d to 65535", raw, lowest)
	}
	return value, nil
}

// isDNSLabel reports whether name is an RFC 1123 label.
func isDNSLabel(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alphanumeric && (i == 0 || i == len(name)-1 || c != '-') {
			return false
		}
	}
	return true
}
