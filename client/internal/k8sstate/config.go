// Package k8sstate keeps the Kubernetes gateway's state directory in a
// Secret, so a replaced pod comes back as the same Device
// (k8s-gateway-plan §4.3). It talks to the API server over plain REST with
// the pod's service account, without client-go.
package k8sstate

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultTimeout bounds each API request. The stores call the mirror under
// their locks, so a request must not hang.
const DefaultTimeout = 5 * time.Second

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Config says which Secret to mirror into and how to reach the API server.
type Config struct {
	// Server is the API server's https URL.
	Server string
	// CAFile holds the cluster CA the server's certificate must chain to.
	CAFile string
	// TokenFile holds the service account token, read for every request.
	TokenFile  string
	Namespace  string
	SecretName string
	// Timeout bounds each request.
	Timeout time.Duration
}

// InClusterConfig is the Config of a pod: the API server from the service
// environment, and the namespace, CA and token from the service account
// mount.
func InClusterConfig(secretName string) (Config, error) {
	return inClusterConfig(os.Getenv, serviceAccountDir, secretName)
}

func inClusterConfig(getenv func(string) string, mount, secretName string) (Config, error) {
	host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Config{}, errors.New("k8sstate: not in a pod: KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT is unset")
	}
	namespace, err := os.ReadFile(filepath.Join(mount, "namespace")) //nolint:gosec // G304: the service account mount
	if err != nil {
		return Config{}, fmt.Errorf("k8sstate: reading the pod namespace: %w", err)
	}
	cfg := Config{
		Server:     "https://" + net.JoinHostPort(host, port),
		CAFile:     filepath.Join(mount, "ca.crt"),
		TokenFile:  filepath.Join(mount, "token"),
		Namespace:  strings.TrimSpace(string(namespace)),
		SecretName: secretName,
		Timeout:    DefaultTimeout,
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	switch {
	case !strings.HasPrefix(c.Server, "https://"):
		return errors.New("k8sstate: the API server must be an https URL")
	case c.CAFile == "" || c.TokenFile == "":
		return errors.New("k8sstate: the CA and token files are required")
	case !isDNSLabel(c.Namespace):
		return fmt.Errorf("k8sstate: invalid namespace %q", c.Namespace)
	case !isDNSSubdomain(c.SecretName):
		return fmt.Errorf("k8sstate: invalid Secret name %q", c.SecretName)
	case c.Timeout <= 0:
		return errors.New("k8sstate: the request timeout must be positive")
	}
	return nil
}

// isDNSLabel reports whether name is an RFC 1123 label, as namespaces are.
func isDNSLabel(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		edge := i == 0 || i == len(name)-1
		if !alphanumeric && (edge || c != '-') {
			return false
		}
	}
	return true
}

// isDNSSubdomain reports whether name is an RFC 1123 subdomain, as Secret
// names are.
func isDNSSubdomain(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if !isDNSLabel(label) {
			return false
		}
	}
	return true
}
