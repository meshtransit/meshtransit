// Package kubeapi is the small Kubernetes API client the chart's bootstrap
// Job uses (V1-11): read Secrets and ConfigMaps in the pod's namespace,
// create a Secret only when it is absent (never overwrite), and create or
// update a ConfigMap. Plain REST with the pod's service account, without
// client-go, as client/internal/k8sstate does for the gateway.
package kubeapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	// DefaultTimeout bounds each request.
	DefaultTimeout   = 10 * time.Second
	maxResponseBytes = 1 << 20
)

var (
	// ErrConfig reports a configuration the client cannot use.
	ErrConfig = errors.New("kubeapi: invalid configuration")
	// ErrConflict reports an update that lost a race (HTTP 409 on PUT).
	ErrConflict  = errors.New("kubeapi: conflict")
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// Config says how to reach the API server.
type Config struct {
	Server    string // https URL
	CAFile    string
	TokenFile string // read for every request (the kubelet rotates it)
	Namespace string
	Timeout   time.Duration
}

// InCluster is the Config of a pod.
func InCluster() (Config, error) { return inCluster(os.Getenv, serviceAccountDir) }

func inCluster(getenv func(string) string, mount string) (Config, error) {
	host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Config{}, fmt.Errorf("%w: not in a pod", ErrConfig)
	}
	namespace, err := os.ReadFile(filepath.Join(mount, "namespace")) //nolint:gosec // G304: the service account mount
	if err != nil {
		return Config{}, fmt.Errorf("%w: reading the pod namespace: %w", ErrConfig, err)
	}
	return Config{
		Server: "https://" + net.JoinHostPort(host, port), CAFile: filepath.Join(mount, "ca.crt"),
		TokenFile: filepath.Join(mount, "token"), Namespace: strings.TrimSpace(string(namespace)),
		Timeout: DefaultTimeout,
	}, nil
}

// Client talks to one namespace.
type Client struct {
	cfg  Config
	http *http.Client
	base string // .../api/v1/namespaces/<ns>
}

// New checks cfg and builds a Client.
func New(cfg Config) (*Client, error) {
	server, err := url.Parse(cfg.Server)
	if err != nil || server.Scheme != "https" || server.Host == "" || cfg.TokenFile == "" ||
		!validName(cfg.Namespace) || cfg.Timeout <= 0 {
		return nil, ErrConfig
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the cluster CA: %w", ErrConfig, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: the cluster CA file holds no certificate", ErrConfig)
	}
	// No proxy from the environment: the token goes to the API server only.
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Transport: transport, Timeout: cfg.Timeout,
			// The token must not follow a redirect anywhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		base: strings.TrimSuffix(cfg.Server, "/") + "/api/v1/namespaces/" + url.PathEscape(cfg.Namespace),
	}, nil
}

// Namespace is the namespace the client works in.
func (c *Client) Namespace() string { return c.cfg.Namespace }

// Metadata is the part of an object's metadata the bootstrap reads and sets.
type Metadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
}

// Secret is an Opaque Secret.
type Secret struct {
	Metadata  Metadata          `json:"metadata"`
	Immutable *bool             `json:"immutable,omitempty"`
	Data      map[string][]byte `json:"data,omitempty"`
}

// ConfigMap is a ConfigMap with string data.
type ConfigMap struct {
	Metadata  Metadata          `json:"metadata"`
	Immutable *bool             `json:"immutable,omitempty"`
	Data      map[string]string `json:"data,omitempty"`
}

// Container is the part of a container a rollout check reads.
type Container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Env   []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"env,omitempty"`
}

// EnvValue is the literal value of name in the container's env, if any.
func (container Container) EnvValue(name string) string {
	for _, variable := range container.Env {
		if variable.Name == name {
			return variable.Value
		}
	}
	return ""
}

// ObjectMeta is the part of an object's metadata a rollout check reads.
type ObjectMeta struct {
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels,omitempty"`
	DeletionTimestamp *string           `json:"deletionTimestamp,omitempty"`
}

// Pod is the part of a Pod a rollout check reads.
type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Containers []Container `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

// ReplicaSet is the part of a ReplicaSet a rollout check reads.
type ReplicaSet struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Replicas *int32 `json:"replicas,omitempty"`
		Template struct {
			Metadata ObjectMeta `json:"metadata"`
			Spec     struct {
				Containers []Container `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		Replicas int32 `json:"replicas"`
	} `json:"status"`
}

const (
	// listPage is one page of a list; each page is also bounded by
	// maxResponseBytes.
	listPage = 100
	// maxListPages bounds a whole list (2 000 objects).
	maxListPages = 20
)

// ErrDenied reports a request the API server refused for the token (401 or
// 403): waiting will not help.
var ErrDenied = errors.New("kubeapi: denied")

// ListPods lists the namespace's pods that match labelSelector.
func (c *Client) ListPods(ctx context.Context, labelSelector string) ([]Pod, error) {
	return listAll[Pod](ctx, c, c.base+"/pods", "pods", labelSelector)
}

// ListReplicaSets lists the namespace's ReplicaSets that match
// labelSelector.
func (c *Client) ListReplicaSets(ctx context.Context, labelSelector string) ([]ReplicaSet, error) {
	base := strings.Replace(c.base, "/api/v1/", "/apis/apps/v1/", 1)
	return listAll[ReplicaSet](ctx, c, base+"/replicasets", "replicasets", labelSelector)
}

// listAll reads every page of a list, at most maxListPages.
func listAll[T any](ctx context.Context, c *Client, target, kind, labelSelector string) ([]T, error) {
	if labelSelector == "" || len(labelSelector) > 1024 {
		return nil, ErrConfig
	}
	items := []T{}
	next := ""
	for page := 0; page < maxListPages; page++ {
		query := url.Values{"labelSelector": {labelSelector}, "limit": {strconv.Itoa(listPage)}}
		if next != "" {
			query.Set("continue", next)
		}
		code, payload, err := c.do(ctx, http.MethodGet, target+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if code == http.StatusUnauthorized || code == http.StatusForbidden {
			return nil, errors.Join(ErrDenied, statusError("list "+kind, code, payload))
		}
		if code != http.StatusOK {
			return nil, statusError("list "+kind, code, payload)
		}
		var list struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := json.Unmarshal(payload, &list); err != nil {
			return nil, fmt.Errorf("kubeapi: decoding %s: %w", kind, err)
		}
		items = append(items, list.Items...)
		if list.Metadata.Continue == "" {
			return items, nil
		}
		next = list.Metadata.Continue
	}
	return nil, fmt.Errorf("kubeapi: more than %d %s match %q", maxListPages*listPage, kind, labelSelector)
}

// GetSecret reads a Secret; false when it does not exist.
func (c *Client) GetSecret(ctx context.Context, name string) (Secret, bool, error) {
	var secret Secret
	found, err := c.get(ctx, "secrets", name, &secret)
	return secret, found, err
}

// CreateSecretIfAbsent creates secret unless one of that name exists; it
// never changes an existing Secret. It reports whether it created it.
func (c *Client) CreateSecretIfAbsent(ctx context.Context, secret Secret) (bool, error) {
	if !validName(secret.Metadata.Name) {
		return false, ErrConfig
	}
	body, err := json.Marshal(struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Type       string `json:"type"`
		Secret
	}{APIVersion: "v1", Kind: "Secret", Type: "Opaque", Secret: secret})
	if err != nil {
		return false, err
	}
	code, payload, err := c.do(ctx, http.MethodPost, c.base+"/secrets", body)
	switch {
	case err != nil:
		return false, err
	case code == http.StatusCreated || code == http.StatusOK:
		return true, nil
	case code == http.StatusConflict:
		return false, nil
	default:
		return false, statusError("create Secret", code, payload)
	}
}

// GetConfigMap reads a ConfigMap; false when it does not exist.
func (c *Client) GetConfigMap(ctx context.Context, name string) (ConfigMap, bool, error) {
	var configMap ConfigMap
	found, err := c.get(ctx, "configmaps", name, &configMap)
	return configMap, found, err
}

// CreateConfigMapIfAbsent creates configMap unless one of that name exists.
func (c *Client) CreateConfigMapIfAbsent(ctx context.Context, configMap ConfigMap) (bool, error) {
	if !validName(configMap.Metadata.Name) {
		return false, ErrConfig
	}
	body, err := json.Marshal(struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		ConfigMap
	}{APIVersion: "v1", Kind: "ConfigMap", ConfigMap: configMap})
	if err != nil {
		return false, err
	}
	code, payload, err := c.do(ctx, http.MethodPost, c.base+"/configmaps", body)
	switch {
	case err != nil:
		return false, err
	case code == http.StatusCreated || code == http.StatusOK:
		return true, nil
	case code == http.StatusConflict:
		return false, nil
	default:
		return false, statusError("create ConfigMap", code, payload)
	}
}

// UpdateConfigMap replaces an existing ConfigMap; configMap carries the
// resourceVersion it read, so a concurrent change fails with ErrConflict.
func (c *Client) UpdateConfigMap(ctx context.Context, configMap ConfigMap) error {
	if !validName(configMap.Metadata.Name) || configMap.Metadata.ResourceVersion == "" {
		return ErrConfig
	}
	body, err := json.Marshal(struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		ConfigMap
	}{APIVersion: "v1", Kind: "ConfigMap", ConfigMap: configMap})
	if err != nil {
		return err
	}
	code, payload, err := c.do(ctx, http.MethodPut, c.base+"/configmaps/"+url.PathEscape(configMap.Metadata.Name), body)
	switch {
	case err != nil:
		return err
	case code == http.StatusOK:
		return nil
	case code == http.StatusConflict:
		return ErrConflict
	default:
		return statusError("update ConfigMap", code, payload)
	}
}

func (c *Client) get(ctx context.Context, kind, name string, into any) (bool, error) {
	if !validName(name) {
		return false, ErrConfig
	}
	code, payload, err := c.do(ctx, http.MethodGet, c.base+"/"+kind+"/"+url.PathEscape(name), nil)
	switch {
	case err != nil:
		return false, err
	case code == http.StatusNotFound:
		return false, nil
	case code != http.StatusOK:
		return false, statusError("get "+kind, code, payload)
	}
	// The payload may hold a Secret's values: clear it once decoded.
	defer clear(payload)
	if err := json.Unmarshal(payload, into); err != nil {
		return false, fmt.Errorf("kubeapi: decoding %s %s: %w", kind, name, err)
	}
	return true, nil
}

func (c *Client) do(ctx context.Context, method, target string, body []byte) (int, []byte, error) {
	token, err := os.ReadFile(c.cfg.TokenFile)
	if err != nil {
		return 0, nil, fmt.Errorf("kubeapi: reading the service account token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("kubeapi: building the request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("kubeapi: %s: %w", method, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("kubeapi: reading the %s answer: %w", method, err)
	}
	if len(payload) > maxResponseBytes {
		return 0, nil, fmt.Errorf("kubeapi: the %s answer is larger than %d bytes", method, maxResponseBytes)
	}
	return response.StatusCode, payload, nil
}

// statusError names the operation, code and the Status reason, never the
// request body.
func statusError(operation string, code int, payload []byte) error {
	var status struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(payload, &status)
	message := status.Message
	if len(message) > 200 {
		message = message[:200]
	}
	return fmt.Errorf("kubeapi: %s: HTTP %d %s: %s", operation, code, status.Reason, message)
}

func validName(name string) bool {
	return len(name) > 0 && len(name) <= 253 && dnsSubdomain.MatchString(name)
}
