package meshgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"meshtransit.net/client/internal/kubeproxy"
	"meshtransit.net/client/internal/kubereq"
)

// The gateway's kubectl modes (K1b design §10).
const (
	// KubeModeProxy ends TLS and forwards each request as its Device's
	// group (K1b).
	KubeModeProxy = "proxy"
	// KubeModePassthrough passes kubectl's TCP to the API server unchanged
	// (K0): only when set explicitly, and gone at K1f.
	KubeModePassthrough = "passthrough"
)

const (
	// #nosec G101 -- file paths, not credential material.
	defaultAPITokenFile    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultAPICAFile       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultServiceAccount  = "meshgw"
	defaultEnvelopeSecret  = "meshgw-envelope" // #nosec G101 -- a Secret's name
	defaultJoinSecret      = "meshgw-join"     // #nosec G101 -- a Secret's name
	defaultReplicas        = 2
	maximumReplicas        = 10
	defaultKubeStaleAfter  = 5 * time.Minute
	maximumKubeGroupsBytes = 64 << 10
	maximumAudienceBytes   = 512
)

// proxyOnlyVariables configure the proxy only.
var proxyOnlyVariables = []string{
	"MESHGW_KUBE_GROUPS", "MESHGW_SECRET_RESOURCES", "MESHGW_KUBE_STALE_AFTER",
	"MESHGW_KUBE_API_BACKEND", "MESHGW_GUARDED_NAMESPACES", "MESHGW_API_AUDIENCES", "MESHGW_KUBE_PROFILES",
}

// KubeConfig is how a K1 gateway serves kubectl (K1b).
type KubeConfig struct {
	// Mode is KubeModeProxy or KubeModePassthrough.
	Mode string
	// Cluster is the cluster's name (MESHGW_CLUSTER).
	Cluster string
	// Groups are MESHGW_KUBE_GROUPS, checked as the chart will.
	Groups []kubeproxy.Group
	// SecretResources are read like secrets (MESHGW_SECRET_RESOURCES,
	// "resource.group" by commas).
	SecretResources []kubereq.GroupResource
	// StaleAfter is how long a map Core has not confirmed stays usable
	// (MESHGW_KUBE_STALE_AFTER, 2–15 minutes).
	StaleAfter time.Duration
	// APIServer is the API server's https URL; APICAFile its CA and
	// APITokenFile the gateway's own token for it.
	APIServer, APICAFile, APITokenFile string
	// APIServerOverride reports MESHGW_KUBE_API_BACKEND set: tests only.
	APIServerOverride bool
	// APIAudiences are the API server's audiences the chart expects
	// (MESHGW_API_AUDIENCES, by commas): the token VAP admits only tokens
	// for exactly these, and the gateway reports a cluster whose own differ
	// (K1c Q91). Empty: not checked.
	APIAudiences []string
	// StatefulSet, Replicas, ServiceAccount and Secrets name the gateway's
	// objects for rbaccheck; GuardedNamespaces add to kube-system
	// (MESHGW_GUARDED_NAMESPACES).
	StatefulSet       string
	Replicas          int
	ServiceAccount    string
	Secrets           []string
	GuardedNamespaces []string
	// Profiles: the gateway narrows groups by access profiles (K2,
	// MESHGW_KUBE_PROFILES), so it asks Core for gateway.kube.v2.
	Profiles bool
}

// groupSpec is one entry of MESHGW_KUBE_GROUPS.
type groupSpec struct {
	Name               string   `json:"name"`
	Default            bool     `json:"default"`
	Namespaces         []string `json:"namespaces"` // the chart's RoleBindings; unused here
	Privileged         bool     `json:"privileged"`
	AllowedPrincipals  []string `json:"allowedPrincipals"`
	AllowImpersonation bool     `json:"allowImpersonation"`
}

// loadKubeConfig reads a K1 gateway's kubectl configuration. apiServer is
// KUBERNETES_SERVICE_HOST:PORT; certificates whether the replica keeps a
// certificate, which the proxy serves with.
func loadKubeConfig(getenv func(string) string, cfg Config, apiServer string, certificates bool,
) (KubeConfig, error) {
	value := func(name, fallback string) string {
		if got := strings.TrimSpace(getenv(name)); got != "" {
			return got
		}
		return fallback
	}
	rawGroups := value("MESHGW_KUBE_GROUPS", "")
	mode := value("MESHGW_KUBE_MODE", KubeModeProxy)
	switch mode {
	case KubeModePassthrough:
		for _, name := range proxyOnlyVariables {
			if value(name, "") != "" {
				return KubeConfig{}, fmt.Errorf("meshgw: MESHGW_KUBE_MODE=passthrough takes no %s", name)
			}
		}
		return KubeConfig{Mode: mode}, nil
	case KubeModeProxy:
	default:
		return KubeConfig{}, fmt.Errorf(`meshgw: MESHGW_KUBE_MODE must be %q or %q`, KubeModeProxy, KubeModePassthrough)
	}
	if !certificates {
		return KubeConfig{}, errors.New("meshgw: MESHGW_KUBE_MODE=proxy serves with the replica certificate: " +
			"MESHGW_CERTIFICATES must be on")
	}
	groups, err := parseGroups(rawGroups)
	if err != nil {
		return KubeConfig{}, err
	}
	resources, err := parseSecretResources(value("MESHGW_SECRET_RESOURCES", ""))
	if err != nil {
		return KubeConfig{}, err
	}
	staleAfter, err := time.ParseDuration(value("MESHGW_KUBE_STALE_AFTER", defaultKubeStaleAfter.String()))
	if err != nil || staleAfter < 2*time.Minute || staleAfter > 15*time.Minute {
		return KubeConfig{}, errors.New("meshgw: MESHGW_KUBE_STALE_AFTER must be a duration of 2m to 15m")
	}
	server := "https://" + apiServer
	override := value("MESHGW_KUBE_API_BACKEND", "")
	if override != "" {
		parsed, err := url.Parse(override)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return KubeConfig{}, errors.New("meshgw: MESHGW_KUBE_API_BACKEND must be https://host:port")
		}
		server = override
	}
	if !isDNSLabel(cfg.Namespace) {
		return KubeConfig{}, errors.New("meshgw: proxy mode needs POD_NAMESPACE from the downward API")
	}
	replicas, err := strconv.Atoi(value("MESHGW_REPLICAS", strconv.Itoa(defaultReplicas)))
	if err != nil || replicas < 1 || replicas > maximumReplicas {
		return KubeConfig{}, fmt.Errorf("meshgw: MESHGW_REPLICAS must be 1 to %d", maximumReplicas)
	}
	// A replica past the count means the StatefulSet grew without it:
	// rbaccheck would not guard the new pods' names (review b5b M5).
	if cfg.Ordinal >= replicas {
		return KubeConfig{}, fmt.Errorf("meshgw: replica %d is past MESHGW_REPLICAS=%d: raise it with the StatefulSet",
			cfg.Ordinal, replicas)
	}
	// A comma list (the chart joins its values), never JSON: brackets and
	// quotes would be taken as part of an audience (review c2a M1).
	audiences := splitList(value("MESHGW_API_AUDIENCES", ""))
	for index, audience := range audiences {
		if len(audience) > maximumAudienceBytes || strings.ContainsFunc(audience, unicode.IsSpace) ||
			strings.ContainsFunc(audience, unicode.IsControl) || strings.ContainsAny(audience, `"[]`) ||
			slices.Contains(audiences[:index], audience) {
			return KubeConfig{}, fmt.Errorf("meshgw: MESHGW_API_AUDIENCES: %q is not an audience, or repeats", audience)
		}
	}
	profiles, err := strconv.ParseBool(value("MESHGW_KUBE_PROFILES", "false"))
	if err != nil {
		return KubeConfig{}, errors.New("meshgw: MESHGW_KUBE_PROFILES must be true or false")
	}
	statefulSet := cfg.PodName[:strings.LastIndexByte(cfg.PodName, '-')]
	serviceAccount := value("MESHGW_SERVICE_ACCOUNT", defaultServiceAccount)
	if !isDNSSubdomain(statefulSet) || !isDNSSubdomain(serviceAccount) {
		return KubeConfig{}, errors.New("meshgw: the StatefulSet and MESHGW_SERVICE_ACCOUNT must be DNS names")
	}
	prefix := strings.TrimSuffix(cfg.StateSecret, "-"+strconv.Itoa(cfg.Ordinal))
	secrets := []string{value("MESHGW_ENVELOPE_SECRET", defaultEnvelopeSecret), value("MESHGW_JOIN_SECRET", defaultJoinSecret)}
	// Two more than the replicas, for a scale-up (as rbaccheck's pods).
	for ordinal := range replicas + 2 {
		secrets = append(secrets, prefix+"-"+strconv.Itoa(ordinal))
	}
	return KubeConfig{
		Mode: mode, Cluster: cfg.Cluster, Groups: groups, SecretResources: resources, StaleAfter: staleAfter,
		APIServer: server, APICAFile: value("MESHGW_KUBE_API_CA_FILE", defaultAPICAFile),
		APITokenFile: value("MESHGW_KUBE_API_TOKEN_FILE", defaultAPITokenFile), APIServerOverride: override != "",
		StatefulSet: statefulSet, Replicas: replicas, ServiceAccount: serviceAccount, Secrets: secrets,
		GuardedNamespaces: splitList(value("MESHGW_GUARDED_NAMESPACES", "")), APIAudiences: audiences,
		Profiles: profiles,
	}, nil
}

// parseGroups reads MESHGW_KUBE_GROUPS strictly.
func parseGroups(raw string) ([]kubeproxy.Group, error) {
	if raw == "" {
		return nil, errors.New("meshgw: MESHGW_KUBE_GROUPS is required in proxy mode")
	}
	if len(raw) > maximumKubeGroupsBytes {
		return nil, errors.New("meshgw: MESHGW_KUBE_GROUPS is too long")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	var specs []groupSpec
	if err := decoder.Decode(&specs); err != nil {
		return nil, fmt.Errorf("meshgw: MESHGW_KUBE_GROUPS is not a JSON list of groups: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("meshgw: MESHGW_KUBE_GROUPS has more after its list")
	}
	groups := make([]kubeproxy.Group, 0, len(specs))
	defaults := 0
	for _, spec := range specs {
		groups = append(groups, kubeproxy.Group{
			Name: spec.Name, Default: spec.Default, Privileged: spec.Privileged,
			AllowedPrincipals: spec.AllowedPrincipals, AllowImpersonation: spec.AllowImpersonation,
		})
		if spec.Default {
			defaults++
		}
	}
	// Exactly one default (K1 §6): kubectl without a group uses it.
	if defaults != 1 {
		return nil, errors.New("meshgw: MESHGW_KUBE_GROUPS needs exactly one default group")
	}
	if err := kubeproxy.ValidateGroups(groups); err != nil {
		return nil, fmt.Errorf("meshgw: MESHGW_KUBE_GROUPS: %w", err)
	}
	return groups, nil
}

// parseSecretResources reads "resource.group" names, a bare resource being
// the core group's.
func parseSecretResources(raw string) ([]kubereq.GroupResource, error) {
	var resources []kubereq.GroupResource
	for _, name := range splitList(raw) {
		resource, group, _ := strings.Cut(name, ".")
		if !isDNSLabel(resource) || group != "" && !isDNSSubdomain(group) {
			return nil, fmt.Errorf("meshgw: MESHGW_SECRET_RESOURCES: %q is not resource.group", name)
		}
		resources = append(resources, kubereq.GroupResource{Group: group, Resource: resource})
	}
	return resources, nil
}

func splitList(raw string) []string {
	var items []string
	for item := range strings.SplitSeq(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// isDNSSubdomain reports an RFC 1123 subdomain.
func isDNSSubdomain(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if !isDNSLabel(label) {
			return false
		}
	}
	return true
}
