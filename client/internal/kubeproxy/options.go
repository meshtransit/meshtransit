// Package kubeproxy is a Kubernetes gateway's kubectl proxy: it ends TLS
// with the replica's certificate, names the Device by the key its packets
// come under, checks each request against the map, has Core record type A
// operations first, and forwards with a token of the group's account
// (K1b design §3–§6).
package kubeproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubeaudit"
	"meshtransit.net/client/internal/kubeevent"
	"meshtransit.net/client/internal/kubereq"
	"meshtransit.net/client/internal/kubetoken"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/rbaccheck"
)

// Peer is the map's Device at a connection's source, under the node key
// its packets come under.
type Peer struct {
	DeviceID, Name string
	Key            [32]byte
	Access         *networkmap.KubernetesAccess
}

// Group is one Kubernetes group of the gateway, as its values configure it
// (K1b design §10).
type Group struct {
	Name    string
	Default bool
	// Privileged groups are used only by name, by the principals listed,
	// on Devices that kept their owner a week.
	Privileged         bool
	AllowedPrincipals  []string
	AllowImpersonation bool
}

// Recorder has Core record type A operations (kubeaudit.Recorder).
type Recorder interface {
	Record(ctx context.Context, device string, intent controlplane.KubeAuditIntent) kubeaudit.Answer
	Finished(auditID [16]byte, status int, duration time.Duration)
	Denied(peer, reason string)
}

// Bearer is a minted token: its value never formats (kubetoken.Token).
type Bearer interface {
	Value() string
	ID() []byte
}

// Tokens mints the group accounts' tokens.
type Tokens interface {
	For(ctx context.Context, device, owner, group string) (Bearer, error)
	Forget(device, owner, group string, token Bearer)
}

// MinterTokens are a kubetoken.Minter's tokens.
type MinterTokens struct{ Minter *kubetoken.Minter }

// For implements Tokens.
func (tokens MinterTokens) For(ctx context.Context, device, owner, group string) (Bearer, error) {
	token, err := tokens.Minter.For(ctx, device, owner, group)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// Forget implements Tokens.
func (tokens MinterTokens) Forget(device, owner, group string, token Bearer) {
	if minted, ok := token.(kubetoken.Token); ok {
		tokens.Minter.Forget(device, owner, group, minted)
	}
}

// Options configure a proxy.
type Options struct {
	// Cluster names the cluster, as whoami says.
	Cluster string
	// Namespace is the gateway's: its accounts' namespace.
	Namespace string
	Groups    []Group
	// Backend is the API server's https URL and BackendCA its CA file.
	Backend   string
	BackendCA string
	// Peer finds the Device at a source address (daemon KubernetesPeerAt).
	Peer func(netip.Addr) (Peer, bool)
	// Certificate is the replica's certificate now; false: none valid.
	Certificate func() (*tls.Certificate, bool)
	// MapFreshAt is when Core last confirmed the map current; StaleAfter
	// how long it stays usable.
	MapFreshAt func() time.Time
	StaleAfter time.Duration
	// CoreNow is Core's clock, which grants' deadlines are on.
	CoreNow func() time.Time
	// Verdict is rbaccheck's verdict on a group.
	Verdict func(group string) rbaccheck.Verdict
	Records Recorder
	Tokens  Tokens
	// SecretResources are read like secrets.
	SecretResources []kubereq.GroupResource
	// Events record each use of a privileged group on the cluster's side;
	// required when a group is privileged (K1b design §4).
	Events PrivilegedEvents
	// Limits bound connections and sessions; zero: DefaultLimits.
	Limits Limits
	// Pressure, when set, reports the heap past its watermark: new
	// watches, followed logs, upgrades and lists are refused (§8).
	Pressure func() bool
	// Wake, when set, has Run sweep the sessions at once (rbaccheck's
	// verdicts changed); a map change waits for the next second's sweep.
	Wake    <-chan struct{}
	Version string
	Logger  *slog.Logger
}

// PrivilegedEvents is kubeevent.Recorder: counted false with an error
// means the cluster could not be told, and the use is refused.
type PrivilegedEvents interface {
	Privileged(ctx context.Context, use kubeevent.Use) (counted bool, err error)
}

// staleBounds bound StaleAfter (K1b design §4).
const (
	minimumStale = 2 * time.Minute
	maximumStale = 15 * time.Minute
)

func (options Options) validate() error {
	backend, err := url.Parse(options.Backend)
	switch {
	case options.Cluster == "" || !dnsLabel(options.Namespace) || len(options.Groups) == 0:
		return errors.New("kubeproxy: a cluster, a namespace and groups are required")
	case err != nil || backend.Scheme != "https" || backend.Host == "" || backend.User != nil ||
		backend.RawQuery != "" || backend.Fragment != "" || backend.Path != "" && backend.Path != "/":
		return errors.New("kubeproxy: the API server must be an https URL")
	case options.Peer == nil || options.Certificate == nil || options.MapFreshAt == nil || options.CoreNow == nil ||
		options.Verdict == nil || options.Records == nil || options.Tokens == nil || options.Logger == nil:
		return errors.New("kubeproxy: missing dependencies")
	case options.StaleAfter < minimumStale || options.StaleAfter > maximumStale:
		return errors.New("kubeproxy: staleAfter must be 2 to 15 minutes")
	case options.Limits != (Limits{}) && !options.Limits.valid():
		return errors.New("kubeproxy: invalid limits")
	case options.Events == nil && slices.ContainsFunc(options.Groups, func(group Group) bool { return group.Privileged }):
		return errors.New("kubeproxy: a privileged group needs the cluster's Events")
	}
	return ValidateGroups(options.Groups)
}

// ValidateGroups checks groups as the chart will (K1 §6): DNS labels, one
// default and not privileged, principals for a privileged group,
// impersonation only for one.
func ValidateGroups(groups []Group) error {
	defaults := 0
	seen := map[string]bool{}
	for _, group := range groups {
		switch {
		case !dnsLabel(group.Name) || seen[group.Name]:
			return errors.New("kubeproxy: group names must be distinct DNS labels")
		case group.Privileged && len(group.AllowedPrincipals) == 0:
			return errors.New("kubeproxy: a privileged group needs allowedPrincipals")
		case !group.Privileged && (group.AllowImpersonation || len(group.AllowedPrincipals) > 0):
			return errors.New("kubeproxy: only a privileged group impersonates or lists principals")
		case group.Default && group.Privileged:
			return errors.New("kubeproxy: the default group cannot be privileged")
		case slices.Contains(group.AllowedPrincipals, ""):
			return errors.New("kubeproxy: an empty principal")
		}
		seen[group.Name] = true
		if group.Default {
			defaults++
		}
	}
	if defaults > 1 {
		return errors.New("kubeproxy: at most one default group")
	}
	return nil
}

// dnsLabel reports an RFC 1123 label.
func dnsLabel(name string) bool {
	if name == "" || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
