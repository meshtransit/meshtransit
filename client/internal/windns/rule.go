// Package windns connects the MeshTransit resolver to Windows. The DNS
// client sends names under the Network's DNS routes to the resolver through
// one Name Resolution Policy Table (NRPT) rule; every other name keeps the
// system resolvers.
package windns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/client/internal/dnsconfig"
)

// ResolverAddress is where the MeshTransit resolver listens on Windows. NRPT
// name servers are reached on port 53 only; a loopback address of its own
// needs no adapter and cannot be reached from another machine.
var ResolverAddress = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 53, 53, 53}), 53)

// ErrAllNames refuses a plan that would send every name to MeshTransit:
// restoring the host's resolvers afterwards is not implemented on Windows.
var ErrAllNames = errors.New("windns: DNS for all names is not supported on Windows yet")

// maxNamespaces bounds the rule a map can ask for.
const maxNamespaces = 256

// Rule is the one NRPT rule MeshTransit installs.
type Rule struct {
	// Namespaces are DNS suffixes with a leading dot, such as ".shared.mesh".
	Namespaces []string
	// Server is the resolver the DNS client sends those names to.
	Server netip.Addr
}

// rootNamespace is NRPT's namespace of every name.
const rootNamespace = "."

// RuleFromPlan turns an enabled DNS plan into the NRPT rule that sends its
// route and search domains to server, and every name while the host uses
// an exit node (exit node design §7.1) or has a root zone (DNS design D1b
// §4.3): removing the rule gives the host its own resolvers back.
func RuleFromPlan(plan dnsconfig.Plan, server netip.Addr) (Rule, error) {
	if len(plan.DefaultResolvers) != 0 && plan.Exit == nil && plan.Root == nil {
		return Rule{}, ErrAllNames
	}
	if !server.Is4() {
		return Rule{}, fmt.Errorf("windns: resolver %s is not IPv4", server)
	}
	domains := make([]string, 0, len(plan.Routes)+len(plan.SearchDomains))
	for _, route := range plan.Routes {
		domains = append(domains, route.Suffix)
	}
	domains = append(domains, plan.SearchDomains...)
	namespaces := make([]string, 0, len(domains))
	for _, domain := range domains {
		if !validDomain(domain) {
			return Rule{}, fmt.Errorf("windns: domain %q is not a canonical DNS name", domain)
		}
		namespaces = append(namespaces, "."+domain)
	}
	if plan.Exit != nil || plan.Root != nil {
		namespaces = append(namespaces, rootNamespace)
	}
	slices.Sort(namespaces)
	namespaces = slices.Compact(namespaces)
	switch {
	case len(namespaces) == 0:
		return Rule{}, errors.New("windns: enabled plan has no DNS domains")
	case len(namespaces) > maxNamespaces:
		return Rule{}, fmt.Errorf("windns: %d DNS domains exceed %d", len(namespaces), maxNamespaces)
	}

	return Rule{Namespaces: namespaces, Server: server}, nil
}

// Equal reports whether two rules install the same policy.
func (r Rule) Equal(other Rule) bool {
	return r.Server == other.Server && slices.Equal(r.Namespaces, other.Namespaces)
}

// validDomain accepts lowercase names of letters, digits, hyphens and dots
// without empty labels; the root domain only comes with default resolvers.
func validDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}

	return true
}
