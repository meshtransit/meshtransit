package kubeproxy

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubereq"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/kubeprofile"
)

// discoveryWait bounds how long a request waits for the cluster's discovery
// to be fetched again for a resource it does not know.
const discoveryWait = 2 * time.Second

// Discovery is the cluster's resource scopes (kubediscovery.Discovery).
type Discovery interface {
	Scope(ctx context.Context, group, resource string) kubeprofile.ResourceScope
}

// profileCheck is a request as access profiles read it (K2 §5.3): the
// request, and each name it impersonates (S5), all of which one grant must
// allow.
type profileCheck struct {
	request      kubeprofile.Attributes
	impersonated []kubeprofile.Attributes
	// exempt: a read of discovery or a self review, which kubectl needs
	// whatever the profile (§5.5); any grant of the group lets it through.
	exempt bool
}

// profileDecision is how a group's grants decide one request.
type profileDecision struct {
	// whole: the peer holds the group whole; no profile applies.
	whole   bool
	allowed bool
	// scope names the grant that let the request through, or the one whose
	// profile refused it.
	scope [32]byte
	// reported: a reporting grant let it through, its profile would deny.
	reported bool
	// refusing are the scopes that refused it, for the message.
	refusing []networkmap.KubernetesScope
}

// checkFor reads a request for the profiles: the outgoing URL's info, what
// the request's method and headers add (S1, S3), each name it impersonates
// (S5), and, when lookup is set, the resource's scope from the cluster's
// discovery. Discovery and self reviews are exempt, never what they
// impersonate (review e1–e3 H1).
func (server *Server) checkFor(ctx context.Context, r *http.Request, info kubereq.Info,
	impersonate http.Header, lookup bool,
) profileCheck {
	check := profileCheck{exempt: kubereq.SafeDiscovery(r.Method, info) || kubereq.SelfReview(r.Method, info)}
	for _, user := range impersonate.Values("Impersonate-User") {
		check.impersonated = append(check.impersonated, impersonation("users", user))
	}
	for _, group := range impersonate.Values("Impersonate-Group") {
		check.impersonated = append(check.impersonated, impersonation("groups", group))
	}
	if check.exempt {
		return check
	}
	check.request = kubeprofile.Attributes{
		ResourceRequest: info.IsResourceRequest, Verb: info.Verb, APIGroup: info.APIGroup, Resource: info.Resource,
		Subresource: info.Subresource, Namespace: info.Namespace, Name: info.Name, Path: info.Path,
		Upgrade:   kubereq.Upgrades(kubereq.Request{Method: r.Method, Header: r.Header}),
		MayCreate: r.Method == http.MethodPut || r.Method == http.MethodPatch && applyPatch(r.Header),
	}
	if lookup && info.IsResourceRequest && info.Resource != "" && server.options.Discovery != nil {
		waiting, cancel := context.WithTimeout(ctx, discoveryWait)
		check.request.Scope = server.options.Discovery.Scope(waiting, info.APIGroup, info.Resource)
		cancel()
	}
	return check
}

// impersonation is the API server's check of one impersonated name (S5).
func impersonation(resource, name string) kubeprofile.Attributes {
	return kubeprofile.Attributes{
		ResourceRequest: true, Verb: "impersonate", Resource: resource, Name: name,
		Scope: kubeprofile.ScopeCluster,
	}
}

// applyPatch reports a server-side apply, which creates what does not exist
// (S3), whatever its encoding.
func applyPatch(header http.Header) bool {
	media, _, _ := strings.Cut(header.Get("Content-Type"), ";")
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(media)), "application/apply-patch")
}

// allowedBy reports whether one scope allows the request and every name it
// impersonates.
func (check profileCheck) allowedBy(scope kubeprofile.Scope) bool {
	if !check.exempt && !scope.Allows(check.request) {
		return false
	}
	for _, name := range check.impersonated {
		if !scope.Allows(name) {
			return false
		}
	}
	return true
}

// decide applies the group's grants in force at now (K2 §9.1): a whole
// grant lets everything through; else the first scoped grant whose profile
// allows the request; else, before its deadline, a reporting grant, which
// lets it through and counts it. A privileged group never reports (§9.5).
func decide(peer Peer, group Group, check profileCheck, now time.Time) profileDecision {
	if peer.Access.WholeAt(now, group.Name) {
		return profileDecision{whole: true, allowed: true}
	}
	grants := peer.Access.ScopedAt(now, group.Name)
	decision := profileDecision{}
	var reporting *networkmap.KubernetesScopedGrant
	for index, grant := range grants {
		scope, named := peer.Scopes[grant.Scope]
		if !named {
			continue
		}
		if check.allowedBy(scope.Scope) {
			return profileDecision{allowed: true, scope: grant.Scope}
		}
		if reporting == nil && grant.Report && now.Before(grant.ReportUntil) && !group.Privileged {
			reporting = &grants[index]
		}
		if len(decision.refusing) == 0 {
			decision.scope = grant.Scope
		}
		decision.refusing = append(decision.refusing, scope)
	}
	if reporting != nil {
		return profileDecision{allowed: true, scope: reporting.Scope, reported: true, refusing: decision.refusing}
	}
	return decision
}

// profile is the scope hash an intent names: none for a whole grant.
func (decision profileDecision) profile() []byte {
	if decision.whole {
		return nil
	}
	return slices.Clone(decision.scope[:])
}

// sample is a refused request as Core keeps it.
func (check profileCheck) sample(scope [32]byte) controlplane.KubeAuditDenialSample {
	return controlplane.KubeAuditDenialSample{
		Verb: check.request.Verb, APIGroup: check.request.APIGroup,
		Resource: check.request.Resource, Subresource: check.request.Subresource,
		Namespace: check.request.Namespace, Scope: scope,
	}
}

// refuseProfile answers a request the group's profiles refuse: a Forbidden
// Status naming the profiles and what the request asked, with a hint for a
// list across namespaces, and the cluster's access contact last (K2 §9.2).
func (server *Server) refuseProfile(w http.ResponseWriter, peer Peer, group Group, check profileCheck,
	decision profileDecision,
) {
	if len(decision.refusing) == 0 {
		// Every scoped grant expired since choose: access ended.
		server.deny(w, peer.DeviceID, "not_granted", http.StatusForbidden, fmt.Sprintf(
			"the Device's access to group %s ended", group.Name,
		), 0)
		return
	}
	server.options.Records.ProfileDenied(peer.DeviceID, false, check.sample(decision.scope))
	refuse(w, http.StatusForbidden, profileMessage(peer, group, check, decision.refusing), 0)
}

// profileMessage is what kubectl shows of a profile's refusal.
func profileMessage(peer Peer, group Group, check profileCheck, refusing []networkmap.KubernetesScope) string {
	var message strings.Builder
	names := make([]string, 0, len(refusing))
	for _, scope := range refusing {
		names = append(names, fmt.Sprintf("%q (%s)", scope.ProfileName, namespacesText(scope.Scope)))
	}
	slices.Sort(names)
	names = slices.Compact(names)
	noun, verb := "profile", "does"
	if len(names) > 1 {
		noun, verb = "profiles", "do"
	}
	fmt.Fprintf(&message, "MeshTransit access %s %s of group %s %s not allow %s", noun, strings.Join(names, ", "),
		group.Name, verb, requestText(check.request))
	if check.request.ResourceRequest && check.request.Scope == kubeprofile.ScopeUnknown {
		message.WriteString("; the cluster's discovery does not know this resource")
	}
	if hint := namespaceHint(check.request, refusing); hint != "" {
		message.WriteString("; " + hint)
	}
	if len(check.impersonated) > 0 {
		message.WriteString(", or one of the names it impersonates")
	}
	if peer.AccessContact != "" {
		fmt.Fprintf(&message, " (access contact set by the cluster's admins: %q)", peer.AccessContact)
	}
	return message.String()
}

func namespacesText(scope kubeprofile.Scope) string {
	namespaces := scope.Namespaces()
	if slices.Equal(namespaces, []string{"*"}) {
		return "all namespaces"
	}
	if len(namespaces) == 1 {
		return "namespace " + namespaces[0]
	}
	return "namespaces " + strings.Join(namespaces, ", ")
}

// requestText names what a request asked, quoting what the client sent.
func requestText(request kubeprofile.Attributes) string {
	if !request.ResourceRequest {
		return fmt.Sprintf("%q on path %q", request.Verb, request.Path)
	}
	resource := request.Resource
	if request.Subresource != "" {
		resource += "/" + request.Subresource
	}
	text := fmt.Sprintf("%q on %q", request.Verb, resource)
	if request.APIGroup != "" {
		text += fmt.Sprintf(" of API group %q", request.APIGroup)
	}
	switch {
	case request.Namespace != "":
		text += fmt.Sprintf(" in namespace %q", request.Namespace)
	case request.Scope == kubeprofile.ScopeNamespaced:
		text += " across namespaces"
	}
	return text
}

// namespaceHint suggests -n for a list or watch across namespaces that one
// of the refusing scopes allows in a namespace of its own.
func namespaceHint(request kubeprofile.Attributes, refusing []networkmap.KubernetesScope) string {
	if !request.ResourceRequest || request.Namespace != "" || request.Scope != kubeprofile.ScopeNamespaced ||
		request.Verb != "list" && request.Verb != "watch" {
		return ""
	}
	for _, scope := range refusing {
		namespaces := scope.Scope.Namespaces()
		if len(namespaces) == 0 || namespaces[0] == "*" {
			continue
		}
		within := request
		within.Namespace = namespaces[0]
		if scope.Scope.Allows(within) {
			return "use -n " + namespaces[0]
		}
	}
	return ""
}
