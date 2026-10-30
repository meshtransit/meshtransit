package kubereq

import (
	"net/http"
	"net/url"
	"strings"
)

// Class is what a request is for the gateway's records (K1b design §5;
// gateway.audit1 classes). Every class but ClassRead is type A: Core
// records it before the gateway forwards it.
type Class string

// Classes, in the order they are decided: the first that holds is the
// request's.
const (
	ClassPrivileged Class = "privileged"
	ClassExec       Class = "exec"
	ClassProxy      Class = "proxy"
	ClassSecretRead Class = "secret_read"
	ClassWrite      Class = "write"
	ClassUnparsed   Class = "unparsed"
	ClassRead       Class = "read"
)

// TypeA reports a class Core must record before forwarding.
func (class Class) TypeA() bool { return class != ClassRead }

// GroupResource names a resource of an API group ("" is the core group).
type GroupResource struct {
	Group, Resource string
}

// secrets is the core group's secrets.
var secrets = GroupResource{Resource: "secrets"}

// selfReviews only ask what the caller itself may do or is (Q65).
var selfReviews = map[GroupResource]bool{
	{Group: "authorization.k8s.io", Resource: "selfsubjectaccessreviews"}: true,
	{Group: "authorization.k8s.io", Resource: "selfsubjectrulesreviews"}:  true,
	{Group: "authentication.k8s.io", Resource: "selfsubjectreviews"}:      true,
}

// interactive are the subresources that open a session in a container.
var interactive = map[string]bool{"exec": true, "attach": true, "portforward": true}

// Request is what classification reads of a request.
type Request struct {
	Method string
	// URL is the URL the gateway sends on, not the one it received.
	URL    *url.URL
	Header http.Header
}

// Options are what the request's group adds.
type Options struct {
	// Privileged reports a privileged group; Impersonating a request that
	// keeps Impersonate-* headers.
	Privileged, Impersonating bool
	// SecretResources are resources read like secrets, besides the core
	// group's.
	SecretResources []GroupResource
}

// Classify returns the request's class and what the API server reads of it.
// A read is a GET or HEAD (or a self-review's POST) that neither upgrades,
// proxies, opens a session nor reads a secret-like resource.
func Classify(request Request, options Options) (Class, Info) {
	if request.URL == nil {
		return ClassUnparsed, Info{}
	}
	info, err := Parse(request.Method, request.URL)
	reading := request.Method == http.MethodGet || request.Method == http.MethodHead
	switch {
	case options.Privileged || options.Impersonating:
		return ClassPrivileged, info
	case upgrades(request):
		return ClassExec, info
	case err != nil:
		return ClassUnparsed, info
	case !info.IsResourceRequest:
		if reading && safeNonResource(info.Path) {
			return ClassRead, info
		}
		return ClassUnparsed, info
	case interactive[info.Subresource]:
		return ClassExec, info
	case info.Verb == "proxy" || info.Subresource == "proxy":
		return ClassProxy, info
	}
	resource := GroupResource{Group: info.APIGroup, Resource: info.Resource}
	switch info.Verb {
	case "get", "list", "watch":
		// A watch the path names may come with any method; an aggregated
		// server may take that as a write (review b1 M1).
		if !reading {
			return ClassUnparsed, info
		}
		// Any subresource of a secret-like resource may return the whole
		// object, as a CRD's status does (review b1 H1).
		if resource == secrets || contains(options.SecretResources, resource) {
			return ClassSecretRead, info
		}
		return ClassRead, info
	case "create", "update", "patch", "delete", "deletecollection":
		if selfReviews[resource] && request.Method == http.MethodPost && info.Subresource == "" &&
			info.Namespace == "" && info.Name == "" {
			return ClassRead, info
		}
		return ClassWrite, info
	}
	return ClassUnparsed, info
}

// upgrades reports a request that asks to switch protocols: an
// interactive session, whatever resource it names (K1b design §5). As
// apimachinery's IsUpgradeRequest, any Connection value holding "upgrade"
// counts, and any Upgrade header besides.
func upgrades(request Request) bool {
	if request.Method == http.MethodConnect || len(request.Header.Values("Upgrade")) > 0 {
		return true
	}
	for _, value := range request.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(value), "upgrade") {
			return true
		}
	}
	return false
}

func contains(resources []GroupResource, resource GroupResource) bool {
	for _, candidate := range resources {
		if candidate == resource {
			return true
		}
	}
	return false
}

// Upgrades reports a request that asks to switch protocols, as Classify
// reads it.
func Upgrades(request Request) bool { return upgrades(request) }

// SelfReview reports a self review's POST, which Classify reads as a read:
// it only asks what the caller itself may do or is.
func SelfReview(method string, info Info) bool {
	return info.IsResourceRequest && method == http.MethodPost && info.Verb == "create" &&
		selfReviews[GroupResource{Group: info.APIGroup, Resource: info.Resource}] && info.Subresource == "" &&
		info.Namespace == "" && info.Name == ""
}

// SafeDiscovery reports a GET or HEAD of a path that only reads discovery,
// OpenAPI, the issuer's documents or health, which kubectl needs whatever
// the caller may do (K1b design §5).
func SafeDiscovery(method string, info Info) bool {
	return !info.IsResourceRequest && (method == http.MethodGet || method == http.MethodHead) &&
		safeNonResource(info.Path)
}
