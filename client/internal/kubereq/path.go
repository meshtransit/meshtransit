package kubereq

import (
	"errors"
	"strings"
)

// maximumPath bounds a path the gateway forwards.
const maximumPath = 4096

// ErrPath reports a path the gateway refuses to forward.
var ErrPath = errors.New("kubereq: path not allowed")

// CheckPath reports a path the gateway may forward (K1b design §5): it
// starts with "/", holds printable ASCII but "%" and "\", and has no empty
// (but for one trailing "/"), "." or ".." segment. Kubernetes names never
// need more, and nothing else is then left for the API server to read
// otherwise than the gateway does. Callers pass the path as it came, still
// escaped (URL.EscapedPath, review b1 L4): a "%" is refused before any
// decoding, so the decoded path the gateway classifies is the path itself.
func CheckPath(path string) error {
	if len(path) < 2 || len(path) > maximumPath || path[0] != '/' {
		return ErrPath
	}
	for index := 0; index < len(path); index++ {
		if character := path[index]; character <= ' ' || character >= 0x7f || character == '%' || character == '\\' {
			return ErrPath
		}
	}
	segments := strings.Split(strings.TrimSuffix(path[1:], "/"), "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return ErrPath
		}
	}
	return nil
}

// groupPrefix starts a path that names the Kubernetes group to use.
const groupPrefix = "/mt/g/"

// SplitGroup reads a path that may name a group as /mt/g/<group>/…: it
// returns the group (empty when none is named) and the path to forward,
// which must be an API path (/api, /apis and below) or a safe non-resource
// one; false otherwise, including any other /mt/ path, which the gateway
// answers itself. The path was checked with CheckPath.
func SplitGroup(path string) (string, string, bool) {
	// Paths outside /mt/ go to the default group; what is not an API path
	// is then type A (unparsed), never refused here.
	if !strings.HasPrefix(path, "/mt/") {
		return "", path, true
	}
	rest, named := strings.CutPrefix(path, groupPrefix)
	if !named {
		return "", "", false
	}
	group, forwarded, found := strings.Cut(rest, "/")
	if !found || !dnsLabel(group) {
		return "", "", false
	}
	forwarded = "/" + forwarded
	if forwarded != "/api" && !strings.HasPrefix(forwarded, "/api/") && forwarded != "/apis" &&
		!strings.HasPrefix(forwarded, "/apis/") && !safeNonResource(forwarded) {
		return "", "", false
	}
	return group, forwarded, true
}

// dnsLabel reports a DNS label (RFC 1123): what a group's name is.
func dnsLabel(name string) bool {
	if name == "" || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

// safeNonResource reports the non-resource paths a GET or HEAD only reads:
// discovery, OpenAPI, the service account issuer's documents and health.
func safeNonResource(path string) bool {
	parts := splitPath(path)
	switch {
	case len(parts) == 0:
		return false
	case parts[0] == "api":
		return len(parts) <= 2
	case parts[0] == "apis":
		return len(parts) <= 3
	case path == "/version", path == "/openapi/v2", path == "/.well-known/openid-configuration",
		path == "/openid/v1/jwks":
		return true
	case parts[0] == "openapi":
		return len(parts) >= 2 && parts[1] == "v3"
	case parts[0] == "healthz", parts[0] == "livez", parts[0] == "readyz":
		return true
	}
	return false
}
