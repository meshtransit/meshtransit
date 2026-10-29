package kubeproxy

import (
	"net/http"
	"strings"
)

// bearerProtocol prefixes the WebSocket subprotocol that carries a token.
const bearerProtocol = "base64url.bearer.authorization.k8s.io."

// credentialHeader reports a header that names who the request is from, or
// claims to: never forwarded from the client (K1-I3).
func credentialHeader(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "authorization", "proxy-authorization", "cookie", "x-real-ip", "forwarded", "audit-id":
		return true
	}
	return strings.HasPrefix(name, "impersonate-") || strings.HasPrefix(name, "x-remote-") ||
		strings.HasPrefix(name, "x-forwarded-")
}

// stripCredentials drops every credential the client sent: the headers
// above, and a token in a WebSocket subprotocol, whatever its case or how
// the values are split (review v1 L3).
func stripCredentials(header http.Header) {
	for name := range header {
		if credentialHeader(name) {
			delete(header, name)
		}
	}
	values := header.Values("Sec-Websocket-Protocol")
	if len(values) == 0 {
		return
	}
	var kept []string
	for _, value := range values {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if protocol != "" && !strings.HasPrefix(strings.ToLower(protocol), bearerProtocol) {
				kept = append(kept, protocol)
			}
		}
	}
	header.Del("Sec-Websocket-Protocol")
	if len(kept) > 0 {
		header.Set("Sec-Websocket-Protocol", strings.Join(kept, ", "))
	}
}

// connectionNamesCredentials refuses a Connection header naming a
// credential header: it would have a proxy drop the gateway's own.
func connectionNamesCredentials(header http.Header) string {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if credentialHeader(strings.TrimSpace(token)) {
				return "a Connection header names an identity header"
			}
		}
	}
	return ""
}

// browserRequest refuses what a browser sends and client-go never does: a
// page cannot reach the cluster through a laptop on the mesh (K1 §5.2).
func browserRequest(r *http.Request) string {
	for _, name := range []string{"Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Cookie"} {
		if r.Header.Get(name) != "" {
			return "requests from a web browser are not served"
		}
	}
	return ""
}
