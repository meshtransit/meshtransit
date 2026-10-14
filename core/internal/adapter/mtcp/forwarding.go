package mtcp

import (
	"context"
	"sync"
	"time"
)

// untrustedForwardingWarnEvery spaces the warning about forwarding headers
// from an untrusted peer: often enough to be seen, never a flood a client
// can drive by sending such headers itself.
const untrustedForwardingWarnEvery = 10 * time.Minute

// forwardingWarning rate-limits the untrusted-forwarding warning.
type forwardingWarning struct {
	mu   sync.Mutex
	next time.Time
}

// due reports whether a warning may be logged now, and if so holds the
// next one back for untrustedForwardingWarnEvery.
func (warning *forwardingWarning) due(now time.Time) bool {
	warning.mu.Lock()
	defer warning.mu.Unlock()
	if now.Before(warning.next) {
		return false
	}
	warning.next = now.Add(untrustedForwardingWarnEvery)
	return true
}

// noteUntrustedForwarding records a request whose client-forwarding headers
// were ignored because its peer is not a trusted proxy. Behind a proxy that
// is missing from the trusted set every client shares the proxy's address,
// so one busy source can exhaust the per-source limits (mtcp-v1 §14).
func (server *Server) noteUntrustedForwarding(ctx context.Context) {
	server.options.Metrics.untrustedForwarding()
	if !server.forwarding.due(server.options.Now()) {
		return
	}
	server.options.Logger.WarnContext(ctx,
		"mtcp request carries client-forwarding headers from an untrusted peer; if Core runs behind a "+
			"reverse proxy, add its address to MESHTRANSIT_CONTROL_MTCP_TRUSTED_PROXY_CIDRS, otherwise all "+
			"clients share the proxy's address for admission limits",
		"error_code", "mtcp_untrusted_forwarding")
}
