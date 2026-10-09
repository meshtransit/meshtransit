package dataplane

import (
	"bytes"
	"sync"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/key"
)

// relayCredentials is what this node presents to Interchange relays: the
// disco key the daemon uses for this control session and the latest ticket
// Core issued for it. It implements interchange.Credentials.
type relayCredentials struct {
	now func() time.Time

	mu          sync.Mutex
	disco       key.DiscoPrivate
	ticket      []byte
	notAfter    time.Time
	ticketDisco key.DiscoPublic
}

func newRelayCredentials(now func() time.Time) *relayCredentials {
	return &relayCredentials{now: now}
}

// RelayCredentials returns the disco key and ticket while the ticket binds
// that key and has not expired.
func (c *relayCredentials) RelayCredentials() (key.DiscoPrivate, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disco.IsZero() || len(c.ticket) == 0 || c.ticketDisco != c.disco.Public() ||
		!c.now().Before(c.notAfter) {
		return key.DiscoPrivate{}, nil, false
	}
	return c.disco, bytes.Clone(c.ticket), true
}

func (c *relayCredentials) setIdentity(disco key.DiscoPrivate) {
	c.mu.Lock()
	c.disco = disco
	c.mu.Unlock()
}

// setGrant adopts the ticket of a map's relay grant. A map without one keeps
// the current ticket until it expires.
func (c *relayCredentials) setGrant(grant *networkmap.Interchange) {
	if grant == nil {
		return
	}
	c.mu.Lock()
	c.ticket = bytes.Clone(grant.Ticket)
	c.notAfter = grant.TicketNotAfter
	c.ticketDisco = key.DiscoPublic(grant.TicketDisco)
	c.mu.Unlock()
}

// usesInterchange reports whether a relay configuration names Interchange
// (MTRP) relays rather than legacy ones.
func usesInterchange(config relay.Config) bool {
	for _, region := range config.Regions {
		for _, node := range region.Nodes {
			if node.RelayKey != ([32]byte{}) {
				return true
			}
		}
	}
	return false
}

// SetRelayIdentity sets the disco key this node proves to Interchange relays.
// The daemon calls it once per control session, before Apply, with the key
// whose public half it reports to Core.
func (e *WireGuardEngine) SetRelayIdentity(disco key.DiscoPrivate) {
	if e != nil && e.credentials != nil {
		e.credentials.setIdentity(disco)
	}
}

// EnforcedPolicy returns the digest of the rules the packet filter enforces
// right now, for the daemon to report to Core (R1-69).
func (e *WireGuardEngine) EnforcedPolicy() (EnforcedPolicy, bool) {
	if e == nil {
		return EnforcedPolicy{}, false
	}
	return e.filter.Enforced()
}

// SetPolicyDriftTest makes the packet filter enforce one rule fewer than
// Core sends. It exists only to demonstrate enforcement mismatch detection
// and must never be enabled in production.
func (e *WireGuardEngine) SetPolicyDriftTest(enabled bool) {
	if e != nil {
		e.filter.setDropLastRule(enabled)
	}
}
