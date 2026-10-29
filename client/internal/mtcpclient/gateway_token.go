package mtcpclient

import (
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	// podTokenReread is how often a gateway session reads its pod token
	// file again; it sends the token as soon as it changed (K1c-T H1).
	podTokenReread = 20 * time.Second
	// podTokenResend sends an unchanged token again, so a refresh Core
	// dropped is not lost for the token's life (review v2 N2).
	podTokenResend = 2 * time.Minute
)

// SetPodTokenSource has a gateway present its pod token on every session
// (gateway.token1, mtcp-v1 §6.7): source is read for each session and
// every podTokenReread while one runs; it returns empty when it has none.
// It is ignored on a client that is not a gateway's, and must be set before
// the first session.
func (c *Client) SetPodTokenSource(source func() controlplane.PodToken) {
	if c.gateway != nil {
		c.podToken = source
	}
}

// refreshPodToken sends the pod token when it changed since the session
// last sent it, or podTokenResend after; it reports a send failure, which
// ends the session.
func (run *sessionRun) refreshPodToken(now time.Time) error {
	s := run.s
	source := run.stream.client.podToken
	if !s.tokens || source == nil {
		return nil
	}
	token := source()
	if token == "" || token == s.podToken && now.Sub(s.podTokenSent) < podTokenResend {
		return nil
	}
	if err := s.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{PodToken: token.Reveal()}); err != nil {
		return err
	}
	s.podToken, s.podTokenSent = token, now
	return nil
}
