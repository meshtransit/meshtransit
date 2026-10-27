package mtcp

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/adapter/kubetoken"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubejoin"
)

// gatewayRotationToken verifies the pod ServiceAccount token a Kubernetes
// gateway's rotation carries (K1.1 design §7.2, §7.3), against its
// cluster's signing trust and the pod its join named, read for the keys the
// session proved. It returns the token's evidence for the store, which
// records one use of it; or false, counted, and the rotation is refused. A
// copy of the gateway's Secret has no such token.
func (conversation *conversation) gatewayRotationToken(ctx context.Context, raw string,
	machine node.MachineKey, nodeKey node.Key) (node.GatewayToken, bool) {
	application := conversation.application
	metrics := application.options.Metrics
	// Each refusal is counted, and audited off the session's path (schema
	// 233): token_missing is how a copy of the gateway's Secret shows.
	refuseWith := func(limit string, reason kubecluster.KeyEventReason, keyID string) (node.GatewayToken, bool) {
		metrics.limited(limit)
		if conversation.session != nil && conversation.session.server != nil {
			conversation.session.server.keyReports.reportToken(machine.Fingerprint(), reason, keyID)
		}
		return node.GatewayToken{}, false
	}
	refuse := func(limit string, reason kubecluster.KeyEventReason) (node.GatewayToken, bool) {
		return refuseWith(limit, reason, "")
	}
	refuseToken := func(reason kubetoken.Reason) (node.GatewayToken, bool) {
		return refuse(gatewayTokenLimit(reason), kubecluster.KeyEventReason(reason))
	}
	// No token (an older meshgw, or no projected volume): refused before
	// any database read.
	if raw == "" {
		return refuseToken(kubetoken.ReasonMissing)
	}
	rotations := application.options.MachineKeyRotations
	if rotations == nil {
		// Core's own configuration, not the gateway's: counted only.
		metrics.limited(limitGatewayTrustUnavailable)
		return node.GatewayToken{}, false
	}
	readCtx, cancel := context.WithTimeout(ctx, registrationTimeout)
	trust, err := rotations.ReadRotationTrust(readCtx, machine, nodeKey)
	cancel()
	switch {
	case errors.Is(err, kubecluster.ErrNotFound):
		return refuse(limitGatewayTrustMissing, kubecluster.KeyEventTrustMissing)
	case err != nil:
		return refuse(limitGatewayTrustUnavailable, kubecluster.KeyEventTrustUnavailable)
	case !trust.Complete():
		// No trust, or a gateway that joined before K1.1: it joins again.
		return refuse(limitGatewayTrustMissing, kubecluster.KeyEventTrustMissing)
	}
	jwks, err := kubejoin.ParseJWKS(trust.JWKS)
	if err != nil {
		return refuse(limitGatewayTrustUnavailable, kubecluster.KeyEventTrustUnavailable)
	}
	claims, err := kubetoken.Verify(raw, kubetoken.Expectation{Issuer: trust.Issuer, JWKS: jwks,
		Namespace: trust.Namespace, ServiceAccount: trust.ServiceAccount, PodName: trust.PodName}, application.now())
	if refused, ok := errors.AsType[*kubetoken.RefusedError](err); ok {
		// A key the trust lacks is named, so the Console can say which.
		return refuseWith(gatewayTokenLimit(refused.Reason), kubecluster.KeyEventReason(refused.Reason),
			refused.KeyID)
	}
	if err != nil {
		// The trust as read cannot check a token.
		return refuse(limitGatewayTrustUnavailable, kubecluster.KeyEventTrustUnavailable)
	}
	token := node.GatewayToken{DeviceID: trust.DeviceID, TrustVersion: trust.TrustVersion, JTI: claims.JTI,
		ExpiresAt: claims.Expiry}
	if !token.IsValid() {
		return refuseToken(kubetoken.ReasonMalformed)
	}
	return token, true
}
