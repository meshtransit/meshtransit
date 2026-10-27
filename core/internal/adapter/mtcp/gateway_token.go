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
	// No token (an older meshgw, or no projected volume): refused before
	// any database read.
	if raw == "" {
		metrics.limited(gatewayTokenLimit(kubetoken.ReasonMissing))
		return node.GatewayToken{}, false
	}
	rotations := application.options.MachineKeyRotations
	if rotations == nil {
		metrics.limited(limitGatewayTrustUnavailable)
		return node.GatewayToken{}, false
	}
	readCtx, cancel := context.WithTimeout(ctx, registrationTimeout)
	trust, err := rotations.ReadRotationTrust(readCtx, machine, nodeKey)
	cancel()
	switch {
	case errors.Is(err, kubecluster.ErrNotFound):
		metrics.limited(limitGatewayTrustMissing)
		return node.GatewayToken{}, false
	case err != nil:
		metrics.limited(limitGatewayTrustUnavailable)
		return node.GatewayToken{}, false
	case !trust.Complete():
		// No trust, or a gateway that joined before K1.1: it joins again.
		metrics.limited(limitGatewayTrustMissing)
		return node.GatewayToken{}, false
	}
	jwks, err := kubejoin.ParseJWKS(trust.JWKS)
	if err != nil {
		metrics.limited(limitGatewayTrustUnavailable)
		return node.GatewayToken{}, false
	}
	claims, err := kubetoken.Verify(raw, kubetoken.Expectation{Issuer: trust.Issuer, JWKS: jwks,
		Namespace: trust.Namespace, ServiceAccount: trust.ServiceAccount, PodName: trust.PodName}, application.now())
	if refused, ok := errors.AsType[*kubetoken.RefusedError](err); ok {
		metrics.limited(gatewayTokenLimit(refused.Reason))
		return node.GatewayToken{}, false
	}
	if err != nil {
		metrics.limited(limitGatewayTrustMissing)
		return node.GatewayToken{}, false
	}
	token := node.GatewayToken{DeviceID: trust.DeviceID, TrustVersion: trust.TrustVersion, JTI: claims.JTI,
		ExpiresAt: claims.Expiry}
	if !token.IsValid() {
		metrics.limited(gatewayTokenLimit(kubetoken.ReasonMalformed))
		return node.GatewayToken{}, false
	}
	return token, true
}
