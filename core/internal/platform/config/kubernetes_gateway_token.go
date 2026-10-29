package config

import "meshtransit.net/core/internal/domain/kubecluster"

// envKubernetesGatewayToken is how strictly Core holds Kubernetes gateways
// to presenting their pod token on every session (mtcp-v1 §6.7,
// gateway.token1): observe, ratchet (the default) or required. Core offers
// gateway.token1 whenever its database has the functions, whatever the
// mode; every mode ratchets a Device once a session of it proved a token.
const envKubernetesGatewayToken = "MESHTRANSIT_KUBERNETES_GATEWAY_TOKEN" //nolint:gosec // G101: a variable name

func loadKubernetesGatewayToken(lookup LookupFunc) (kubecluster.GatewayTokenMode, error) {
	mode := kubecluster.GatewayTokenMode(valueOrDefault(lookup, envKubernetesGatewayToken,
		string(kubecluster.GatewayTokenRatchet)))
	if !mode.IsKnown() {
		return "", settingError(envKubernetesGatewayToken)
	}
	return mode, nil
}
