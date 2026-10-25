package config

// envKubernetesJoin lets Kubernetes gateway replicas join their clusters
// over MTCP (mtcp-v1 §6.6). Off by default until gateways prove their keys
// on every session and cannot log out (K1a1.4) and a second approver guards
// approvals (K1a1.6): with it off, clusters and join keys can be prepared
// but every join is refused.
const envKubernetesJoin = "MESHTRANSIT_KUBERNETES_JOIN"

func loadKubernetesJoin(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envKubernetesJoin, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envKubernetesJoin)
	}
}
