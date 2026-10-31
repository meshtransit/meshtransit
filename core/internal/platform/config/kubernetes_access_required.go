package config

// envKubernetesAccessRequired makes a new rule to a Kubernetes cluster (or
// a rule now pointing to one) name its access: full group rights or a
// permission set (K2 Q195, K2h f5). Off by default, when such a rule sent
// without access grants its groups in full. Turning it off again only
// loosens input checks.
const envKubernetesAccessRequired = "MESHTRANSIT_KUBERNETES_ACCESS_REQUIRED"

func loadKubernetesAccessRequired(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envKubernetesAccessRequired, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envKubernetesAccessRequired)
	}
}
