package config

// envKubernetesProfiles lets Kubernetes gateways take access profiles
// (MTCP gateway.kube.v2, K2): scoped grants and their cluster's scope table.
// Off by default until gateways enforce profiles (K2e): with it off, a rule
// that applies a profile grants nothing through any gateway.
const envKubernetesProfiles = "MESHTRANSIT_KUBERNETES_PROFILES"

func loadKubernetesProfiles(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envKubernetesProfiles, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envKubernetesProfiles)
	}
}
