package config

// envKubernetesClusteredProfiles tells Core that every Core of the
// Deployment knows the clusters of permission sets (K2h §32.12): sets of
// different clusters may share a name, a release holds up to 1024 sets, a
// new set names its cluster, and no rule newly applies a set of every
// cluster. Off by default; turn it on only once no Core before K2h runs,
// and do not roll back below K2h after.
const envKubernetesClusteredProfiles = "MESHTRANSIT_KUBERNETES_CLUSTERED_PROFILES"

func loadKubernetesClusteredProfiles(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envKubernetesClusteredProfiles, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envKubernetesClusteredProfiles)
	}
}
