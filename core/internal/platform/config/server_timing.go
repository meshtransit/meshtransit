package config

// envServerTiming adds a Server-Timing header to Console management answers:
// the database, Redis and total time of each (TD-CON-48). It carries
// durations only. Off by default; turn it on to measure, not as a feature.
const envServerTiming = "MESHTRANSIT_SERVER_TIMING"

func loadServerTiming(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envServerTiming, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envServerTiming)
	}
}
