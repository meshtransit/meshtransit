package config

// envExitSpread lets Exit Pools become spread (exit node design §16): maps
// then give each consumer its own exit node of the pool's serving set. Off
// by default; turn it on once every role runs a Core that knows spread
// pools, and set it the same on every role.
const envExitSpread = "MESHTRANSIT_EXIT_SPREAD_ENABLED"

func loadExitSpread(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envExitSpread, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envExitSpread)
	}
}
