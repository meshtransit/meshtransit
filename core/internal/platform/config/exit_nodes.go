package config

// envExitNodes lets Access Rules name Exit Pools, so a Device may be granted
// the Internet through exit nodes (exit node design §4.2). Off by default
// until maps carry Exit Pools and nodes forward to the Internet: with it off,
// Exit Pools can be prepared but no rule may grant one.
const envExitNodes = "MESHTRANSIT_EXIT_NODES_ENABLED"

func loadExitNodes(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envExitNodes, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envExitNodes)
	}
}
