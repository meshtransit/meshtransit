package config

// envSubnetRoutes turns subnet routes on for the deployment: Access Rules
// may name Sites, and maps carry routes (mtcp-v1 §7.6). Off by default.
// Every role reads it so that the roles that compile policy and the roles
// that encode maps always agree.
const envSubnetRoutes = "MESHTRANSIT_SUBNET_ROUTES_ENABLED"

func loadSubnetRoutes(lookup LookupFunc) (bool, error) {
	switch valueOrDefault(lookup, envSubnetRoutes, "false") {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, settingError(envSubnetRoutes)
	}
}
