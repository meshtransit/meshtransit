package postgres

// RegistrationAllocationPlanStatements returns, by name, the statements
// registration runs under the Network's allocator lock to choose an address
// and a hostname (schema 157). The qualification plan check runs them over
// a Network of thousands of Devices and requires the rows they touch not to
// grow with it. They are the exact statements registration sends.
func RegistrationAllocationPlanStatements() map[string]string {
	return map[string]string{
		"address floor":       lockRegistrationAddressFloorSQL,
		"reclaimable address": lowestReclaimableRegistrationAddressSQL,
		"lease window":        loadRegistrationLeasesSQL,
		"hostname candidates": registrationHostnamesTakenSQL,
	}
}
