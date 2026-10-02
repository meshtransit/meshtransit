package mapsession

func directDeviceProjectionsCanAdvance(current, next Snapshot) bool {
	before := make(map[string]DirectDeviceProjection, len(current.directDeviceProjections))
	for _, projection := range current.directDeviceProjections {
		before[projection.ContractID().String()+projection.ConsumerRuleID().String()] = projection
	}
	for _, projection := range next.directDeviceProjections {
		previous, found := before[projection.ContractID().String()+projection.ConsumerRuleID().String()]
		if !found {
			continue
		}
		if projection.providerNetworkRevision < previous.providerNetworkRevision ||
			projection.consumerNetworkRevision < previous.consumerNetworkRevision ||
			projection.consumerPolicyRevision < previous.consumerPolicyRevision ||
			projection.authority.Contract.Version() < previous.authority.Contract.Version() ||
			projection.authority.Endpoint.Generation() < previous.authority.Endpoint.Generation() ||
			projection.export.Version() < previous.export.Version() {
			return false
		}
	}
	return true
}
