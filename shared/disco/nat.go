package disco

// Mapping is the NAT mapping behaviour (docs/protocol/nat-classification.md).
type Mapping uint8

// Mapping values.
const (
	MappingUnknown                 Mapping = 0
	MappingNone                    Mapping = 1
	MappingEndpointIndependent     Mapping = 2
	MappingAddressDependent        Mapping = 3
	MappingAddressAndPortDependent Mapping = 4
)

// Filtering is the NAT filtering behaviour.
type Filtering uint8

// Filtering values.
const (
	FilteringUnknown                 Filtering = 0
	FilteringEndpointIndependent     Filtering = 1
	FilteringAddressDependent        Filtering = 2
	FilteringAddressAndPortDependent Filtering = 3
)

// Allocation is the NAT port allocation pattern.
type Allocation uint8

// Allocation values.
const (
	AllocationUnknown    Allocation = 0
	AllocationPreserving Allocation = 1
	AllocationSequential Allocation = 2
	AllocationRandom     Allocation = 3
)

// NATInfo is a node's classification of the NAT in front of its socket.
type NATInfo struct {
	Mapping    Mapping
	Filtering  Filtering
	Allocation Allocation
}

// Easy reports a mapping that keeps one public port for every destination.
func (m Mapping) Easy() bool { return m == MappingNone || m == MappingEndpointIndependent }

// Hard reports an endpoint-dependent mapping.
func (m Mapping) Hard() bool {
	return m == MappingAddressDependent || m == MappingAddressAndPortDependent
}

func (n NATInfo) valid() bool {
	return n.Mapping <= MappingAddressAndPortDependent &&
		n.Filtering <= FilteringAddressAndPortDependent &&
		n.Allocation <= AllocationRandom
}
