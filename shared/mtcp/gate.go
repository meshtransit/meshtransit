package mtcp

// The gateway gate's Error messages (mtcp-v1 §6.7, §6.8). Core sends them
// and a gateway client maps them; both use these constants, so wording
// cannot drift between the two.
const (
	GateProveFirst     = "a Kubernetes gateway must prove its node key first"
	GateMachineRetired = "machine key is retired"
	GateNodeNotCurrent = "node key is not current"
	GateMachineUnbound = "machine key is not bound"
	GateInvalidProof   = "invalid node key proof"
	GateReplayed       = "handshake replayed"
	GateAhead          = "handshake timestamp is ahead of Core"
	GateUnavailable    = "handshake check unavailable"
)
