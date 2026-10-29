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

// The gateway gate's pod token refusals (mtcp-v1 §6.7, gateway.token1),
// each a fatal Error{NOT_AUTHORIZED}. A gateway reads its token again and
// reconnects with its usual backoff; it never stops for one.
const (
	// GateTokenRequired: the session presented no pod token and its Device
	// presented one before, or Core requires one from every gateway.
	GateTokenRequired = "pod token required"
	// GateTokenRefused: the token does not check against the cluster's
	// trust or names another pod.
	GateTokenRefused = "pod token refused"
	// GateTokenExpired: the session's last token expired.
	GateTokenExpired = "pod token expired"
	// GateTokenClockSkew: the token was issued further ahead of Core's
	// clock than Core tolerates; the cluster's clock is wrong.
	GateTokenClockSkew = "pod token clock skew"
)
