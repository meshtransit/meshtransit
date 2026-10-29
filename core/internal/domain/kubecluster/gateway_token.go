package kubecluster

// GatewayTokenMode is how Core holds Kubernetes gateways to presenting
// their pod token on every session (K1c-T design §3.4). Every mode
// ratchets a Device once a session of it proved its token.
type GatewayTokenMode string

// Gateway token modes.
const (
	// GatewayTokenObserve refuses nothing for the token; Core counts the
	// sessions it would have refused.
	GatewayTokenObserve GatewayTokenMode = "observe"
	// GatewayTokenRatchet refuses a session without a token once its
	// Device is ratcheted. The default.
	GatewayTokenRatchet GatewayTokenMode = "ratchet"
	// GatewayTokenRequired refuses every gateway session without a token.
	GatewayTokenRequired GatewayTokenMode = "required"
)

// IsKnown reports one of the modes above.
func (mode GatewayTokenMode) IsKnown() bool {
	return mode == GatewayTokenObserve || mode == GatewayTokenRatchet || mode == GatewayTokenRequired
}

// GatewayTimestampResult is what committing a gateway's handshake
// timestamp did (schema 246). The zero value is invalid.
type GatewayTimestampResult string

// Results of committing a gateway's handshake timestamp.
const (
	// GatewayTimestampCommitted: recorded; a proven token ratcheted the
	// Device.
	GatewayTimestampCommitted GatewayTimestampResult = "committed"
	// GatewayTimestampNotCommitted: the keys are no longer the gateway's
	// current ones, or the timestamp is not newer.
	GatewayTimestampNotCommitted GatewayTimestampResult = "not_committed"
	// GatewayTimestampTokenRequired: the session proved no pod token and
	// its Device is ratcheted, or the mode is required; nothing was
	// written.
	GatewayTimestampTokenRequired GatewayTimestampResult = "token_required"
)

// IsKnown reports one of the results above.
func (result GatewayTimestampResult) IsKnown() bool {
	return result == GatewayTimestampCommitted || result == GatewayTimestampNotCommitted ||
		result == GatewayTimestampTokenRequired
}
