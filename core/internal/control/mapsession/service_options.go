package mapsession

import "time"

const (
	minimumEndpointTTL     = time.Second
	maximumEndpointTTL     = 5 * time.Minute
	minimumEndpointTimeout = time.Millisecond
	maximumEndpointTimeout = 30 * time.Second
)

// ServiceOptions bounds transient endpoint coordination for map requests.
type ServiceOptions struct {
	EndpointTTL     time.Duration
	EndpointTimeout time.Duration
	// PeerLimit bounds the peers of one map (zero: DefaultPeerLimit).
	PeerLimit int
}

func (options ServiceOptions) peerLimit() int {
	if options.PeerLimit == 0 {
		return DefaultPeerLimit
	}
	return options.PeerLimit
}

func (options ServiceOptions) isValid() bool {
	return options.EndpointTTL >= minimumEndpointTTL &&
		options.EndpointTTL <= maximumEndpointTTL &&
		options.EndpointTimeout >= minimumEndpointTimeout &&
		options.EndpointTimeout <= maximumEndpointTimeout &&
		options.EndpointTimeout < options.EndpointTTL &&
		options.PeerLimit >= 0 && options.PeerLimit <= MaximumPeerCandidates
}
