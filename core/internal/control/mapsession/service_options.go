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
	// EndpointAnnounceInterval spaces the endpoint changes a Device's peers
	// see (zero: DefaultEndpointAnnounceInterval).
	EndpointAnnounceInterval time.Duration
}

func (options ServiceOptions) endpointAnnounceInterval() time.Duration {
	if options.EndpointAnnounceInterval == 0 {
		return DefaultEndpointAnnounceInterval
	}
	return options.EndpointAnnounceInterval
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
		options.PeerLimit >= 0 && options.PeerLimit <= MaximumPeerCandidates &&
		(options.EndpointAnnounceInterval == 0 ||
			options.EndpointAnnounceInterval >= minimumEndpointAnnounceInterval &&
				options.EndpointAnnounceInterval <= maximumEndpointAnnounceInterval) &&
		// A deferred change must be announced before the endpoints expire.
		options.endpointAnnounceInterval() < options.EndpointTTL
}
