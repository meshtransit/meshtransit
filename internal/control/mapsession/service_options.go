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
}

func (options ServiceOptions) isValid() bool {
	return options.EndpointTTL >= minimumEndpointTTL &&
		options.EndpointTTL <= maximumEndpointTTL &&
		options.EndpointTimeout >= minimumEndpointTimeout &&
		options.EndpointTimeout <= maximumEndpointTimeout &&
		options.EndpointTimeout < options.EndpointTTL
}
