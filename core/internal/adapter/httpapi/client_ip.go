package httpapi

import "meshtransit.net/core/internal/platform/clientip"

type clientIPResolver = clientip.Resolver

var newClientIPResolver = clientip.NewResolver
