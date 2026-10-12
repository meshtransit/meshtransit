//go:build windows

package main

import (
	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/localapi"
	"meshtransit.net/client/internal/peercred"
)

// localAPIOptions authorizes callers by their access token: LocalSystem,
// elevated Administrators and members of the MeshTransit Users group.
func localAPIOptions(config.Config) (localapi.Options, error) {
	operators, err := peercred.OperatorsSID()
	if err != nil {
		return localapi.Options{}, err
	}

	return localapi.Options{OperatorsSID: operators}, nil
}
