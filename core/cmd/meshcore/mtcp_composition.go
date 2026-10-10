package main

import (
	"errors"
	"log/slog"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidMTCPComposition = errors.New("invalid MTCP composition")

var (
	_ mtcpadapter.MapStreams       = (*mapsession.StreamService)(nil)
	_ mtcpadapter.EndpointObserver = (*mapsession.Service)(nil)
)

// mtcpCapabilities lists what this Core serves (mtcp-v1 §13). Device alias
// grants are offered only where the deployment projects them.
func mtcpCapabilities(deviceAliases bool) []string {
	capabilities := []string{"map.zstd", "disco.v2", "relay.mtrp1", "dns.split", "stats.path1", "nat.report1"}
	if deviceAliases {
		capabilities = append(capabilities, "device-alias.v1")
	}
	return capabilities
}

// composeMTCP builds the MTCP v1 server that shares the control listener
// and control key with TS2021. It returns nil when MTCP is off.
func composeMTCP(
	controlConfig config.ControlConfig,
	streams mtcpadapter.MapStreams,
	endpoints mtcpadapter.EndpointObserver,
	guard mtcpadapter.TimestampGuard,
	logger *slog.Logger,
) (*mtcpadapter.Server, *mtcpadapter.Metrics, error) {
	if controlConfig.MTCP == nil {
		return nil, nil, nil
	}
	if streams == nil || endpoints == nil || guard == nil || logger == nil {
		return nil, nil, errInvalidMTCPComposition
	}
	material, err := controlConfig.NoisePrivateKeyFile.Read()
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	private, err := mtcpadapter.ParseControlKey(material)
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	keys := []mtcpadapter.ControlKey{{Private: private, NotAfter: controlConfig.MTCP.KeyNotAfter}}
	clients, err := clientip.NewResolver(controlConfig.MTCP.TrustedProxyPrefixes())
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	application, err := mtcpadapter.NewApplication(streams, endpoints, keys, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	metrics := mtcpadapter.NewMetrics()
	server, err := mtcpadapter.NewServer(mtcpadapter.Options{
		Keys:         keys,
		ClientIPs:    clients,
		Handler:      application,
		Guard:        guard,
		Capabilities: mtcpCapabilities(controlConfig.Map.EnableDeviceAliases),
		Logger:       logger,
		Metrics:      metrics,
		// MTCP connections count against the listener's connection bound.
		MaxSessions: controlConfig.MaxSessions,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	return server, metrics, nil
}
