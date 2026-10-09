package main

import (
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/core/internal/adapter/httpapi"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/adapter/routeagent"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing/endpointpublication"
	"github.com/meshtransit/meshtransit/core/internal/platform/app"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
	"github.com/prometheus/client_golang/prometheus"
)

var errInvalidPrivateEndpointWorkerComposition = errors.New("invalid Private Endpoint worker composition")

func composePrivateEndpointWorker(
	settings config.PrivateEndpointWorkerConfig,
	pool *postgresadapter.Pool,
	telemetry *endpointpublication.Telemetry,
	logger *slog.Logger,
) (*endpointpublication.Worker, *routeagent.Client, prometheus.Collector, error) {
	if pool == nil || telemetry == nil || logger == nil {
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	ca, err := settings.AgentCAFile.Read()
	if err != nil {
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	certificate, err := settings.AgentCertificate.Read()
	if err != nil {
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	privateKey, err := settings.AgentPrivateKey.Read()
	if err != nil {
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	defer clear(privateKey)
	gateway, err := routeagent.New(routeagent.Options{
		Origin: settings.AgentOrigin, ServerCA: ca,
		ClientCertificate: certificate, ClientPrivateKey: privateKey,
		Timeout: settings.OperationTimeout,
	})
	if err != nil {
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	store, err := postgresadapter.NewPrivateEndpointPublicationStore(pool)
	if err != nil {
		gateway.CloseIdleConnections()
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	worker, err := endpointpublication.New(endpointpublication.Options{
		DeploymentID: settings.DeploymentID, ReconcilerID: settings.ReconcilerID,
		BatchSize: settings.BatchSize, PollInterval: settings.PollInterval,
		OperationTimeout: settings.OperationTimeout, InitialRetryDelay: settings.InitialRetryDelay,
		MaximumRetryDelay: settings.MaximumRetryDelay,
	}, store, gateway, telemetry, logger)
	if err != nil {
		gateway.CloseIdleConnections()
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	metrics, err := httpapi.NewPrivateEndpointWorkerMetricsCollector(telemetry)
	if err != nil {
		gateway.CloseIdleConnections()
		return nil, nil, nil, errInvalidPrivateEndpointWorkerComposition
	}
	return worker, gateway, metrics, nil
}

var _ app.Service = (*endpointpublication.Worker)(nil)
