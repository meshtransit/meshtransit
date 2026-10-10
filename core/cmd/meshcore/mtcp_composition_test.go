package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/platform/config"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

type mtcpStreamsFixture struct{}

func (mtcpStreamsFixture) Serve(context.Context, control.AuthenticatedMachine, mapsession.Request,
	mapsession.StreamSink) error {
	return nil
}

func (mtcpStreamsFixture) ReportEnforcement(context.Context, control.AuthenticatedMachine,
	mapsession.ClientEnforcement) error {
	return nil
}

type mtcpEndpointsFixture struct{}

func (mtcpEndpointsFixture) ObserveSessionEndpoints(context.Context, mapsession.Snapshot, node.EndpointSet, int,
	bool) error {
	return nil
}

func (mtcpEndpointsFixture) Open(context.Context, control.AuthenticatedMachine, mapsession.Request) (
	mapsession.Snapshot, error) {
	return mapsession.Snapshot{}, mapsession.ErrUnauthorized
}

type mtcpRegistrationsFixture struct{}

func (mtcpRegistrationsFixture) Register(context.Context, control.AuthenticatedMachine,
	control.RegistrationRequest) (registration.Result, error) {
	return registration.Result{}, errors.New("unused")
}

type mtcpLogoutFixture struct{}

func (mtcpLogoutFixture) Logout(context.Context, control.AuthenticatedMachine, node.Key) (control.DeviceLogout,
	error) {
	return control.DeviceLogout{}, control.ErrDeviceLogoutNotFound
}

func mtcpDependenciesFixture() mtcpDependencies {
	return mtcpDependencies{streams: mtcpStreamsFixture{}, sessions: mtcpEndpointsFixture{},
		registrations: mtcpRegistrationsFixture{}, logout: mtcpLogoutFixture{}, guard: mtcpGuardFixture{},
		logger: discardCompositionLogger()}
}

type mtcpGuardFixture struct{}

func (mtcpGuardFixture) AcceptTimestamp(context.Context, [32]byte, []byte, int64) (bool, error) {
	return true, nil
}

func TestComposeMTCP(t *testing.T) {
	t.Parallel()

	controlConfig, _ := controlConfigFixture(t)
	server, metrics, err := composeMTCP(controlConfig, mtcpDependenciesFixture())
	if err != nil || server != nil || metrics != nil {
		t.Fatalf("MTCP off: %v %v %v", server, metrics, err)
	}

	notAfter := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	controlConfig.MTCP = &config.ControlMTCPConfig{KeyNotAfter: notAfter}
	server, metrics, err = composeMTCP(controlConfig, mtcpDependenciesFixture())
	if err != nil || server == nil || len(metrics.Collectors()) == 0 {
		t.Fatalf("composeMTCP() = %v, %v", server, err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	// The key document answers with the TS2021 Noise key file's key.
	material, err := controlConfig.NoisePrivateKeyFile.Read()
	if err != nil {
		t.Fatal(err)
	}
	private, err := mtcpadapter.ParseControlKey(material)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, sharedmtcp.KeyPath, nil))
	public, _ := private.Public().MarshalText()
	if recorder.Code != http.StatusOK || !containsAll(recorder.Body.String(), string(public), notAfter.Format(time.RFC3339)) {
		t.Fatalf("key document %d %s", recorder.Code, recorder.Body.String())
	}

	missing := mtcpDependenciesFixture()
	missing.streams = nil
	if _, _, err := composeMTCP(controlConfig, missing); !errors.Is(err, errInvalidMTCPComposition) {
		t.Fatalf("missing streams: %v", err)
	}
	browserWithoutOrigin := mtcpDependenciesFixture()
	browserWithoutOrigin.browser = &browserControlServices{}
	if _, _, err := composeMTCP(controlConfig, browserWithoutOrigin); !errors.Is(err, errInvalidMTCPComposition) {
		t.Fatalf("browser without origin: %v", err)
	}
}

func TestMTCPCapabilities(t *testing.T) {
	t.Parallel()

	if slices.Contains(mtcpCapabilities(false), "device-alias.v1") ||
		!slices.Contains(mtcpCapabilities(true), "device-alias.v1") || !slices.Contains(mtcpCapabilities(false), "map.zstd") {
		t.Fatal("capabilities do not follow the deployment")
	}
}

func containsAll(text string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(text, part) {
			return false
		}
	}
	return true
}
