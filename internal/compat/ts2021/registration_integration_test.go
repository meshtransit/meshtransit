//go:build integration

package ts2021

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"tailscale.com/types/key"
)

const integrationEnrollmentCredentialFileEnv = "MESHTRANSIT_INTEGRATION_ENROLLMENT_CREDENTIAL_FILE"

func TestClient_RegisterAndReceiveInitialMap(t *testing.T) {
	t.Parallel()

	controlURL, expectedFingerprint := integrationControlConfig(t)
	credential := readIntegrationEnrollmentCredential(t)
	client := New()

	trust, err := client.BootstrapTrust(t.Context(), controlURL, expectedFingerprint)
	if err != nil {
		t.Fatalf("BootstrapTrust() error = %v", err)
	}
	defer clearIntegrationKeyMaterial(&trust.Material)

	registration, err := client.Register(t.Context(), controlURL, trust.Material, RegisterOptions{
		Hostname:          "qualification-node",
		Version:           "integration",
		PinnedFingerprint: expectedFingerprint,
		AuthKey:           credential,
	})
	credential = ""
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if registration.State != RegistrationStateAuthorized ||
		!registration.MachineAuthorized || registration.AuthURL != "" {
		t.Fatal("Register() did not return an authorized node")
	}

	candidates, err := pathdiscovery.NewSet(nil)
	if err != nil {
		t.Fatalf("pathdiscovery.NewSet() error = %v", err)
	}
	discoveryKey := key.NewDisco()
	streamContext, cancelStream := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelStream()
	var initial networkmap.Snapshot
	streamErr := client.StreamNetmap(
		streamContext,
		controlURL,
		trust.Material,
		NetmapOptions{
			Hostname:           "qualification-node",
			Version:            "integration",
			PinnedFingerprint:  expectedFingerprint,
			PeerProbePublicKey: discoveryKey.Public().String(),
			Candidates:         candidates,
		},
		func(_ context.Context, snapshot networkmap.Snapshot) error {
			initial = snapshot
			cancelStream()

			return nil
		},
	)
	if !errors.Is(streamErr, context.Canceled) {
		t.Fatalf("StreamNetmap() error = %v, want cancellation after initial map", streamErr)
	}
	assertInitialIntegrationMap(t, initial)
}

func readIntegrationEnrollmentCredential(t *testing.T) string {
	t.Helper()

	path := os.Getenv(integrationEnrollmentCredentialFileEnv)
	if path == "" {
		t.Skip("live enrollment credential file is not configured")
	}
	information, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(enrollment credential) error = %v", err)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 ||
		information.Size() < 1 || information.Size() > maxCredentialBytes+1 {
		t.Fatal("enrollment credential must be a bounded owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(enrollment credential) error = %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("Close(enrollment credential) error = %v", err)
		}
	}()
	encoded, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+2))
	if err != nil {
		t.Fatalf("Read(enrollment credential) error = %v", err)
	}
	defer clear(encoded)
	credential := strings.TrimSuffix(string(encoded), "\n")
	if credential == "" || len(credential) > maxCredentialBytes ||
		credential+"\n" != string(encoded) {
		t.Fatal("enrollment credential file has invalid framing")
	}

	return credential
}

func assertInitialIntegrationMap(t *testing.T, snapshot networkmap.Snapshot) {
	t.Helper()

	if snapshot.Revision == 0 || strings.TrimSpace(snapshot.NetworkName) == "" {
		t.Fatalf("initial map identity = (%d, %q), want authoritative network", snapshot.Revision, snapshot.NetworkName)
	}
	if snapshot.Self.ID == 0 || snapshot.Self.PublicKey == "" ||
		!snapshot.Self.MachineAuthorized || snapshot.Self.Expired ||
		len(snapshot.Self.Addresses) == 0 {
		t.Fatal("initial map does not contain an authorized address-bearing self node")
	}
	usableRelay := false
	for regionID, region := range snapshot.Relays {
		if regionID <= 0 || region.ID != regionID || strings.TrimSpace(region.Code) == "" ||
			strings.TrimSpace(region.Name) == "" || len(region.Nodes) == 0 {
			t.Fatal("initial map contains an incomplete relay region")
		}
		for _, node := range region.Nodes {
			if !node.STUNOnly && node.RelayPort > 0 {
				usableRelay = true
			}
		}
	}
	if !usableRelay {
		t.Fatal("initial map has no usable encrypted relay")
	}
}

func clearIntegrationKeyMaterial(material *KeyMaterial) {
	if material == nil {
		return
	}
	clear(material.MachinePrivateKey)
	clear(material.NodePrivateKey)
	clear(material.ControlPublicKey)
	*material = KeyMaterial{}
}
