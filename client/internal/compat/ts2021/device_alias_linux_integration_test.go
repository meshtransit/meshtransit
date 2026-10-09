//go:build integration && linux

package ts2021

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/dataplane"
	"github.com/meshtransit/meshtransit/client/internal/netadmin"
	"github.com/meshtransit/meshtransit/client/internal/networkmap"
	"github.com/meshtransit/meshtransit/client/internal/socket"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// aliasQualification is a fixture control channel, never a production control endpoint.
// A privileged operator supplies public peer metadata and a separate ephemeral private key.
type aliasQualification struct {
	Role          string    `json:"role"`
	PeerKey       string    `json:"peer_key"`
	PeerEndpoint  string    `json:"peer_endpoint"`
	ExpiresAt     time.Time `json:"expires_at"`
	GrantRevision uint64    `json:"grant_revision"`
	TCP           bool      `json:"tcp"`
	UDP           bool      `json:"udp"`
	ICMP          bool      `json:"icmp"`
	Peer          bool      `json:"peer"`
	Stop          bool      `json:"stop"`
}

// TestDeviceAliasEncryptedPeer runs the real decoder, helper, kernel TUN and
// userspace encrypted engine against a second qualification process. It proves
// the packet path only; fixture authority is not an SSO or Core runtime result.
func TestDeviceAliasEncryptedPeer(t *testing.T) {
	controlPath := os.Getenv("MESHD_ALIAS_QUAL_CONTROL")
	privatePath := os.Getenv("MESHD_ALIAS_QUAL_PRIVATE")
	if controlPath == "" || privatePath == "" {
		t.Skip("requires explicit disposable peer qualification files")
	}
	if os.Geteuid() != 0 {
		t.Fatal("qualification helper requires root")
	}
	if !filepath.IsAbs(controlPath) || !filepath.IsAbs(privatePath) {
		t.Fatal("qualification paths must be absolute")
	}
	material, err := readQualificationFile(privatePath, 32)
	if err != nil || len(material) != 32 {
		t.Fatal("invalid ephemeral private key file")
	}
	defer clear(material)
	private, err := ecdh.X25519().NewPrivateKey(material)
	if err != nil {
		t.Fatal("invalid ephemeral private key")
	}
	var nodePrivate dataplane.NodePrivateKey
	copy(nodePrivate[:], material)
	defer clear(nodePrivate[:])
	selfKey := "nodekey:" + hex.EncodeToString(private.PublicKey().Bytes())
	helper, err := netadmin.NewServer(netadmin.ServerOptions{
		AllowedUID: 0, InterfaceName: "meshqual0", MTU: 1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd00:10::/64"), netip.MustParsePrefix("fd00:feed::/64"), netip.MustParsePrefix("fd00:feed:1::/64")},
		Logger:          slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := socket.ListenPacket(filepath.Join(t.TempDir(), "alias-helper.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	done := make(chan error, 1)
	go func() { done <- helper.Serve(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("helper shutdown: %v", err)
		}
	}()
	client, err := netadmin.NewClient(listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := dataplane.NewWireGuard(client, 42642)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("engine shutdown: %v", err)
		}
	}()
	accumulator := newMapAccumulator()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var previous []byte
	createdAt := time.Now().UTC().Add(-time.Hour)
	selfExpiresAt := time.Now().UTC().Add(15 * time.Minute)
	for {
		body, err := readQualificationFile(controlPath, 4096)
		if err != nil || len(body) > 4096 {
			t.Fatal("invalid fixture control file")
		}
		if string(body) != string(previous) {
			var configuration aliasQualification
			if err := json.Unmarshal(body, &configuration); err != nil {
				t.Fatal("invalid qualification control")
			}
			if configuration.Stop {
				return
			}
			response := qualificationAliasFrame(t, configuration, selfKey, createdAt, selfExpiresAt)
			snapshot, changed, err := accumulator.apply(response, time.Now().UTC())
			if err != nil || !changed {
				t.Fatalf("qualification decoder changed=%t error=%v", changed, err)
			}
			state, err := engine.Apply(ctx, snapshot, nodePrivate)
			if err != nil {
				t.Fatalf("qualification engine: %v", err)
			}
			t.Logf("alias-applied role=%s grant_revision=%d map_revision=%d peers=%d state=%s", configuration.Role, configuration.GrantRevision, snapshot.Revision, len(snapshot.Peers), state)
			previous = append(previous[:0], body...)
		}
		select {
		case <-ctx.Done():
			t.Fatal("qualification timed out")
		case <-ticker.C:
		}
	}
}

func qualificationAliasFrame(t *testing.T, configuration aliasQualification, selfKey string, createdAt, selfExpiresAt time.Time) tailcfg.MapResponse {
	t.Helper()
	if configuration.Role != "provider" && configuration.Role != "consumer" {
		t.Fatal("invalid qualification role")
	}
	body, err := coreDeviceAliasFixtures.ReadFile("testdata/core-device-alias-v1/" + configuration.Role + "-tcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var response tailcfg.MapResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if err := response.Node.Key.UnmarshalText([]byte(selfKey)); err != nil {
		t.Fatal(err)
	}
	response.Node.Created = createdAt
	response.Node.KeyExpiry = selfExpiresAt
	response.DERPMap = nil
	response.PacketFilter = []tailcfg.FilterRule{}
	if !configuration.Peer {
		response.Peers = []*tailcfg.Node{}
		return response
	}
	peer := response.Peers[0]
	if err := peer.Key.UnmarshalText([]byte(configuration.PeerKey)); err != nil {
		t.Fatal(err)
	}
	endpoint, err := netip.ParseAddrPort(configuration.PeerEndpoint)
	if err != nil || endpoint.Port() != 42642 {
		t.Fatal("invalid qualification endpoint")
	}
	peer.Endpoints = []netip.AddrPort{endpoint}
	peer.Created = response.Node.Created
	peer.KeyExpiry = configuration.ExpiresAt
	var grant aliasDocument
	if err := json.Unmarshal([]byte(peer.CapMap[deviceAliasCapability][0]), &grant); err != nil {
		t.Fatal(err)
	}
	grant.SelfKey = selfKey
	grant.PeerKey = configuration.PeerKey
	grant.ExpiresAt = configuration.ExpiresAt
	grant.GrantRevision = configuration.GrantRevision
	grant.Services = []aliasService{}
	protocols := []struct {
		name    string
		enabled bool
	}{{"icmp", configuration.ICMP}, {"tcp", configuration.TCP}, {"udp", configuration.UDP}}
	for _, protocol := range protocols {
		if !protocol.enabled {
			continue
		}
		frame, err := coreDeviceAliasFixtures.ReadFile("testdata/core-device-alias-v1/" + configuration.Role + "-" + protocol.name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var encoded tailcfg.MapResponse
		if err := json.Unmarshal(frame, &encoded); err != nil {
			t.Fatal(err)
		}
		var serviceGrant aliasDocument
		if err := json.Unmarshal([]byte(encoded.Peers[0].CapMap[deviceAliasCapability][0]), &serviceGrant); err != nil {
			t.Fatal(err)
		}
		grant.Services = append(grant.Services, serviceGrant.Services...)
		response.PacketFilter = append(response.PacketFilter, encoded.PacketFilter...)
	}
	// Canonical protocol order is required by the product validator.
	slices.SortFunc(grant.Services, func(left, right aliasService) int {
		return int(left.Protocol) - int(right.Protocol)
	})
	document, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	peer.CapMap = tailcfg.NodeCapMap{deviceAliasCapability: {tailcfg.RawMessage(document)}}
	var expected key.NodePublic
	if err := expected.UnmarshalText([]byte(selfKey)); err != nil || expected != response.Node.Key {
		t.Fatal("qualification self key mismatch")
	}
	if grant.Role != networkmap.AliasRole(configuration.Role) {
		t.Fatal("qualification role mismatch")
	}
	return response
}

// readQualificationFile bounds allocation and confines operator-supplied paths
// to an opened directory. Metadata checks apply to the opened file, not a prior
// path lookup that could race replacement.
func readQualificationFile(path string, maximum int64) (body []byte, err error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	information, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 ||
		information.Size() < 1 || information.Size() > maximum {
		return nil, errors.New("qualification file must be a bounded owner-only regular file")
	}
	body, err = io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		clear(body)
		return nil, errors.New("qualification file exceeded its bound")
	}
	return body, nil
}
