//go:build relaye2e

package interchange

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// This test drives a real meshrelay process (not the fake relay) with meshd's
// relay client and Core-format tickets. It needs:
//
//	MESHTRANSIT_RELAY_E2E_UDP=127.0.0.1:34790   the relay's MTRP UDP address
//	MESHTRANSIT_RELAY_E2E_KEY=mtrelay:...        the relay's public key
//	MESHTRANSIT_RELAY_E2E_SEED=<64 hex>          seed of the signing key the
//	                                             relay trusts (--trusted-signing-keys)
//	MESHTRANSIT_RELAY_E2E_OLD=1                  the relay predates MTT2
//
// go test -tags relaye2e -run TestRealRelay ./internal/interchange

type e2eRelay struct {
	node   relay.Node
	signer key.SigningPrivate
	old    bool
}

func realRelay(t *testing.T) e2eRelay {
	t.Helper()
	udp, relayKey, seed := os.Getenv("MESHTRANSIT_RELAY_E2E_UDP"), os.Getenv("MESHTRANSIT_RELAY_E2E_KEY"),
		os.Getenv("MESHTRANSIT_RELAY_E2E_SEED")
	if udp == "" || relayKey == "" || seed == "" {
		t.Skip("set MESHTRANSIT_RELAY_E2E_UDP, _KEY and _SEED for a running meshrelay")
	}
	public, err := key.ParseRelayPublic(relayKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := key.SigningPrivateFromSeed(raw)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, ok := cutLast(udp, ":")
	port, err := strconv.ParseUint(portText, 10, 16)
	if !ok || err != nil {
		t.Fatalf("bad MESHTRANSIT_RELAY_E2E_UDP %q", udp)
	}
	return e2eRelay{
		node:   relay.Node{Name: "e2e", HostName: host, IPv4: host, UDPPort: uint16(port), RelayKey: public},
		signer: signer, old: os.Getenv("MESHTRANSIT_RELAY_E2E_OLD") != "",
	}
}

func cutLast(s, sep string) (string, string, bool) {
	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return "", "", false
}

func e2eZone(kind mtrp.ZoneKind, n uint32) mtrp.Zone {
	z := mtrp.Zone{Kind: kind}
	binary.BigEndian.PutUint32(z.ID[:4], n)
	z.ID[15] = 0xe2
	return z
}

// sign issues a ticket the way Core does: MTT1 up to MaxZones zones, else
// MTT2 with its zone list and an MTT1 fallback naming the inline zones.
func (r e2eRelay) sign(t *testing.T, node key.NodePublic, disco key.DiscoPublic, zones []mtrp.Zone) (ticket, list, fallback []byte) {
	t.Helper()
	now := time.Now()
	tk := mtrp.Ticket{
		IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(10 * time.Minute).UnixMilli(),
		Node: node, Disco: disco, Deployment: [16]byte{0x01, 0x99, 6: 0x70, 8: 0x80}, Zones: zones,
	}
	if _, err := rand.Read(tk.ID[:]); err != nil {
		t.Fatal(err)
	}
	if len(zones) <= mtrp.MaxZones {
		ticket, err := tk.Sign(r.signer)
		if err != nil {
			t.Fatal(err)
		}
		return ticket, nil, nil
	}
	ticket, list, err := tk.SignZones(r.signer)
	if err != nil {
		t.Fatal(err)
	}
	backup := tk
	backup.ID[0] ^= 0x80
	backup.Zones = slices.SortedFunc(slices.Values(zones), mtrp.CompareZones)[:mtrp.MaxZones]
	if fallback, err = backup.Sign(r.signer); err != nil {
		t.Fatal(err)
	}
	return ticket, list, fallback
}

func (r e2eRelay) dial(t *testing.T, node key.NodePublic, zones []mtrp.Zone) (*Client, *zoneCreds) {
	t.Helper()
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	ticket, list, fallback := r.sign(t, node, disco.Public(), zones)
	creds := &zoneCreds{testCreds: &testCreds{disco: disco, ticket: ticket, ok: true}, zones: list, fallback: fallback}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	c, err := NewDialer(creds).Dial(ctx, relay.Key{}, relay.Region{ID: 1, Nodes: []relay.Node{r.node}})
	if err != nil {
		t.Fatalf("dial the real relay: %v", err)
	}
	client, ok := c.(*Client)
	if !ok {
		t.Fatalf("Dial returned %T", c)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, creds
}

// reaches reports whether from's packets reach to within the deadline; it
// keeps sending, as WireGuard would, while the relay refuses the route.
func reaches(t *testing.T, from, to *Client, toNode key.NodePublic, within time.Duration) bool {
	t.Helper()
	got := make(chan bool, 1)
	go func() {
		for {
			event, err := to.Receive()
			if err != nil {
				got <- false
				return
			}
			if event.Kind == relay.ReceivePacket && string(event.Data) == "mtt2" {
				got <- true
				return
			}
		}
	}()
	deadline := time.After(within)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		_ = from.Send(relay.Key(toNode), []byte("mtt2"))
		select {
		case ok := <-got:
			return ok
		case <-deadline:
			return false
		case <-tick.C:
		}
	}
}

// TestRealRelayRoutesEveryShare: a providing node in its Network and 40
// Trust Contracts reaches, through a real relay, a consumer whose only
// shared zone is the 40th contract (beyond the 31 an MTT1 ticket names). An
// old relay drops the MTT2 ticket; the provider then connects with its MTT1
// fallback and reaches consumers of its oldest contracts only.
func TestRealRelayRoutesEveryShare(t *testing.T) {
	r := realRelay(t)
	providerNode, lastNode, firstNode := key.NodePublic{0xe1}, key.NodePublic{0xe2}, key.NodePublic{0xe3}
	zones := []mtrp.Zone{e2eZone(mtrp.ZoneNetwork, 1)}
	for i := range uint32(40) {
		zones = append(zones, e2eZone(mtrp.ZoneTrustContract, 100+i))
	}
	sorted := slices.SortedFunc(slices.Values(zones), mtrp.CompareZones)
	last, first := sorted[len(sorted)-1], sorted[1]

	provider, creds := r.dial(t, providerNode, zones)
	consumerLast, _ := r.dial(t, lastNode, []mtrp.Zone{e2eZone(mtrp.ZoneNetwork, 2), last})
	consumerFirst, _ := r.dial(t, firstNode, []mtrp.Zone{e2eZone(mtrp.ZoneNetwork, 3), first})

	provider.mu.Lock()
	onFallback := slices.Equal(provider.ticket, creds.fallback)
	provider.mu.Unlock()
	if !reaches(t, consumerFirst, provider, providerNode, 10*time.Second) {
		t.Fatal("a consumer of the oldest contract cannot reach the provider")
	}
	reachedLast := reaches(t, consumerLast, provider, providerNode, 10*time.Second)
	t.Logf("old relay %v, provider on MTT1 fallback %v, 40th contract reaches %v", r.old, onFallback, reachedLast)
	switch {
	case r.old && (!onFallback || reachedLast):
		t.Fatal("an old relay must take the fallback and route only its 31 oldest contracts")
	case !r.old && (onFallback || !reachedLast):
		t.Fatal("an MTT2 relay must route the 40th contract")
	}
}
