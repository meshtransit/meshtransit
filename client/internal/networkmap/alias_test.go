package networkmap

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func aliasTestSnapshot() (Snapshot, time.Time) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	self := Node{
		ID: 1, StableID: "consumer-1", Name: "consumer.example.test",
		PublicKey: "nodekey:" + strings.Repeat("11", 32), MachineAuthorized: true,
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.10.1/32"), netip.MustParsePrefix("fd00:1::1/128")},
		KeyExpiry: now.Add(time.Hour),
	}
	self.AllowedIPs = append([]netip.Prefix{}, self.Addresses...)
	peer := Node{
		ID: 2, StableID: "provider-1", Name: "provider.example.test",
		PublicKey: "nodekey:" + strings.Repeat("22", 32), MachineAuthorized: true,
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32"), netip.MustParsePrefix("fd00:2::1/128")},
		KeyExpiry: now.Add(time.Hour),
	}
	peer.AllowedIPs = append([]netip.Prefix{}, peer.Addresses...)
	peer.Alias = &AliasBinding{
		ContractID: "00000000-0000-4000-8000-000000000001",
		EndpointID: "00000000-0000-4000-8000-000000000002",
		Generation: 3, GrantRevision: 4, RecoveryEpoch: 1,
		SelfKey: self.PublicKey, PeerKey: peer.PublicKey, Role: AliasConsumer,
		SelfIPv4: netip.MustParseAddr("100.96.0.2"), SelfIPv6: netip.MustParseAddr("fd00:2::2"),
		ExpiresAt: now.Add(time.Minute),
		Services:  []AliasService{{Protocol: 6, PortFrom: 443, PortTo: 443}},
	}
	return Snapshot{Revision: 1, Self: self, Peers: []Node{peer}}, now
}

func TestAliasValidateAndClone(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasTestSnapshot()
	validated, err := ValidateAndClone(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Peers[0].Alias.Services[0].PortTo = 65535
	snapshot.Peers[0].Alias.SelfIPv4 = netip.MustParseAddr("192.0.2.1")
	if validated.Peers[0].Alias.Services[0].PortTo != 443 ||
		validated.Peers[0].Alias.SelfIPv4 != netip.MustParseAddr("100.96.0.2") {
		t.Fatal("caller changed validated alias authority")
	}
}

func TestAliasRejectsUnsafeAuthority(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*Snapshot)
	}{
		{"self binding", func(s *Snapshot) { s.Self.Alias = s.Peers[0].Alias }},
		{"wrong self key", func(s *Snapshot) { s.Peers[0].Alias.SelfKey = s.Peers[0].PublicKey }},
		{"wrong peer key", func(s *Snapshot) { s.Peers[0].Alias.PeerKey = s.Self.PublicKey }},
		{"unknown role", func(s *Snapshot) { s.Peers[0].Alias.Role = "" }},
		{"zero generation", func(s *Snapshot) { s.Peers[0].Alias.Generation = 0 }},
		{"zero revision", func(s *Snapshot) { s.Peers[0].Alias.GrantRevision = 0 }},
		{"zero recovery", func(s *Snapshot) { s.Peers[0].Alias.RecoveryEpoch = 0 }},
		{"malformed contract", func(s *Snapshot) { s.Peers[0].Alias.ContractID = "foreign" }},
		{"zero endpoint", func(s *Snapshot) { s.Peers[0].Alias.EndpointID = "00000000-0000-0000-0000-000000000000" }},
		{"exclusive expiry", func(s *Snapshot) { s.Peers[0].Alias.ExpiresAt = s.Peers[0].Alias.ExpiresAt.Add(-time.Minute) }},
		{"unbounded peer key", func(s *Snapshot) { s.Peers[0].KeyExpiry = time.Time{} }},
		{"unbounded self key", func(s *Snapshot) { s.Self.KeyExpiry = time.Time{} }},
		{"past peer deadline", func(s *Snapshot) { s.Peers[0].Alias.ExpiresAt = s.Peers[0].KeyExpiry.Add(time.Second) }},
		{"expired peer", func(s *Snapshot) { s.Peers[0].Expired = true }},
		{"unauthorized peer", func(s *Snapshot) { s.Peers[0].MachineAuthorized = false }},
		{"missing ipv6 alias", func(s *Snapshot) { s.Peers[0].Alias.SelfIPv6 = netip.Addr{} }},
		{"wrong alias family", func(s *Snapshot) { s.Peers[0].Alias.SelfIPv4 = s.Peers[0].Alias.SelfIPv6 }},
		{"mapped alias", func(s *Snapshot) { s.Peers[0].Alias.SelfIPv6 = netip.MustParseAddr("::ffff:192.0.2.1") }},
		{"canonical alias collision", func(s *Snapshot) { s.Peers[0].Alias.SelfIPv4 = s.Self.Addresses[0].Addr() }},
		{"peer alias collision", func(s *Snapshot) { s.Peers[0].Alias.SelfIPv4 = s.Peers[0].Addresses[0].Addr() }},
		{"subnet route", func(s *Snapshot) {
			s.Peers[0].AllowedIPs = append(s.Peers[0].AllowedIPs, netip.MustParsePrefix("10.0.0.0/8"))
		}},
		{"duplicate family", func(s *Snapshot) {
			s.Peers[0].Addresses[1] = netip.MustParsePrefix("100.96.0.10/32")
			s.Peers[0].AllowedIPs[1] = s.Peers[0].Addresses[1]
		}},
		{"no services", func(s *Snapshot) { s.Peers[0].Alias.Services = nil }},
		{"wildcard protocol", func(s *Snapshot) { s.Peers[0].Alias.Services[0].Protocol = 0 }},
		{"zero tcp port", func(s *Snapshot) { s.Peers[0].Alias.Services[0].PortFrom = 0 }},
		{"reversed range", func(s *Snapshot) { s.Peers[0].Alias.Services[0].PortFrom = 444 }},
		{"icmp ports", func(s *Snapshot) { s.Peers[0].Alias.Services[0].Protocol = 1 }},
		{"overlapping ranges", func(s *Snapshot) {
			s.Peers[0].Alias.Services = append(s.Peers[0].Alias.Services, s.Peers[0].Alias.Services[0])
		}},
		{"too many services", func(s *Snapshot) { s.Peers[0].Alias.Services = make([]AliasService, 65) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot, now := aliasTestSnapshot()
			test.edit(&snapshot)
			if _, err := ValidateAndClone(snapshot, now); err == nil {
				t.Fatal("unsafe alias accepted")
			}
		})
	}
}

func TestAliasIPv4AndIPv6OnlyProfiles(t *testing.T) {
	t.Parallel()
	for _, ipv4 := range []bool{true, false} {
		t.Run(map[bool]string{true: "ipv4", false: "ipv6"}[ipv4], func(t *testing.T) {
			t.Parallel()
			snapshot, now := aliasTestSnapshot()
			index := 0
			snapshot.Peers[0].Alias.SelfIPv6 = netip.Addr{}
			if !ipv4 {
				index = 1
				snapshot.Peers[0].Alias.SelfIPv4 = netip.Addr{}
				snapshot.Peers[0].Alias.SelfIPv6 = netip.MustParseAddr("fd00:2::2")
			}
			snapshot.Peers[0].Addresses = snapshot.Peers[0].Addresses[index : index+1]
			snapshot.Peers[0].AllowedIPs = snapshot.Peers[0].AllowedIPs[index : index+1]
			if _, err := ValidateAndClone(snapshot, now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAliasGenerationAndGrantFences(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*AliasBinding)
	}{
		{"generation regression", func(b *AliasBinding) { b.Generation-- }},
		{"revision regression", func(b *AliasBinding) { b.GrantRevision-- }},
		{"role reversal", func(b *AliasBinding) { b.Role = AliasProvider; b.GrantRevision++ }},
		{"recovery replacement", func(b *AliasBinding) { b.RecoveryEpoch++; b.Generation++ }},
		{"contract replacement", func(b *AliasBinding) { b.ContractID = "00000000-0000-4000-8000-000000000003" }},
		{"alias moved within generation", func(b *AliasBinding) { b.SelfIPv4 = netip.MustParseAddr("100.96.0.9"); b.GrantRevision++ }},
		{"key moved within generation", func(b *AliasBinding) { b.PeerKey = "replacement"; b.GrantRevision++ }},
		{"same revision widened", func(b *AliasBinding) { b.Services[0].PortTo++ }},
		{"same revision renewed", func(b *AliasBinding) { b.ExpiresAt = b.ExpiresAt.Add(time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot, _ := aliasTestSnapshot()
			previous := snapshot.Peers[0].Alias
			next := cloneAlias(previous)
			test.edit(next)
			if err := ValidateAliasAdvance(previous, next); err == nil {
				t.Fatal("alias authority mutation accepted")
			}
		})
	}
	snapshot, _ := aliasTestSnapshot()
	next := cloneAlias(snapshot.Peers[0].Alias)
	next.GrantRevision++
	next.Services[0].PortTo++
	if err := ValidateAliasAdvance(snapshot.Peers[0].Alias, next); err != nil {
		t.Fatal(err)
	}
}

func TestAliasSharedProviderAliasRequiresSameEndpoint(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasTestSnapshot()
	snapshot.Peers[0].Alias.Role = AliasProvider
	second := cloneNode(snapshot.Peers[0])
	second.ID = 3
	second.PublicKey = "nodekey:" + strings.Repeat("33", 32)
	second.Alias.PeerKey = second.PublicKey
	second.Addresses = []netip.Prefix{netip.MustParsePrefix("100.96.0.3/32"), netip.MustParsePrefix("fd00:2::3/128")}
	second.AllowedIPs = append([]netip.Prefix{}, second.Addresses...)
	snapshot.Peers = append(snapshot.Peers, second)
	if _, err := ValidateAndClone(snapshot, now); err != nil {
		t.Fatal(err)
	}
	snapshot.Peers[1].Alias.Generation++
	if _, err := ValidateAndClone(snapshot, now); err == nil {
		t.Fatal("local alias joined unrelated endpoint generations")
	}
}

func TestAliasPeerLimitRejectsTheWholeMap(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasTestSnapshot()
	template := snapshot.Peers[0]
	snapshot.Peers = make([]Node, 0, maxAliasPeers+1)
	for index := range maxAliasPeers + 1 {
		peer := cloneNode(template)
		peer.ID = uint64(index + 2)
		peer.PublicKey = fmt.Sprintf("nodekey:%064x", index+100)
		peer.Alias.PeerKey = peer.PublicKey
		peer.Alias.SelfIPv6 = netip.Addr{}
		peer.Addresses = []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("100.96.%d.%d/32", index/200+1, index%200+1))}
		peer.AllowedIPs = append([]netip.Prefix{}, peer.Addresses...)
		peer.Alias.SelfIPv4 = netip.MustParseAddr(fmt.Sprintf("100.97.%d.%d", index/200+1, index%200+1))
		snapshot.Peers = append(snapshot.Peers, peer)
	}
	full := snapshot.Peers
	snapshot.Peers = full[:maxAliasPeers]
	if _, err := ValidateAndClone(snapshot, now); err != nil {
		t.Fatal(err)
	}
	snapshot.Peers = full
	if validated, err := ValidateAndClone(snapshot, now); err == nil || validated.Revision != 0 || len(validated.Peers) != 0 {
		t.Fatal("overflow did not reject the whole map")
	}
}
