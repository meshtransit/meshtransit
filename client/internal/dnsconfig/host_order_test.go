package dnsconfig

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/networkmap"
)

func replicaAddresses(count int) []netip.Addr {
	addresses := make([]netip.Addr, count)
	for index := range addresses {
		addresses[index] = netip.AddrFrom4([4]byte{100, 64, 1, byte(10 + index)})
	}
	return addresses
}

func firstFor(self string, addresses []netip.Addr) netip.Addr {
	ordered := slices.Clone(addresses)
	orderHostAddresses(ordered, self)
	return ordered[0]
}

// Nodes spread evenly over a cluster's replicas: each node's first address
// is its own (K1f, Q191).
func TestOrderHostAddressesSpreadsNodes(t *testing.T) {
	t.Parallel()
	const nodes = 3000
	for _, replicas := range []int{2, 3, 5} {
		addresses := replicaAddresses(replicas)
		first := map[netip.Addr]int{}
		for index := range nodes {
			first[firstFor(fmt.Sprintf("01890f00-0000-7000-8000-%012d", index), addresses)]++
		}
		even := nodes / replicas
		for _, address := range addresses {
			if count := first[address]; count < even*85/100 || count > even*115/100 {
				t.Errorf("%d replicas: %s first for %d nodes, want about %d", replicas, address, count, even)
			}
		}
	}
}

// A replica joining moves only the nodes that rank it first, and one
// leaving moves only those that had it first: the rest keep their replica
// and their open sessions.
func TestOrderHostAddressesIsStableAsReplicasChange(t *testing.T) {
	t.Parallel()
	before, after := replicaAddresses(3), replicaAddresses(4)
	joined := after[3]
	moved := 0
	for index := range 2000 {
		self := fmt.Sprintf("node-%d", index)
		was, now := firstFor(self, before), firstFor(self, after)
		if was != now {
			moved++
			if now != joined {
				t.Fatalf("%s moved from %s to %s, not to the new replica", self, was, now)
			}
		}
		if left := slices.DeleteFunc(slices.Clone(before), func(address netip.Addr) bool {
			return address == before[0]
		}); was != before[0] && firstFor(self, left) != was {
			t.Fatalf("%s moved when a replica it did not use left", self)
		}
	}
	if moved < 2000*15/100 || moved > 2000*35/100 {
		t.Errorf("%d of 2000 nodes moved to the fourth replica, want about a quarter", moved)
	}
}

// The order is the node's own and the same every time; every address stays;
// without the node's ID it is ascending, as before.
func TestOrderHostAddressesIsDeterministic(t *testing.T) {
	t.Parallel()
	addresses := append(replicaAddresses(4), netip.MustParseAddr("fd00::1:10"), netip.MustParseAddr("fd00::1:11"))
	once, again := slices.Clone(addresses), slices.Clone(addresses)
	slices.Reverse(again)
	orderHostAddresses(once, "01890f00-0000-7000-8000-000000000001")
	orderHostAddresses(again, "01890f00-0000-7000-8000-000000000001")
	if !slices.Equal(once, again) {
		t.Fatalf("order depends on the input order: %v, %v", once, again)
	}
	sorted := slices.Clone(once)
	slices.SortFunc(sorted, netip.Addr.Compare)
	if !slices.Equal(sorted, addresses) {
		t.Fatalf("addresses changed: %v", once)
	}
	anonymous := slices.Clone(addresses)
	slices.Reverse(anonymous)
	orderHostAddresses(anonymous, "")
	if !slices.Equal(anonymous, addresses) {
		t.Fatalf("without an ID: %v, want ascending", anonymous)
	}
}

// The plan answers a cluster's name with its replicas in the node's own
// order.
func TestCompileOrdersAClusterNameForTheNode(t *testing.T) {
	t.Parallel()
	replicas := replicaAddresses(3)
	firsts := map[netip.Addr]bool{}
	for index := range 40 {
		snapshot := dnsSnapshot()
		snapshot.Self.StableID = fmt.Sprintf("01890f00-0000-7000-8000-%012d", index)
		for _, address := range replicas {
			snapshot.DNS.Records = append(snapshot.DNS.Records, networkmap.DNSRecord{
				Name: "prod.kube.example.mesh", Type: networkmap.DNSRecordA, Address: address,
			})
		}
		plan, err := Compile(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		host := plan.Hosts[slices.IndexFunc(plan.Hosts, func(host Host) bool { return host.Name == "prod.kube.example.mesh" })]
		want := slices.Clone(replicas)
		orderHostAddresses(want, snapshot.Self.StableID)
		if !slices.Equal(host.Addresses, want) {
			t.Fatalf("node %d: %v, want %v", index, host.Addresses, want)
		}
		firsts[host.Addresses[0]] = true
	}
	if len(firsts) != len(replicas) {
		t.Fatalf("40 nodes start at %d of 3 replicas", len(firsts))
	}
}

// A name's A answer, one family of its addresses, is in the same order as
// the node would rank those addresses alone.
func TestOrderHostAddressesKeepsEachFamilysOrder(t *testing.T) {
	t.Parallel()
	v4 := replicaAddresses(5)
	var v6 []netip.Addr
	for index := range 5 {
		v6 = append(v6, netip.MustParseAddr(fmt.Sprintf("fd00::1:%d", 10+index)))
	}
	for index := range 50 {
		self := fmt.Sprintf("node-%d", index)
		mixed := append(slices.Clone(v4), v6...)
		orderHostAddresses(mixed, self)
		resources, err := addressResources(Host{Name: "prod.kube.example.mesh", Addresses: mixed},
			"prod.kube.example.mesh", dnsmessage.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		var answered []netip.Addr
		for _, resource := range resources {
			answered = append(answered, netip.AddrFrom4(resource.Body.(*dnsmessage.AResource).A))
		}
		alone := slices.Clone(v4)
		orderHostAddresses(alone, self)
		if !slices.Equal(answered, alone) {
			t.Fatalf("%s: A answer %v, want %v", self, answered, alone)
		}
	}
}
