package daemon

import (
	"slices"
	"testing"

	"meshtransit.net/client/internal/networkmap"
)

// The names a root zone leaves to the network are the control host, the
// relays' hosts and the ones Core names (TD-CLI-70), each once.
func TestInfrastructureNamesTakeCoresNames(t *testing.T) {
	t.Parallel()
	snapshot := networkmap.Snapshot{
		Relays: map[int]networkmap.RelayRegion{1: {Nodes: []networkmap.RelayNode{{HostName: "relay.example.net"}}}},
		DNS:    &networkmap.DNSConfig{InfrastructureNames: []string{"console.example.net", "control.example.net"}},
	}
	got := infrastructureNames("https://control.example.net", snapshot)
	want := []string{"control.example.net", "relay.example.net", "console.example.net"}
	if !slices.Equal(got, want) {
		t.Fatalf("infrastructure names = %v, want %v", got, want)
	}
}
