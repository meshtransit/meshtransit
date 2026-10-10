package relay

import (
	"errors"
	"testing"
	"time"
)

func twoRegionConfig() Config {
	config := testConfig()
	config.Regions[2] = Region{ID: 2, Nodes: []Node{{Name: "relay-2", HostName: "relay-2.example.com", Port: 443}}}
	return config
}

func TestTopologyFingerprintIgnoresHomeRegion(t *testing.T) {
	t.Parallel()

	first := twoRegionConfig()
	second := twoRegionConfig()
	second.HomeRegion = 2
	if TopologyFingerprint(first) != TopologyFingerprint(second) {
		t.Fatal("a home region change must not change the relay transport")
	}
	if Fingerprint(first) == Fingerprint(second) {
		t.Fatal("a home region change must change the relay authority")
	}
}

func TestPoolMovesHomeRegionInPlace(t *testing.T) {
	t.Parallel()

	dialer := &fakeDialer{client: newFakeClient(), calls: make(chan int, 4)}
	pool, err := New(t.Context(), twoRegionConfig(), dialer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if region := <-dialer.calls; region != 1 {
		t.Fatalf("first dial = region %d, want 1", region)
	}
	peers := testConfig().Peers
	if err := pool.ReplaceAuthority(3, peers); err == nil {
		t.Fatal("ReplaceAuthority() accepted a region outside the map")
	}
	if home := pool.Health().HomeRegion; home != 1 {
		t.Fatalf("home after a rejected change = %d, want 1", home)
	}
	if err := pool.ReplaceAuthority(2, peers); err != nil {
		t.Fatalf("ReplaceAuthority(2) error = %v", err)
	}
	if home := pool.Health().HomeRegion; home != 2 {
		t.Fatalf("home = %d, want 2", home)
	}
	select {
	case region := <-dialer.calls:
		if region != 2 {
			t.Fatalf("dial after the change = region %d, want 2", region)
		}
	case <-time.After(time.Second):
		t.Fatal("the new home region was not connected")
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := pool.ReplaceAuthority(1, peers); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReplaceAuthority() after Close = %v, want ErrClosed", err)
	}
}
