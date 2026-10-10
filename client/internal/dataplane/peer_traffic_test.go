package dataplane

import (
	"strings"
	"testing"
)

func TestParsePeerTraffic(t *testing.T) {
	t.Parallel()
	first, second := strings.Repeat("11", 32), strings.Repeat("22", 32)
	response := "private_key=" + strings.Repeat("33", 32) + "\nlisten_port=41641\n" +
		"public_key=" + first + "\nendpoint=192.0.2.1:41641\nrx_bytes=100\ntx_bytes=200\n" +
		"public_key=" + second + "\nrx_bytes=7\ntx_bytes=notanumber\n" +
		"public_key=zz\nrx_bytes=9\n" +
		"errno=0\n"
	traffic := parsePeerTraffic(response)
	if len(traffic) != 2 {
		t.Fatalf("parsed %d peers", len(traffic))
	}
	var key [32]byte
	key[0] = 0x11
	for i := range key {
		key[i] = 0x11
	}
	if got := traffic[key]; got.rx != 100 || got.tx != 200 {
		t.Fatalf("first peer %+v", got)
	}
	for i := range key {
		key[i] = 0x22
	}
	if got := traffic[key]; got.rx != 7 || got.tx != 0 {
		t.Fatalf("second peer %+v", got)
	}
}

func TestRelayRegionOf(t *testing.T) {
	t.Parallel()
	for endpoint, want := range map[string]int{
		"relay:12:" + strings.Repeat("ab", 32): 12,
		"relay:0:" + strings.Repeat("ab", 32):  0,
		"192.0.2.1:41641":                      0,
		"relay:x:abc":                          0,
	} {
		if got := relayRegionOf(endpoint); got != want {
			t.Errorf("relayRegionOf(%q) = %d, want %d", endpoint, got, want)
		}
	}
}
