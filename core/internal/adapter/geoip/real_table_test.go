package geoip

import (
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestOpenRealTable reads a real DB-IP table when MESHTRANSIT_TEST_GEOIP_FILE
// names one, and reports its size and load time.
func TestOpenRealTable(t *testing.T) {
	path := os.Getenv("MESHTRANSIT_TEST_GEOIP_FILE")
	if path == "" {
		t.Skip("MESHTRANSIT_TEST_GEOIP_FILE is not set")
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	started := time.Now()
	countries, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("v4 %d ranges, v6 %d ranges, %s, %.1f MiB", len(countries.v4), len(countries.v6), elapsed,
		float64(after.HeapAlloc-before.HeapAlloc)/(1<<20))
	if _, found := countries.Country(netip.MustParseAddr("10.0.0.1")); found {
		t.Error("a private address has a country")
	}
	for _, text := range []string{"8.8.8.8", "1.0.0.1", "113.161.2.3", "2001:4860:4860::8888"} {
		got, found := countries.Country(netip.MustParseAddr(text))
		if !found {
			t.Errorf("%s has no country", text)
		}
		t.Logf("%s -> %s", text, got)
	}
	runtime.KeepAlive(countries)
}
