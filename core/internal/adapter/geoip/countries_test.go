package geoip

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.4.0,1.0.7.255,AU
1.0.8.0,1.0.15.255,CN
10.0.0.0,10.255.255.255,ZZ
113.160.0.0,113.191.255.255,VN
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
2405:4800::,2405:4803:ffff:ffff:ffff:ffff:ffff:ffff,VN
`

func TestCountriesLooksUpBothFamilies(t *testing.T) {
	t.Parallel()
	countries, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	for text, want := range map[string]string{
		"1.0.0.1": "AU", "1.0.2.9": "CN", "1.0.7.255": "AU", "1.0.8.0": "CN", "113.161.2.3": "VN",
		"2001:200::1": "JP", "2405:4802::9": "VN", "::ffff:113.161.2.3": "VN",
		"1.0.16.0": "", "10.1.1.1": "", "9.9.9.9": "", "2a01::1": "", "0.0.0.0": "",
	} {
		got, found := countries.Country(netip.MustParseAddr(text))
		if got != want || found != (want != "") {
			t.Errorf("Country(%s) = %q %v, want %q", text, got, found, want)
		}
	}
	// AU, CN, AU, CN, VN stay apart; ZZ is left out.
	if len(countries.v4) != 5 || len(countries.v6) != 2 {
		t.Fatalf("ranges v4 %d v6 %d", len(countries.v4), len(countries.v6))
	}
	var none *Countries
	if _, found := none.Country(netip.MustParseAddr("1.0.0.1")); found {
		t.Fatal("a nil table found a country")
	}
}

func TestCountriesMergesAdjacentRangesOfOneCountry(t *testing.T) {
	t.Parallel()
	countries, err := Parse(strings.NewReader("1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.1.255,AU\n1.0.2.0,1.0.2.255,NZ\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(countries.v4) != 2 {
		t.Fatalf("ranges %d", len(countries.v4))
	}
	if got, _ := countries.Country(netip.MustParseAddr("1.0.1.7")); got != "AU" {
		t.Fatalf("merged range answers %q", got)
	}
}

func TestParseReadsWindowsLineEndsAndAByteOrderMark(t *testing.T) {
	t.Parallel()
	countries, err := Parse(strings.NewReader("\uFEFF1.0.0.0,1.0.0.255,AU\r\n2001:200::,2001:200::ffff,JP\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := countries.Country(netip.MustParseAddr("2001:200::7")); got != "JP" {
		t.Fatalf("answers %q", got)
	}
}

func TestParseMergesIPv6AndHandlesTheEdgesOfTheSpace(t *testing.T) {
	t.Parallel()
	countries, err := Parse(strings.NewReader("255.255.255.0,255.255.255.255,US\n" +
		"2001:200::,2001:200::ffff,JP\n2001:200::1:0,2001:200::1:ffff,JP\n" +
		"ffff::,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,DE\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(countries.v6) != 2 {
		t.Fatalf("v6 ranges %d", len(countries.v6))
	}
	for text, want := range map[string]string{"255.255.255.255": "US", "2001:200::1:9": "JP",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": "DE"} {
		if got, _ := countries.Country(netip.MustParseAddr(text)); got != want {
			t.Errorf("Country(%s) = %q, want %q", text, got, want)
		}
	}
}

func TestParseNamesTheBadLine(t *testing.T) {
	t.Parallel()
	_, err := Parse(strings.NewReader("1.0.0.0,1.0.0.255,AU\nbroken\n"))
	if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("Parse = %v", err)
	}
}

func TestParseRejectsMalformedTables(t *testing.T) {
	t.Parallel()
	for name, text := range map[string]string{
		"empty":        "",
		"fields":       "1.0.0.0,1.0.0.255\n",
		"address":      "1.0.0.x,1.0.0.255,AU\n",
		"reversed":     "1.0.0.255,1.0.0.0,AU\n",
		"families":     "1.0.0.0,2001::1,AU\n",
		"overlap":      "1.0.0.0,1.0.0.255,AU\n1.0.0.128,1.0.1.255,CN\n",
		"unsorted":     "1.0.1.0,1.0.1.255,AU\n1.0.0.0,1.0.0.255,CN\n",
		"country":      "1.0.0.0,1.0.0.255,Au\n",
		"long country": "1.0.0.0,1.0.0.255,AUS\n",
		"quoted":       "\"1.0.0.0\",\"1.0.0.255\",\"AU\"\n",
		"zone":         "fe80::%eth0,fe80::ffff%eth0,AU\n",
		"v6 before v4": "2001::,2001::ff,JP\n1.0.0.0,1.0.0.255,AU\n",
		"long line":    strings.Repeat("1", maximumLineBytes+1) + "\n",
	} {
		if _, err := Parse(strings.NewReader(text)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Parse = %v", name, err)
		}
	}
}

func TestOpenReadsPlainAndGzipFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	plain := filepath.Join(directory, "countries.csv")
	if err := os.WriteFile(plain, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(sample)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	zipped := filepath.Join(directory, "countries.csv.gz")
	if err := os.WriteFile(zipped, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plain, zipped} {
		countries, err := Open(path)
		if err != nil {
			t.Fatalf("Open(%s): %v", path, err)
		}
		if got, _ := countries.Country(netip.MustParseAddr("113.161.2.3")); got != "VN" {
			t.Fatalf("Open(%s) answers %q", path, got)
		}
	}
	if _, err := Open(filepath.Join(directory, "missing.csv")); err == nil {
		t.Fatal("a missing file opened")
	}
	broken := filepath.Join(directory, "broken.csv.gz")
	if err := os.WriteFile(broken, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(broken); err == nil {
		t.Fatal("a broken gzip file opened")
	}
}
