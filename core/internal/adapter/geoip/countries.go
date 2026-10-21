// Package geoip maps public addresses to the country they are registered
// in, from a DB-IP "IP to Country Lite" table (CC BY 4.0, db-ip.com): CSV
// lines of first address, last address and ISO 3166-1 alpha-2 code, in
// address order, IPv4 before IPv6. The table is read once and kept in
// memory; a lookup is a binary search.
package geoip

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
)

const (
	// maximumLineBytes bounds one CSV line: two IPv6 addresses and a code.
	maximumLineBytes = 128
	// maximumRanges bounds the table; the Lite table has about a million.
	maximumRanges = 4_000_000
	// unknownCountry is DB-IP's code for addresses of no country.
	unknownCountry = "ZZ"
)

// ErrMalformed reports a table that is not one Countries can read.
var ErrMalformed = errors.New("geoip: malformed country table")

type countryCode [2]byte

type rangeV4 struct {
	first, last uint32
	country     countryCode
}

type rangeV6 struct {
	first, last [16]byte
	country     countryCode
}

// Countries is an immutable country table, safe for concurrent lookups.
type Countries struct {
	v4 []rangeV4
	v6 []rangeV6
}

// Open reads a table from a CSV file, gzip-compressed when its name ends
// in .gz.
func Open(path string) (*Countries, error) {
	file, err := os.Open(path) // #nosec G304 -- the operator configures the path.
	if err != nil {
		return nil, fmt.Errorf("geoip: open country table: %w", err)
	}
	defer file.Close()
	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		decompressed, err := gzip.NewReader(file)
		if err != nil {
			return nil, errors.Join(ErrMalformed, err)
		}
		defer decompressed.Close()
		reader = decompressed
	}
	return Parse(reader)
}

// Parse reads a table. Ranges must be in address order and must not
// overlap; ranges of no country (ZZ) are left out, and adjacent ranges of
// one country are merged. A byte order mark and CRLF line ends are read.
func Parse(reader io.Reader) (*Countries, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, maximumLineBytes), maximumLineBytes)
	countries := &Countries{}
	var previous netip.Addr
	ranges := 0
	for scanner.Scan() {
		line := bytes.TrimSuffix(scanner.Bytes(), []byte{'\r'})
		if ranges == 0 {
			line = bytes.TrimPrefix(line, []byte("\uFEFF"))
		}
		first, last, country, err := parseLine(line)
		if ranges++; err == nil && (ranges > maximumRanges || (previous.IsValid() && first.Compare(previous) <= 0)) {
			err = ErrMalformed
		}
		if err != nil {
			return nil, fmt.Errorf("%w: line %d", err, ranges)
		}
		previous = last
		if country != unknownCountry {
			countries.add(first, last, countryCode{country[0], country[1]})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: line %d: %w", ErrMalformed, ranges+1, err)
	}
	if ranges == 0 {
		return nil, ErrMalformed
	}
	// Copies drop the spare capacity append left behind.
	countries.v4, countries.v6 = slices.Clone(countries.v4), slices.Clone(countries.v6)
	return countries, nil
}

func parseLine(line []byte) (netip.Addr, netip.Addr, string, error) {
	fields := bytes.Split(line, []byte{','})
	if len(fields) != 3 {
		return netip.Addr{}, netip.Addr{}, "", ErrMalformed
	}
	first, firstErr := netip.ParseAddr(string(fields[0]))
	last, lastErr := netip.ParseAddr(string(fields[1]))
	country := string(fields[2])
	if firstErr != nil || lastErr != nil || first.Zone() != "" || last.Zone() != "" ||
		first.Is4() != last.Is4() || first.Is4In6() || last.Is4In6() || last.Less(first) || !validCountry(country) {
		return netip.Addr{}, netip.Addr{}, "", ErrMalformed
	}
	return first, last, country, nil
}

func validCountry(country string) bool {
	return len(country) == 2 && country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z'
}

func (countries *Countries) add(first, last netip.Addr, country countryCode) {
	if first.Is4() {
		value := rangeV4{first: uint32Of(first), last: uint32Of(last), country: country}
		if count := len(countries.v4); count > 0 {
			if previous := &countries.v4[count-1]; previous.country == country && previous.last+1 == value.first {
				previous.last = value.last
				return
			}
		}
		countries.v4 = append(countries.v4, value)
		return
	}
	value := rangeV6{first: first.As16(), last: last.As16(), country: country}
	if count := len(countries.v6); count > 0 {
		previous := &countries.v6[count-1]
		if previous.country == country && netip.AddrFrom16(previous.last).Next() == first {
			previous.last = value.last
			return
		}
	}
	countries.v6 = append(countries.v6, value)
}

// Country returns the code of the country an address is registered in;
// false for an address the table does not place, and for a nil table.
func (countries *Countries) Country(address netip.Addr) (string, bool) {
	if countries == nil || !address.IsValid() {
		return "", false
	}
	address = address.Unmap()
	if address.Is4() {
		value := uint32Of(address)
		index, _ := slices.BinarySearchFunc(countries.v4, value, func(entry rangeV4, target uint32) int {
			switch {
			case entry.last < target:
				return -1
			case entry.first > target:
				return 1
			default:
				return 0
			}
		})
		if index < len(countries.v4) && countries.v4[index].first <= value && value <= countries.v4[index].last {
			return string(countries.v4[index].country[:]), true
		}
		return "", false
	}
	value := address.As16()
	index, _ := slices.BinarySearchFunc(countries.v6, value, func(entry rangeV6, target [16]byte) int {
		switch {
		case bytes.Compare(entry.last[:], target[:]) < 0:
			return -1
		case bytes.Compare(entry.first[:], target[:]) > 0:
			return 1
		default:
			return 0
		}
	})
	if index < len(countries.v6) && bytes.Compare(countries.v6[index].first[:], value[:]) <= 0 &&
		bytes.Compare(value[:], countries.v6[index].last[:]) <= 0 {
		return string(countries.v6[index].country[:]), true
	}
	return "", false
}

func uint32Of(address netip.Addr) uint32 {
	bytes := address.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
