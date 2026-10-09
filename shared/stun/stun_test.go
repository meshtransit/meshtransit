package stun

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// rfc5769Response is the IPv4 sample response of RFC 5769 §2.2: SOFTWARE,
// XOR-MAPPED-ADDRESS 192.0.2.1:32853, MESSAGE-INTEGRITY and FINGERPRINT.
const rfc5769Response = "0101003c2112a442b7e7a701bc34d686fa87dfae" +
	"8022000b7465737420766563746f7220" +
	"00200008" + "0001a147e112a643" +
	"000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7" +
	"80280004c07d4c96"

func TestRFC5769Response(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(rfc5769Response)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := netip.MustParseAddrPort("192.0.2.1:32853"); m.XORMapped != want || m.Type != TypeBindingSuccess {
		t.Fatalf("got %+v, want mapped %s", m, want)
	}
	b[len(b)-1] ^= 1
	if _, err := Parse(b); !errors.Is(err, ErrMalformed) {
		t.Fatal("bad fingerprint accepted")
	}
}

func TestBindingRoundTrip(t *testing.T) {
	t.Parallel()
	id := TxID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := AppendBindingRequest(nil, id, ChangeRequest{IP: true, Port: true})
	m, err := Parse(req)
	if err != nil || m.Type != TypeBindingRequest || m.TxID != id || !m.Change.IP || !m.Change.Port {
		t.Fatalf("request = %+v, %v", m, err)
	}
	withSoftware, err := AppendRequest(nil, id, Request{Change: ChangeRequest{Port: true}, Software: "meshtransit"})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := Parse(withSoftware); err != nil || m.Software != "meshtransit" || !m.Change.Port {
		t.Fatalf("request with software = %+v, %v", m, err)
	}
	if _, err := AppendRequest(nil, id, Request{Software: strings.Repeat("x", MaxSoftwareSize+1)}); err == nil {
		t.Fatal("oversized SOFTWARE encoded")
	}
	plain := AppendBindingRequest(nil, id, ChangeRequest{})
	if m, err := Parse(plain); err != nil || m.Change.IP || m.Change.Port {
		t.Fatalf("plain request = %+v, %v", m, err)
	}
	for _, mapped := range []string{"203.0.113.9:41641", "[2001:db8::9]:41641"} {
		ap := netip.MustParseAddrPort(mapped)
		origin := netip.MustParseAddrPort("198.51.100.1:3478")
		other := netip.MustParseAddrPort("198.51.100.2:3479")
		resp, err := AppendBindingSuccess(nil, id, ap, origin, other)
		if err != nil {
			t.Fatal(err)
		}
		m, err := Parse(resp)
		if err != nil || m.XORMapped != ap || m.ResponseOrigin != origin || m.OtherAddress != other {
			t.Fatalf("response %s = %+v, %v", mapped, m, err)
		}
	}
	mapped4in6 := netip.MustParseAddrPort("[::ffff:198.51.100.2]:3479")
	resp, err := AppendBindingSuccess(nil, id, mapped4in6, netip.AddrPort{}, mapped4in6)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := Parse(resp); err != nil || !m.OtherAddress.Addr().Is4() || !m.XORMapped.Addr().Is4() {
		t.Fatalf("IPv4-mapped addresses not unmapped: %+v, %v", m, err)
	}
	if _, err := AppendBindingSuccess(nil, id, netip.AddrPort{}, netip.AddrPort{}, netip.AddrPort{}); err == nil {
		t.Fatal("response without mapped address encoded")
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	id := TxID{9}
	good := AppendBindingRequest(nil, id, ChangeRequest{Port: true})
	withAttr := func(typ uint16) []byte {
		b := appendHeader(nil, TypeBindingRequest, id)
		b = appendAttr(b, typ, []byte{1, 2, 3, 4})
		return finish(b, 0)
	}
	tests := []struct {
		name string
		b    []byte
		want error
	}{
		{"short", good[:10], ErrNotSTUN},
		{"no cookie", append([]byte{0, 1, 0, 0, 0, 0, 0, 0}, good[8:]...), ErrNotSTUN},
		{"length mismatch", good[:len(good)-4], ErrMalformed},
		{"unknown type", append([]byte{0x00, 0x02}, good[2:]...), ErrMalformed},
		{"unknown required attribute", withAttr(0x7777), ErrUnknownAttribute},
		{"oversize", append(bytes.Clone(good), make([]byte, MaxMessageSize)...), ErrMalformed},
		{"success without mapped", finish(appendHeader(nil, TypeBindingSuccess, id), 0), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(tt.b); !errors.Is(err, tt.want) {
				t.Fatalf("Parse error = %v, want %v", err, tt.want)
			}
		})
	}
	if _, err := Parse(withAttr(0x8777)); err != nil {
		t.Fatalf("unknown optional attribute rejected: %v", err)
	}
	if Is([]byte(strings.Repeat("x", 30))) {
		t.Fatal("text detected as STUN")
	}
}

func TestParseAllocations(t *testing.T) {
	resp, err := AppendBindingSuccess(nil, TxID{7}, netip.MustParseAddrPort("[2001:db8::1]:1"),
		netip.MustParseAddrPort("192.0.2.1:3478"), netip.MustParseAddrPort("192.0.2.2:3479"))
	if err != nil {
		t.Fatal(err)
	}
	// Parse runs on every inbound STUN packet; it must not allocate.
	if n := testing.AllocsPerRun(100, func() { _, _ = Parse(resp) }); n != 0 {
		t.Fatalf("Parse allocates %.0f times", n)
	}
}

func FuzzParse(f *testing.F) {
	b, _ := hex.DecodeString(rfc5769Response)
	f.Add(b)
	f.Add(AppendBindingRequest(nil, TxID{1}, ChangeRequest{IP: true}))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil || m.Type != TypeBindingSuccess {
			return
		}
		// A parsed success response re-encodes to one that parses identically.
		out, err := AppendBindingSuccess(nil, m.TxID, m.XORMapped, m.ResponseOrigin, m.OtherAddress)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Parse(out)
		if err != nil || again.XORMapped != m.XORMapped || again.OtherAddress != m.OtherAddress ||
			again.ResponseOrigin != m.ResponseOrigin {
			t.Fatalf("round trip: %+v -> %+v, %v", m, again, err)
		}
	})
}
