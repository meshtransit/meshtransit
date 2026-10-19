package packetmeta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestUnreachableAnswersIPv4(t *testing.T) {
	t.Parallel()
	original := make([]byte, 40)
	original[0], original[8], original[9] = 0x45, 64, ProtocolTCP
	binary.BigEndian.PutUint16(original[2:4], 40)
	copy(original[12:16], []byte{100, 64, 0, 3})
	copy(original[16:20], []byte{10, 30, 0, 5})
	binary.BigEndian.PutUint16(original[20:22], 40000)
	binary.BigEndian.PutUint16(original[22:24], 443)
	original[32] = 0x50
	answer, err := Unreachable(original)
	if err != nil {
		t.Fatal(err)
	}
	header, err := Parse(answer)
	if err != nil {
		t.Fatalf("Parse(answer) error = %v", err)
	}
	if header.Protocol != ProtocolICMPv4 || header.ICMPType != 3 || header.ICMPCode != 1 ||
		header.Source != netip.MustParseAddr("10.30.0.5") || header.Destination != netip.MustParseAddr("100.64.0.3") {
		t.Fatalf("answer header = %+v", header)
	}
	if checksumSum(answer[:20]) != 0xffff || checksumSum(answer[20:]) != 0xffff {
		t.Fatal("answer checksums are wrong")
	}
	if !bytes.Equal(answer[28:], original) {
		t.Fatal("answer does not quote the packet")
	}
}

func TestUnreachableAnswersIPv6(t *testing.T) {
	t.Parallel()
	original := make([]byte, 60)
	original[0], original[6], original[7] = 0x60, ProtocolUDP, 64
	binary.BigEndian.PutUint16(original[4:6], 20)
	source, destination := netip.MustParseAddr("fd7a::3").As16(), netip.MustParseAddr("fd00:1::5").As16()
	copy(original[8:24], source[:])
	copy(original[24:40], destination[:])
	binary.BigEndian.PutUint16(original[40:42], 40000)
	binary.BigEndian.PutUint16(original[42:44], 53)
	binary.BigEndian.PutUint16(original[44:46], 20)
	answer, err := Unreachable(original)
	if err != nil {
		t.Fatal(err)
	}
	header, err := Parse(answer)
	if err != nil || header.Protocol != ProtocolICMPv6 || header.ICMPType != 1 || header.ICMPCode != 3 ||
		header.Source != netip.MustParseAddr("fd00:1::5") || header.Destination != netip.MustParseAddr("fd7a::3") {
		t.Fatalf("answer header = %+v, %v", header, err)
	}
	if transportChecksum(header, answer[40:]) != 0xffff {
		t.Fatal("ICMPv6 checksum is wrong")
	}
}

func TestUnreachableNeverAnswersAnICMPError(t *testing.T) {
	t.Parallel()
	original := make([]byte, 28)
	original[0], original[8], original[9] = 0x45, 64, ProtocolICMPv4
	binary.BigEndian.PutUint16(original[2:4], 28)
	copy(original[12:16], []byte{100, 64, 0, 3})
	copy(original[16:20], []byte{10, 30, 0, 5})
	original[20] = 3 // itself an unreachable
	if _, err := Unreachable(original); !errors.Is(err, ErrNoUnreachable) {
		t.Fatalf("Unreachable(ICMP error) error = %v", err)
	}
	original[20] = 8 // an echo request is answered
	if _, err := Unreachable(original); err != nil {
		t.Fatalf("Unreachable(echo request) error = %v", err)
	}
}
