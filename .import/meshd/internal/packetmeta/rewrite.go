package packetmeta

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// AddressPair names the exact source and destination at one packet boundary.
type AddressPair struct {
	Source      netip.Addr
	Destination netip.Addr
}

// CheckAliasPacket admits only complete, checksum-valid TCP, UDP and ICMP echo
// packets. Alias v1 excludes IP options, extensions, fragments and ICMP errors.
func CheckAliasPacket(packet []byte) (Header, error) {
	header, err := Parse(packet)
	if err != nil {
		return Header{}, err
	}
	if !validRewriteAddress(header.Source, header.Source.Is4()) ||
		!validRewriteAddress(header.Destination, header.Source.Is4()) {
		return Header{}, errors.New("packetmeta: alias original address is invalid")
	}
	if header.Length != len(packet) {
		return Header{}, errors.New("packetmeta: alias packet length is ambiguous")
	}
	offset := 40
	if header.Source.Is4() {
		offset = 20
		if packet[0]&0x0f != 5 || checksumSum(packet[:20]) != 0xffff {
			return Header{}, errors.New("packetmeta: alias ipv4 header is unsupported or corrupt")
		}
	} else if packet[6] != header.Protocol {
		return Header{}, errors.New("packetmeta: alias ipv6 extensions are unsupported")
	}
	transport := packet[offset:]
	switch header.Protocol {
	case ProtocolTCP:
		if transportChecksum(header, transport) != 0xffff {
			return Header{}, errors.New("packetmeta: alias tcp checksum is invalid")
		}
	case ProtocolUDP:
		if int(binary.BigEndian.Uint16(transport[4:6])) != len(transport) {
			return Header{}, errors.New("packetmeta: alias udp length is ambiguous")
		}
		value := binary.BigEndian.Uint16(transport[6:8])
		if value == 0 && header.Source.Is4() {
			break
		}
		if value == 0 || transportChecksum(header, transport) != 0xffff {
			return Header{}, errors.New("packetmeta: alias udp checksum is invalid")
		}
	case ProtocolICMPv4, ProtocolICMPv6:
		if !header.HasICMPIdentifier {
			return Header{}, errors.New("packetmeta: alias icmp form is unsupported")
		}
		value := checksumSum(transport)
		if header.Protocol == ProtocolICMPv6 {
			value = transportChecksum(header, transport)
		}
		if value != 0xffff {
			return Header{}, errors.New("packetmeta: alias icmp checksum is invalid")
		}
	default:
		return Header{}, errors.New("packetmeta: alias protocol is unsupported")
	}
	return header, nil
}

// RewriteAddresses checks the original tuple and checksums before modifying
// packet in place. Failure leaves every byte unchanged. Authority and peer
// identity checks belong to the caller; this function grants no packet access.
func RewriteAddresses(packet []byte, expected, replacement AddressPair) error {
	header, err := CheckAliasPacket(packet)
	if err != nil {
		return err
	}
	if header.Source != expected.Source || header.Destination != expected.Destination {
		return errors.New("packetmeta: alias original tuple mismatch")
	}
	if !validRewriteAddress(replacement.Source, header.Source.Is4()) ||
		!validRewriteAddress(replacement.Destination, header.Source.Is4()) {
		return errors.New("packetmeta: alias replacement address is invalid")
	}
	offset := 40
	if header.Source.Is4() {
		source, destination := replacement.Source.As4(), replacement.Destination.As4()
		copy(packet[12:16], source[:])
		copy(packet[16:20], destination[:])
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], ^checksumSum(packet[:20]))
		offset = 20
	} else {
		source, destination := replacement.Source.As16(), replacement.Destination.As16()
		copy(packet[8:24], source[:])
		copy(packet[24:40], destination[:])
	}
	header.Source, header.Destination = replacement.Source, replacement.Destination
	transport := packet[offset:]
	checksumOffset := 16
	switch header.Protocol {
	case ProtocolICMPv4:
		// ICMPv4 has no address-dependent pseudo-header.
		return nil
	case ProtocolICMPv6:
		checksumOffset = 2
	case ProtocolUDP:
		checksumOffset = 6
		if header.Source.Is4() && binary.BigEndian.Uint16(transport[6:8]) == 0 {
			return nil
		}
	}
	transport[checksumOffset], transport[checksumOffset+1] = 0, 0
	checksum := ^transportChecksum(header, transport)
	if header.Protocol == ProtocolUDP && checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(transport[checksumOffset:checksumOffset+2], checksum)
	return nil
}

func validRewriteAddress(address netip.Addr, ipv4 bool) bool {
	return address.IsValid() && address.Is4() == ipv4 && !address.Is4In6() &&
		address.Zone() == "" && address.IsGlobalUnicast() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func transportChecksum(header Header, transport []byte) uint16 {
	transportLength := len(transport)
	if transportLength > 65535 {
		return 0 // Alias v1 has no jumbogram transport.
	}
	boundedLength := uint16(transportLength)
	var pseudo [40]byte
	length := 40
	if header.Source.Is4() {
		source, destination := header.Source.As4(), header.Destination.As4()
		copy(pseudo[0:4], source[:])
		copy(pseudo[4:8], destination[:])
		pseudo[9] = header.Protocol
		binary.BigEndian.PutUint16(pseudo[10:12], boundedLength)
		length = 12
	} else {
		source, destination := header.Source.As16(), header.Destination.As16()
		copy(pseudo[0:16], source[:])
		copy(pseudo[16:32], destination[:])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(boundedLength))
		pseudo[39] = header.Protocol
	}
	return foldChecksum(uint32(checksumSum(pseudo[:length])) + uint32(checksumSum(transport)))
}

func checksumSum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[:2]))
		packet = packet[2:]
	}
	if len(packet) != 0 {
		sum += uint32(packet[0]) << 8
	}
	return foldChecksum(sum)
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
