// Package packetmeta parses the bounded network metadata needed by the data
// plane and flow reporter. It never retains packet bytes.
package packetmeta

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ProtocolICMPv4 uint8 = 1
	ProtocolTCP    uint8 = 6
	ProtocolUDP    uint8 = 17
	ProtocolICMPv6 uint8 = 58

	maxIPv6ExtensionHeaders = 8
)

// Header is the validated, payload-free metadata of one IP packet.
type Header struct {
	Source            netip.Addr
	Destination       netip.Addr
	Length            int
	Protocol          uint8
	SourcePort        uint16
	DestinationPort   uint16
	TCPFlags          uint8
	ICMPType          uint8
	ICMPCode          uint8
	ICMPIdentifier    uint16
	HasICMPIdentifier bool
}

// Parse validates an IPv4 or IPv6 packet and extracts only bounded header
// metadata. Fragmented packets fail closed because later fragments do not
// carry enough transport information for consistent policy enforcement.
func Parse(packet []byte) (Header, error) {
	if len(packet) == 0 {
		return Header{}, errors.New("packetmeta: packet is empty")
	}

	switch packet[0] >> 4 {
	case 4:
		return parseIPv4(packet)
	case 6:
		return parseIPv6(packet)
	default:
		return Header{}, errors.New("packetmeta: ip version is unsupported")
	}
}

func parseIPv4(packet []byte) (Header, error) {
	if len(packet) < 20 {
		return Header{}, errors.New("packetmeta: ipv4 packet is truncated")
	}
	headerLength := int(packet[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || totalLength < headerLength || totalLength > len(packet) {
		return Header{}, errors.New("packetmeta: ipv4 packet length is invalid")
	}
	fragmentField := binary.BigEndian.Uint16(packet[6:8])
	if fragmentField&0xbfff != 0 {
		return Header{}, errors.New("packetmeta: fragmented ipv4 packet is unsupported")
	}

	header := Header{
		Source:      netip.AddrFrom4([4]byte(packet[12:16])),
		Destination: netip.AddrFrom4([4]byte(packet[16:20])),
		Length:      totalLength,
		Protocol:    packet[9],
	}

	return parseTransport(packet[:totalLength], headerLength, header)
}

func parseIPv6(packet []byte) (Header, error) {
	if len(packet) < 40 {
		return Header{}, errors.New("packetmeta: ipv6 packet is truncated")
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLength == 0 {
		return Header{}, errors.New("packetmeta: ipv6 jumbogram is unsupported")
	}
	totalLength := 40 + payloadLength
	if totalLength > len(packet) {
		return Header{}, errors.New("packetmeta: ipv6 packet length is invalid")
	}

	header := Header{
		Source:      netip.AddrFrom16([16]byte(packet[8:24])),
		Destination: netip.AddrFrom16([16]byte(packet[24:40])),
		Length:      totalLength,
	}
	offset, protocol, err := walkIPv6Extensions(packet[:totalLength], 40, packet[6])
	if err != nil {
		return Header{}, err
	}
	header.Protocol = protocol

	return parseTransport(packet[:totalLength], offset, header)
}

func walkIPv6Extensions(packet []byte, offset int, protocol uint8) (int, uint8, error) {
	for range maxIPv6ExtensionHeaders {
		var extensionLength int
		switch protocol {
		case 0, 43, 60:
			if offset+2 > len(packet) {
				return 0, 0, errors.New("packetmeta: ipv6 extension header is truncated")
			}
			extensionLength = (int(packet[offset+1]) + 1) * 8
		case 44:
			return 0, 0, errors.New("packetmeta: fragmented ipv6 packet is unsupported")
		case 51:
			if offset+2 > len(packet) {
				return 0, 0, errors.New("packetmeta: ipv6 authentication header is truncated")
			}
			extensionLength = (int(packet[offset+1]) + 2) * 4
		default:
			return offset, protocol, nil
		}
		if extensionLength < 8 || offset+extensionLength > len(packet) {
			return 0, 0, errors.New("packetmeta: ipv6 extension header length is invalid")
		}
		protocol = packet[offset]
		offset += extensionLength
	}

	return 0, 0, errors.New("packetmeta: too many ipv6 extension headers")
}

func parseTransport(packet []byte, offset int, header Header) (Header, error) {
	if offset < 0 || offset > len(packet) {
		return Header{}, errors.New("packetmeta: transport offset is invalid")
	}

	switch header.Protocol {
	case ProtocolTCP:
		return parseTCP(packet, offset, header)
	case ProtocolUDP:
		return parseUDP(packet, offset, header)
	case ProtocolICMPv4, ProtocolICMPv6:
		return parseICMP(packet, offset, header)
	default:
		return header, nil
	}
}

func parseTCP(packet []byte, offset int, header Header) (Header, error) {
	if offset+20 > len(packet) {
		return Header{}, errors.New("packetmeta: tcp header is truncated")
	}
	header.SourcePort = binary.BigEndian.Uint16(packet[offset : offset+2])
	header.DestinationPort = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	if header.SourcePort == 0 || header.DestinationPort == 0 {
		return Header{}, errors.New("packetmeta: tcp port is zero")
	}
	headerLength := int(packet[offset+12]>>4) * 4
	if headerLength < 20 || offset+headerLength > len(packet) {
		return Header{}, errors.New("packetmeta: tcp header length is invalid")
	}
	header.TCPFlags = packet[offset+13]

	return header, nil
}

func parseUDP(packet []byte, offset int, header Header) (Header, error) {
	if offset+8 > len(packet) {
		return Header{}, errors.New("packetmeta: udp header is truncated")
	}
	header.SourcePort = binary.BigEndian.Uint16(packet[offset : offset+2])
	header.DestinationPort = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	udpLength := int(binary.BigEndian.Uint16(packet[offset+4 : offset+6]))
	if header.DestinationPort == 0 || udpLength < 8 || offset+udpLength > len(packet) {
		return Header{}, errors.New("packetmeta: udp header is invalid")
	}

	return header, nil
}

func parseICMP(packet []byte, offset int, header Header) (Header, error) {
	if offset+4 > len(packet) {
		return Header{}, errors.New("packetmeta: icmp header is truncated")
	}
	header.ICMPType = packet[offset]
	header.ICMPCode = packet[offset+1]
	isEcho := (header.Protocol == ProtocolICMPv4 && (header.ICMPType == 0 || header.ICMPType == 8)) ||
		(header.Protocol == ProtocolICMPv6 && (header.ICMPType == 128 || header.ICMPType == 129))
	if !isEcho {
		return header, nil
	}
	if offset+8 > len(packet) {
		return Header{}, errors.New("packetmeta: icmp echo header is truncated")
	}
	header.ICMPIdentifier = binary.BigEndian.Uint16(packet[offset+4 : offset+6])
	header.HasICMPIdentifier = true

	return header, nil
}
