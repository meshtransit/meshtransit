package flowlog

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	protocolTCP = 6
	protocolUDP = 17
)

type packetHeader struct {
	protocol uint8
	source   netip.AddrPort
	dest     netip.AddrPort
	bytes    uint64
	tcpFlags uint8
}

func parsePacketHeader(packet []byte) (packetHeader, error) {
	if len(packet) == 0 {
		return packetHeader{}, errors.New("packet is empty")
	}
	switch packet[0] >> 4 {
	case 4:
		return parseIPv4Header(packet)
	case 6:
		return parseIPv6Header(packet)
	default:
		return packetHeader{}, errors.New("IP version is unsupported")
	}
}

func parseIPv4Header(packet []byte) (packetHeader, error) {
	if len(packet) < 20 {
		return packetHeader{}, errors.New("IPv4 packet is truncated")
	}
	headerBytes := int(packet[0]&0x0f) * 4
	totalBytes := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerBytes < 20 || totalBytes < headerBytes || totalBytes > len(packet) {
		return packetHeader{}, errors.New("IPv4 packet length is invalid")
	}
	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x1fff != 0 {
		return packetHeader{}, errors.New("IPv4 non-initial fragment has no ports")
	}
	source := netip.AddrFrom4([4]byte(packet[12:16]))
	destination := netip.AddrFrom4([4]byte(packet[16:20]))

	return parseTransport(packet[:totalBytes], headerBytes, packet[9], source, destination)
}

func parseIPv6Header(packet []byte) (packetHeader, error) {
	if len(packet) < 40 {
		return packetHeader{}, errors.New("IPv6 packet is truncated")
	}
	totalBytes := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	if totalBytes < 40 || totalBytes > len(packet) {
		return packetHeader{}, errors.New("IPv6 packet length is invalid")
	}
	source := netip.AddrFrom16([16]byte(packet[8:24]))
	destination := netip.AddrFrom16([16]byte(packet[24:40]))

	return parseTransport(packet[:totalBytes], 40, packet[6], source, destination)
}

func parseTransport(
	packet []byte,
	offset int,
	protocol uint8,
	sourceAddress netip.Addr,
	destinationAddress netip.Addr,
) (packetHeader, error) {
	minimumBytes := 8
	if protocol == protocolTCP {
		minimumBytes = 20
	} else if protocol != protocolUDP {
		return packetHeader{}, errors.New("transport protocol has no supported ports")
	}
	if offset < 0 || offset+minimumBytes > len(packet) {
		return packetHeader{}, errors.New("transport header is truncated")
	}
	sourcePort := binary.BigEndian.Uint16(packet[offset : offset+2])
	destinationPort := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	if sourcePort == 0 || destinationPort == 0 {
		return packetHeader{}, errors.New("transport port is zero")
	}
	header := packetHeader{
		protocol: protocol,
		source:   netip.AddrPortFrom(sourceAddress, sourcePort),
		dest:     netip.AddrPortFrom(destinationAddress, destinationPort),
		bytes:    uint64(len(packet)),
	}
	if protocol == protocolTCP {
		header.tcpFlags = packet[offset+13]
	}

	return header, nil
}
