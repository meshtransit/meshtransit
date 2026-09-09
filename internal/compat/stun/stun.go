// Package stun implements the bounded RFC 5389 subset required by the direct
// path compatibility layer.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
)

const (
	headerSize    = 20
	maxPacketSize = 2048

	bindingRequestType = 0x0001
	bindingSuccessType = 0x0101
	magicCookie        = 0x2112a442
	fingerprintMask    = 0x5354554e

	attributeMappedAddress       = 0x0001
	attributeXORMappedAddress    = 0x0020
	attributeXORMappedAddressAlt = 0x8020
	attributeSoftware            = 0x8022
	attributeFingerprint         = 0x8028

	// The current compatibility server requires this SOFTWARE value and a
	// valid FINGERPRINT before it answers an otherwise standard request.
	compatibilitySoftware = "tailnode"
)

var (
	// ErrNotMessage means the packet does not have an RFC 5389 header.
	ErrNotMessage = errors.New("stun: packet is not a message")
	// ErrNotSuccessResponse means the packet is not a binding success response.
	ErrNotSuccessResponse = errors.New("stun: packet is not a binding success response")
	// ErrMalformed means the packet has an invalid or ambiguous encoding.
	ErrMalformed = errors.New("stun: packet is malformed")
	// ErrFingerprint means an optional response fingerprint is invalid.
	ErrFingerprint = errors.New("stun: response fingerprint is invalid")
	// ErrNoMappedAddress means the response did not contain a usable address.
	ErrNoMappedAddress = errors.New("stun: response has no mapped address")
)

// TransactionID correlates one response with one request.
type TransactionID [12]byte

// NewTransactionID returns a cryptographically random transaction ID.
func NewTransactionID() (TransactionID, error) {
	var transactionID TransactionID
	if _, err := rand.Read(transactionID[:]); err != nil {
		return TransactionID{}, err
	}

	return transactionID, nil
}

// BindingRequest returns one compatibility-form RFC 5389 binding request.
func BindingRequest(transactionID TransactionID) []byte {
	softwareLength := len(compatibilitySoftware)
	softwarePaddedLength := paddedLength(softwareLength)
	attributesLength := 4 + softwarePaddedLength + 8
	packet := make([]byte, headerSize, headerSize+attributesLength)
	binary.BigEndian.PutUint16(packet[0:2], bindingRequestType)
	binary.BigEndian.PutUint16(packet[2:4], uint16(attributesLength))
	binary.BigEndian.PutUint32(packet[4:8], magicCookie)
	copy(packet[8:headerSize], transactionID[:])

	packet = appendAttribute(packet, attributeSoftware, []byte(compatibilitySoftware))
	fingerprint := crc32.ChecksumIEEE(packet) ^ fingerprintMask
	packet = binary.BigEndian.AppendUint16(packet, attributeFingerprint)
	packet = binary.BigEndian.AppendUint16(packet, 4)
	packet = binary.BigEndian.AppendUint32(packet, fingerprint)

	return packet
}

// LooksLikeMessage reports whether a datagram belongs to the STUN demux. It
// intentionally accepts malformed lengths so such packets are not passed to
// the encrypted packet parser.
func LooksLikeMessage(packet []byte) bool {
	return len(packet) >= headerSize && packet[0]&0xc0 == 0 &&
		binary.BigEndian.Uint32(packet[4:8]) == magicCookie
}

// ParseBindingResponse validates one complete datagram and returns its
// transaction ID and canonical mapped address.
func ParseBindingResponse(packet []byte) (TransactionID, netip.AddrPort, error) {
	var transactionID TransactionID
	if !LooksLikeMessage(packet) {
		return transactionID, netip.AddrPort{}, ErrNotMessage
	}
	copy(transactionID[:], packet[8:headerSize])
	if len(packet) > maxPacketSize {
		return transactionID, netip.AddrPort{}, ErrMalformed
	}
	if binary.BigEndian.Uint16(packet[0:2]) != bindingSuccessType {
		return transactionID, netip.AddrPort{}, ErrNotSuccessResponse
	}
	attributesLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if attributesLength%4 != 0 || attributesLength != len(packet)-headerSize {
		return transactionID, netip.AddrPort{}, ErrMalformed
	}

	var mappedAddress netip.AddrPort
	var xorMappedAddress netip.AddrPort
	var hasMappedAddress bool
	var hasXORMappedAddress bool
	for offset := headerSize; offset < len(packet); {
		if len(packet)-offset < 4 {
			return transactionID, netip.AddrPort{}, ErrMalformed
		}
		attributeStart := offset
		attributeType := binary.BigEndian.Uint16(packet[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4
		paddedAttributeLength := paddedLength(attributeLength)
		if attributeLength > len(packet)-offset || paddedAttributeLength > len(packet)-offset {
			return transactionID, netip.AddrPort{}, ErrMalformed
		}
		value := packet[offset : offset+attributeLength]
		offset += paddedAttributeLength

		switch attributeType {
		case attributeMappedAddress:
			if hasMappedAddress {
				return transactionID, netip.AddrPort{}, ErrMalformed
			}
			address, err := parseMappedAddress(value)
			if err != nil {
				return transactionID, netip.AddrPort{}, err
			}
			mappedAddress = address
			hasMappedAddress = true
		case attributeXORMappedAddress, attributeXORMappedAddressAlt:
			if hasXORMappedAddress {
				return transactionID, netip.AddrPort{}, ErrMalformed
			}
			address, err := parseXORMappedAddress(value, transactionID)
			if err != nil {
				return transactionID, netip.AddrPort{}, err
			}
			xorMappedAddress = address
			hasXORMappedAddress = true
		case attributeFingerprint:
			isLastAttribute := offset == len(packet)
			if !isLastAttribute || len(value) != 4 {
				return transactionID, netip.AddrPort{}, ErrMalformed
			}
			expected := crc32.ChecksumIEEE(packet[:attributeStart]) ^ fingerprintMask
			if binary.BigEndian.Uint32(value) != expected {
				return transactionID, netip.AddrPort{}, ErrFingerprint
			}
		}
	}

	if hasXORMappedAddress {
		return transactionID, xorMappedAddress, nil
	}
	if hasMappedAddress {
		return transactionID, mappedAddress, nil
	}

	return transactionID, netip.AddrPort{}, ErrNoMappedAddress
}

func parseMappedAddress(value []byte) (netip.AddrPort, error) {
	if len(value) < 4 || value[0] != 0 {
		return netip.AddrPort{}, ErrMalformed
	}

	return addressPort(value[1], binary.BigEndian.Uint16(value[2:4]), value[4:])
}

func parseXORMappedAddress(
	value []byte,
	transactionID TransactionID,
) (netip.AddrPort, error) {
	if len(value) < 4 || value[0] != 0 {
		return netip.AddrPort{}, ErrMalformed
	}

	port := binary.BigEndian.Uint16(value[2:4]) ^ uint16(magicCookie>>16)
	encodedAddress := value[4:]
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[0:4], magicCookie)
	copy(mask[4:], transactionID[:])
	address := make([]byte, len(encodedAddress))
	for index := range encodedAddress {
		address[index] = encodedAddress[index] ^ mask[index]
	}

	return addressPort(value[1], port, address)
}

func addressPort(family byte, port uint16, addressBytes []byte) (netip.AddrPort, error) {
	if port == 0 {
		return netip.AddrPort{}, ErrMalformed
	}

	var address netip.Addr
	switch family {
	case 1:
		if len(addressBytes) != 4 {
			return netip.AddrPort{}, ErrMalformed
		}
		address = netip.AddrFrom4([4]byte(addressBytes))
	case 2:
		if len(addressBytes) != 16 {
			return netip.AddrPort{}, ErrMalformed
		}
		address = netip.AddrFrom16([16]byte(addressBytes))
		if address.Is4In6() {
			return netip.AddrPort{}, ErrMalformed
		}
	default:
		return netip.AddrPort{}, ErrMalformed
	}
	if !address.IsValid() || address.Zone() != "" {
		return netip.AddrPort{}, ErrMalformed
	}

	return netip.AddrPortFrom(address, port), nil
}

func appendAttribute(packet []byte, attributeType uint16, value []byte) []byte {
	packet = binary.BigEndian.AppendUint16(packet, attributeType)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(value)))
	packet = append(packet, value...)
	for len(packet)%4 != 0 {
		packet = append(packet, 0)
	}

	return packet
}

func paddedLength(length int) int { return (length + 3) &^ 3 }
