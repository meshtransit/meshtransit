package stun

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"net/netip"
	"slices"
	"testing"

	upstreamstun "tailscale.com/net/stun"
)

func TestNewTransactionID(t *testing.T) {
	t.Parallel()

	first, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID() first error = %v", err)
	}
	second, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID() second error = %v", err)
	}
	if first == (TransactionID{}) || second == (TransactionID{}) || first == second {
		t.Fatalf("NewTransactionID() returned invalid values %x and %x", first, second)
	}
}

func TestBindingRequest(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	packet := BindingRequest(transactionID)
	if !LooksLikeMessage(packet) {
		t.Fatal("BindingRequest() does not look like a STUN message")
	}
	if got := binary.BigEndian.Uint16(packet[0:2]); got != bindingRequestType {
		t.Fatalf("BindingRequest() type = %#x, want %#x", got, bindingRequestType)
	}
	if got := int(binary.BigEndian.Uint16(packet[2:4])); got != len(packet)-headerSize {
		t.Fatalf("BindingRequest() length = %d, want %d", got, len(packet)-headerSize)
	}
	if !slices.Equal(packet[8:headerSize], transactionID[:]) {
		t.Fatalf("BindingRequest() transaction = %x, want %x", packet[8:headerSize], transactionID)
	}
	softwareStart := headerSize + 4
	softwareEnd := softwareStart + len(compatibilitySoftware)
	if got := string(packet[softwareStart:softwareEnd]); got != compatibilitySoftware {
		t.Fatalf("BindingRequest() software = %q, want %q", got, compatibilitySoftware)
	}
	fingerprintStart := len(packet) - 8
	if got := binary.BigEndian.Uint16(packet[fingerprintStart : fingerprintStart+2]); got != attributeFingerprint {
		t.Fatalf("BindingRequest() fingerprint type = %#x", got)
	}
	expectedFingerprint := crc32.ChecksumIEEE(packet[:fingerprintStart]) ^ fingerprintMask
	if got := binary.BigEndian.Uint32(packet[len(packet)-4:]); got != expectedFingerprint {
		t.Fatalf("BindingRequest() fingerprint = %#x, want %#x", got, expectedFingerprint)
	}
}

func TestBindingRequest_Compatibility(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	parsed, err := upstreamstun.ParseBindingRequest(BindingRequest(transactionID))
	if err != nil {
		t.Fatalf("compatibility ParseBindingRequest() error = %v", err)
	}
	if parsed != upstreamstun.TxID(transactionID) {
		t.Fatalf("compatibility transaction = %x, want %x", parsed, transactionID)
	}
}

func TestLooksLikeMessage(t *testing.T) {
	t.Parallel()

	valid := BindingRequest(TransactionID{1})
	wrongCookie := slices.Clone(valid)
	wrongCookie[4] = 0
	wrongPrefix := slices.Clone(valid)
	wrongPrefix[0] = 0xc0

	tests := []struct {
		name     string
		packet   []byte
		expected bool
	}{
		{name: "valid", packet: valid, expected: true},
		{name: "short", packet: valid[:headerSize-1], expected: false},
		{name: "wrong cookie", packet: wrongCookie, expected: false},
		{name: "wrong prefix", packet: wrongPrefix, expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := LooksLikeMessage(test.packet); got != test.expected {
				t.Fatalf("LooksLikeMessage() = %t, want %t", got, test.expected)
			}
		})
	}
}

func TestParseBindingResponse(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23}
	ipv4 := netip.MustParseAddrPort("203.0.113.8:41641")
	ipv6 := netip.MustParseAddrPort("[2001:db8::8]:41641")
	tests := []struct {
		name       string
		packet     []byte
		expectedID TransactionID
		expected   netip.AddrPort
	}{
		{
			name:       "xor mapped ipv4",
			packet:     testResponse(transactionID, testXORAddress(transactionID, ipv4)),
			expectedID: transactionID,
			expected:   ipv4,
		},
		{
			name:       "alternative xor mapped ipv6",
			packet:     testResponse(transactionID, testXORAddressAlt(transactionID, ipv6)),
			expectedID: transactionID,
			expected:   ipv6,
		},
		{
			name:       "mapped fallback",
			packet:     testResponse(transactionID, testMappedAddress(ipv4)),
			expectedID: transactionID,
			expected:   ipv4,
		},
		{
			name: "xor takes precedence",
			packet: testResponse(
				transactionID,
				testMappedAddress(ipv4),
				testXORAddress(transactionID, ipv6),
			),
			expectedID: transactionID,
			expected:   ipv6,
		},
		{
			name: "unknown optional attribute",
			packet: testResponse(
				transactionID,
				testAttribute(0x802b, []byte{1, 2, 3, 4}),
				testXORAddress(transactionID, ipv4),
			),
			expectedID: transactionID,
			expected:   ipv4,
		},
		{
			name:       "valid fingerprint",
			packet:     testResponseWithFingerprint(transactionID, testXORAddress(transactionID, ipv4)),
			expectedID: transactionID,
			expected:   ipv4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			transactionID, address, err := ParseBindingResponse(test.packet)
			if err != nil {
				t.Fatalf("ParseBindingResponse() error = %v", err)
			}
			if transactionID != test.expectedID || address != test.expected {
				t.Fatalf(
					"ParseBindingResponse() = %x, %v; want %x, %v",
					transactionID,
					address,
					test.expectedID,
					test.expected,
				)
			}
		})
	}
}

func TestParseBindingResponse_Compatibility(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24}
	expected := netip.MustParseAddrPort("203.0.113.60:41641")
	packet := upstreamstun.Response(upstreamstun.TxID(transactionID), expected)
	parsedID, parsedAddress, err := ParseBindingResponse(packet)
	if err != nil {
		t.Fatalf("ParseBindingResponse() compatibility error = %v", err)
	}
	if parsedID != transactionID || parsedAddress != expected {
		t.Fatalf(
			"ParseBindingResponse() = %x, %v; want %x, %v",
			parsedID,
			parsedAddress,
			transactionID,
			expected,
		)
	}
}

func TestParseBindingResponse_RejectsMalformedPackets(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24}
	address := netip.MustParseAddrPort("203.0.113.9:41641")
	validAddress := testXORAddress(transactionID, address)
	valid := testResponse(transactionID, validAddress)

	wrongCookie := slices.Clone(valid)
	wrongCookie[4] = 0
	wrongType := slices.Clone(valid)
	binary.BigEndian.PutUint16(wrongType[0:2], 0x0111)
	badLengthAlignment := slices.Clone(valid)
	binary.BigEndian.PutUint16(badLengthAlignment[2:4], 1)
	trailingByte := append(slices.Clone(valid), 0)
	truncatedAttribute := slices.Clone(valid)
	binary.BigEndian.PutUint16(truncatedAttribute[headerSize+2:headerSize+4], 64)
	zeroPort := testResponse(
		transactionID,
		testXORAddress(transactionID, netip.MustParseAddrPort("203.0.113.9:0")),
	)
	duplicateAddress := testResponse(transactionID, validAddress, validAddress)
	badFamily := testResponse(
		transactionID,
		testAttribute(attributeXORMappedAddress, []byte{0, 3, 0, 1, 1, 2, 3, 4}),
	)
	badReservedByte := testResponse(
		transactionID,
		testAttribute(attributeMappedAddress, []byte{1, 1, 0, 1, 1, 2, 3, 4}),
	)
	badFingerprint := testResponseWithFingerprint(transactionID, validAddress)
	badFingerprint[len(badFingerprint)-1] ^= 0xff
	fingerprintNotLast := testResponse(
		transactionID,
		testFingerprintAttribute(0),
		validAddress,
	)
	oversized := make([]byte, maxPacketSize+1)
	copy(oversized, valid)
	const oversizedAttributesLength uint16 = maxPacketSize + 1 - headerSize
	binary.BigEndian.PutUint16(oversized[2:4], oversizedAttributesLength)

	tests := []struct {
		name     string
		packet   []byte
		expected error
	}{
		{name: "short", packet: valid[:headerSize-1], expected: ErrNotMessage},
		{name: "wrong cookie", packet: wrongCookie, expected: ErrNotMessage},
		{name: "wrong response type", packet: wrongType, expected: ErrNotSuccessResponse},
		{name: "bad length alignment", packet: badLengthAlignment, expected: ErrMalformed},
		{name: "trailing byte", packet: trailingByte, expected: ErrMalformed},
		{name: "truncated attribute", packet: truncatedAttribute, expected: ErrMalformed},
		{name: "no mapped address", packet: testResponse(transactionID), expected: ErrNoMappedAddress},
		{name: "zero port", packet: zeroPort, expected: ErrMalformed},
		{name: "duplicate address", packet: duplicateAddress, expected: ErrMalformed},
		{name: "bad family", packet: badFamily, expected: ErrMalformed},
		{name: "bad reserved byte", packet: badReservedByte, expected: ErrMalformed},
		{name: "bad fingerprint", packet: badFingerprint, expected: ErrFingerprint},
		{name: "fingerprint not last", packet: fingerprintNotLast, expected: ErrMalformed},
		{name: "oversized", packet: oversized, expected: ErrMalformed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := ParseBindingResponse(test.packet)
			if !errors.Is(err, test.expected) {
				t.Fatalf("ParseBindingResponse() error = %v, want %v", err, test.expected)
			}
		})
	}
}

func FuzzParseBindingResponse(f *testing.F) {
	transactionID := TransactionID{1, 2, 3}
	f.Add(testResponse(
		transactionID,
		testXORAddress(transactionID, netip.MustParseAddrPort("203.0.113.10:41641")),
	))
	f.Add([]byte("not a message"))

	f.Fuzz(func(t *testing.T, packet []byte) {
		_, address, err := ParseBindingResponse(packet)
		if err != nil {
			return
		}
		if !address.IsValid() || address.Port() == 0 || address.Addr().Is4In6() ||
			address.Addr().Zone() != "" {
			t.Fatalf("ParseBindingResponse() accepted invalid address %v", address)
		}
	})
}

func testResponse(transactionID TransactionID, attributes ...[]byte) []byte {
	attributesLength := 0
	for _, attribute := range attributes {
		attributesLength += len(attribute)
	}
	packet := make([]byte, headerSize, headerSize+attributesLength)
	binary.BigEndian.PutUint16(packet[0:2], bindingSuccessType)
	binary.BigEndian.PutUint16(packet[2:4], checkedTestUint16Length(attributesLength))
	binary.BigEndian.PutUint32(packet[4:8], magicCookie)
	copy(packet[8:headerSize], transactionID[:])
	for _, attribute := range attributes {
		packet = append(packet, attribute...)
	}

	return packet
}

func testResponseWithFingerprint(transactionID TransactionID, attributes ...[]byte) []byte {
	attributes = append(attributes, make([]byte, 8))
	packet := testResponse(transactionID, attributes...)
	fingerprintStart := len(packet) - 8
	binary.BigEndian.PutUint16(packet[fingerprintStart:fingerprintStart+2], attributeFingerprint)
	binary.BigEndian.PutUint16(packet[fingerprintStart+2:fingerprintStart+4], 4)
	fingerprint := crc32.ChecksumIEEE(packet[:fingerprintStart]) ^ fingerprintMask
	binary.BigEndian.PutUint32(packet[fingerprintStart+4:], fingerprint)

	return packet
}

func testMappedAddress(address netip.AddrPort) []byte {
	value := testAddressValue(address)
	binary.BigEndian.PutUint16(value[2:4], address.Port())

	return testAttribute(attributeMappedAddress, value)
}

func testXORAddress(transactionID TransactionID, address netip.AddrPort) []byte {
	return testXORAddressWithType(attributeXORMappedAddress, transactionID, address)
}

func testXORAddressAlt(transactionID TransactionID, address netip.AddrPort) []byte {
	return testXORAddressWithType(attributeXORMappedAddressAlt, transactionID, address)
}

func testXORAddressWithType(
	attributeType uint16,
	transactionID TransactionID,
	address netip.AddrPort,
) []byte {
	value := testAddressValue(address)
	binary.BigEndian.PutUint16(value[2:4], address.Port()^uint16(magicCookie>>16))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], magicCookie)
	copy(mask[4:], transactionID[:])
	for index := 4; index < len(value); index++ {
		value[index] ^= mask[index-4]
	}

	return testAttribute(attributeType, value)
}

func testAddressValue(address netip.AddrPort) []byte {
	if address.Addr().Is4() {
		bytes := address.Addr().As4()

		return []byte{0, 1, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3]}
	}
	bytes := address.Addr().As16()
	value := make([]byte, 20)
	value[1] = 2
	copy(value[4:], bytes[:])

	return value
}

func testFingerprintAttribute(value uint32) []byte {
	attribute := make([]byte, 8)
	binary.BigEndian.PutUint16(attribute[0:2], attributeFingerprint)
	binary.BigEndian.PutUint16(attribute[2:4], 4)
	binary.BigEndian.PutUint32(attribute[4:8], value)

	return attribute
}

func testAttribute(attributeType uint16, value []byte) []byte {
	attribute := make([]byte, 4, 4+paddedLength(len(value)))
	binary.BigEndian.PutUint16(attribute[0:2], attributeType)
	binary.BigEndian.PutUint16(attribute[2:4], checkedTestUint16Length(len(value)))
	attribute = append(attribute, value...)
	for len(attribute)%4 != 0 {
		attribute = append(attribute, 0)
	}

	return attribute
}

func checkedTestUint16Length(length int) uint16 {
	if length < 0 || length > math.MaxUint16 {
		panic("test STUN length exceeds uint16")
	}

	return uint16(length)
}
