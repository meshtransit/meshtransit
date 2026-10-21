//go:build windows && (amd64 || arm64)

// The WFP types below follow fwptypes.h and fwpmtypes.h as transcribed by
// wireguard-windows (tunnel/firewall, MIT licence, Copyright (C) 2019-2021
// WireGuard LLC), for 64-bit Windows.

package winfw

import "golang.org/x/sys/windows"

type fwpActionType uint32

const (
	fwpActionFlagTerminating               = 0x00001000
	fwpActionBlock           fwpActionType = 0x00000001 | fwpActionFlagTerminating
	fwpActionPermit          fwpActionType = 0x00000002 | fwpActionFlagTerminating
)

type fwpMatchType uint32

const (
	fwpMatchEqual       fwpMatchType = 0
	fwpMatchFlagsAllSet fwpMatchType = 6
)

type fwpDataType uint32

const (
	fwpUint8                  fwpDataType = 1
	fwpUint16                 fwpDataType = 2
	fwpUint32                 fwpDataType = 3
	fwpUint64                 fwpDataType = 4
	fwpByteBlobType           fwpDataType = 12
	fwpSecurityDescriptorType fwpDataType = 14
	fwpV4AddrMask             fwpDataType = 0x100
	fwpV6AddrMask             fwpDataType = 0x101
)

const (
	fwpConditionFlagIsLoopback = 0x00000001
	fwpmFilterFlagPersistent   = 0x00000001
	fwpmProviderFlagPersistent = 0x00000001
	fwpmSublayerFlagPersistent = 0x00000001
	rpcCAuthnWinNT             = 10
	// fwpActrlMatchFilter is the access right a user ID condition's
	// security descriptor grants to the users it matches.
	fwpActrlMatchFilter = 1
)

// WFP error codes (fwpmu.h) the kill switch expects.
const (
	fwpErrorFilterNotFound   = 0x80320003
	fwpErrorProviderNotFound = 0x80320005
	fwpErrorSublayerNotFound = 0x80320007
)

type fwpByteBlob struct {
	size uint32
	data *uint8
}

type fwpValue0 struct {
	kind  fwpDataType
	value uintptr
}

type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]uint8
	prefixLength uint8
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      fwpMatchType
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	kind       fwpActionType
	filterType windows.GUID
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           uint8
}

type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   [4]byte // the union below is 8-byte aligned
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// Layers and conditions (fwpmu.h).
var (
	layerALEAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	layerALEAuthConnectV6 = windows.GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
	// FWPM_LAYER_IPFORWARD_V4/V6, FWPM_CONDITION_IP_FORWARD_INTERFACE and
	// FWPM_CONDITION_IP_DESTINATION_ADDRESS (fwpmu.h).
	layerIPForwardV4 = windows.GUID{
		Data1: 0xa82acc24, Data2: 0x4ee1, Data3: 0x4ee1,
		Data4: [8]byte{0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4},
	}
	layerIPForwardV6 = windows.GUID{
		Data1: 0x7b964818, Data2: 0x19c7, Data3: 0x493a,
		Data4: [8]byte{0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c},
	}
	conditionIPForwardInterface = windows.GUID{
		Data1: 0x1076b8a5, Data2: 0x6323, Data3: 0x4c5e,
		Data4: [8]byte{0x98, 0x10, 0xe8, 0xd3, 0xfc, 0x9e, 0x61, 0x36},
	}
	conditionIPDestinationAddress = windows.GUID{
		Data1: 0x2d79133b, Data2: 0xb390, Data3: 0x45c6,
		Data4: [8]byte{0x86, 0x99, 0xac, 0xac, 0xea, 0xaf, 0xed, 0x33},
	}
	// FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE (fwpmu.h).
	conditionIPPhysicalArrivalInterface = windows.GUID{
		Data1: 0xda50d5c8, Data2: 0xfa0d, Data3: 0x4c89,
		Data4: [8]byte{0xb0, 0x32, 0x6e, 0x62, 0x13, 0x6d, 0x1e, 0x96},
	}
	conditionIPLocalInterface = windows.GUID{
		Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969,
		Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4},
	}
	conditionIPRemoteAddress = windows.GUID{
		Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}
	conditionIPProtocol = windows.GUID{
		Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
	}
	conditionIPLocalPort = windows.GUID{
		Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f,
		Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
	}
	conditionIPRemotePort = windows.GUID{
		Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
	conditionALEAppID = windows.GUID{
		Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5,
		Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
	}
	conditionALEUserID = windows.GUID{
		Data1: 0xaf043a0a, Data2: 0xb34d, Data3: 0x4f86,
		Data4: [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66},
	}
	conditionFlags = windows.GUID{
		Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c,
		Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c},
	}
	// The ICMP type is matched as the local port.
	conditionICMPType = conditionIPLocalPort
)
