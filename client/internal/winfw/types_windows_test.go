//go:build windows && (amd64 || arm64)

package winfw

import (
	"testing"
	"unsafe"
)

// The sizes and offsets of fwpmtypes.h on 64-bit Windows.
func TestLayoutsMatchWindows(t *testing.T) {
	var filter fwpmFilter0
	for _, check := range []struct {
		name      string
		got, want uintptr
	}{
		{"FWP_BYTE_BLOB", unsafe.Sizeof(fwpByteBlob{}), 16},
		{"FWP_VALUE0", unsafe.Sizeof(fwpValue0{}), 16},
		{"FWPM_FILTER_CONDITION0", unsafe.Sizeof(fwpmFilterCondition0{}), 40},
		{"FWPM_SESSION0", unsafe.Sizeof(fwpmSession0{}), 72},
		{"FWPM_PROVIDER0", unsafe.Sizeof(fwpmProvider0{}), 64},
		{"FWPM_SUBLAYER0", unsafe.Sizeof(fwpmSublayer0{}), 72},
		{"FWPM_FILTER0", unsafe.Sizeof(filter), 200},
		{"FWPM_FILTER0.weight", unsafe.Offsetof(filter.weight), 96},
		{"FWPM_FILTER0.action", unsafe.Offsetof(filter.action), 128},
		{"FWPM_FILTER0.providerContextKey", unsafe.Offsetof(filter.providerContextKey), 152},
		{"FWPM_FILTER0.filterID", unsafe.Offsetof(filter.filterID), 176},
		{"FWP_V6_ADDR_AND_MASK", unsafe.Sizeof(fwpV6AddrAndMask{}), 17},
	} {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.name, check.got, check.want)
		}
	}
}
