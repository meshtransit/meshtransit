//go:build windows

package winadapter

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// GUID keeps one adapter identity across restarts, so Windows does not list a
// new network for every start.
var GUID = windows.GUID{
	Data1: 0x6d657368, Data2: 0x7472, Data3: 0x616e,
	Data4: [8]byte{0x73, 0x69, 0x74, 0x00, 0x00, 0x00, 0x00, 0x01},
}

// LUID returns the adapter's LUID, or false while the adapter does not exist.
func LUID() (uint64, bool) {
	guid := GUID
	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil || luid == 0 {
		return 0, false
	}

	return uint64(luid), true
}

// Index returns the adapter's interface index, the Index net.Interfaces
// reports, or false while the adapter does not exist.
func Index() (int, bool) {
	luid, ok := LUID()
	if !ok {
		return 0, false
	}
	row, err := winipcfg.LUID(luid).Interface()
	if err != nil || row.InterfaceIndex == 0 {
		return 0, false
	}

	return int(row.InterfaceIndex), true
}
