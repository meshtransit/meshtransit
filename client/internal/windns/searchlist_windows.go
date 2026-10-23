//go:build windows

package windns

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/winadapter"
)

// The Network's search domains go on the MeshTransit adapter's own DNS
// search list (DNS design D5a), so a short name such as "poc-01" is tried
// under them; the NRPT rule then sends those names to MeshTransit. The
// machine's own search list is never changed: while Group Policy or the
// machine sets one, Windows uses it alone and the adapter's is not used.

// policySearchListKey holds a search list Group Policy sets.
const policySearchListKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`

// machineSearchListKey holds the machine's own search list.
const machineSearchListKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

// setSearchList puts domains on the adapter's search list for IPv4 and
// IPv6; none clears it. It reports false while the adapter does not exist.
func setSearchList(domains []string) (bool, error) {
	if _, ok := winadapter.LUID(); !ok {
		return false, nil
	}
	guid := winadapter.GUID
	list, err := windows.UTF16PtrFromString(strings.Join(domains, ","))
	if err != nil {
		return true, fmt.Errorf("windns: search list: %w", err)
	}
	var errs []error
	for _, flags := range []uint64{0, winipcfg.DnsInterfaceSettingsFlagIPv6} {
		settings := &winipcfg.DnsInterfaceSettings{
			Version:    winipcfg.DnsInterfaceSettingsVersion1,
			Flags:      winipcfg.DnsInterfaceSettingsFlagSearchList | flags,
			SearchList: list,
		}
		if err := winipcfg.SetInterfaceDnsSettings(guid, settings); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return true, fmt.Errorf("windns: setting the adapter search list: %w", err)
	}

	return true, nil
}

// machineSearchListSet reports a search list Group Policy or the machine
// sets, which Windows uses in place of the adapter's.
func machineSearchListSet() bool {
	for _, base := range []string{policySearchListKey, machineSearchListKey} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		value, _, err := key.GetStringValue("SearchList")
		_ = key.Close()
		if err == nil && strings.TrimSpace(value) != "" {
			return true
		}
	}

	return false
}
