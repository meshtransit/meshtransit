//go:build windows

package windns

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/winadapter"
)

// The Network's search domains go on the MeshTransit adapter's own DNS
// search list (DNS design D5a), so a short name such as "poc-01" is tried
// under them; the NRPT rule then sends those names to MeshTransit. While the
// machine sets a search list of its own (a cloud image often does), Windows
// uses that one alone: the domains are then added at its end, and what was
// added is recorded so that only it is removed again. A search list Group
// Policy sets is never changed: short mesh names resolve only in full then.

// policySearchListKey holds a search list Group Policy sets.
const policySearchListKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`

// machineSearchListKey holds the machine's own search list.
const machineSearchListKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

// setSearchList puts domains on the adapter's search list for IPv4 and
// IPv6; none clears it. It reports false while the adapter does not exist.
func setSearchList(domains []string) (bool, error) {
	// The machine's list first: what an earlier run added goes even while
	// the adapter is gone.
	if err := mergeMachineSearchList(domains); err != nil {
		return true, err
	}
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

// addedSearchListKey records the domains MeshTransit added to the machine's
// own search list.
const (
	addedSearchListKey   = `SOFTWARE\MeshTransit\DNS`
	addedSearchListValue = "AddedSearchList"
)

// policySearchListSet reports a search list Group Policy sets, which
// Windows uses in place of every other.
func policySearchListSet() bool {
	return len(readSearchList(policySearchListKey)) != 0
}

// readSearchList reads the search list under base, comma separated.
func readSearchList(base string) []string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer func() { _ = key.Close() }()
	value, _, err := key.GetStringValue("SearchList")
	if err != nil {
		return nil
	}
	var domains []string
	for _, domain := range strings.Split(value, ",") {
		if domain = strings.TrimSpace(domain); domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}

// mergeMachineSearchList keeps domains at the end of the machine's own
// search list while it has one, and removes what MeshTransit added before
// that domains no longer hold; none removes every one of them.
func mergeMachineSearchList(domains []string) error {
	added := readAdded()
	current := readSearchList(machineSearchListKey)
	own := slices.DeleteFunc(slices.Clone(current), func(domain string) bool {
		return slices.ContainsFunc(added, func(other string) bool { return strings.EqualFold(other, domain) })
	})
	var next, recorded []string
	next = append(next, own...)
	if len(own) != 0 {
		// Only a list the machine sets itself is joined: without one, the
		// adapter's list is used.
		for _, domain := range domains {
			if !slices.ContainsFunc(next, func(other string) bool { return strings.EqualFold(other, domain) }) {
				next = append(next, domain)
				recorded = append(recorded, domain)
			}
		}
	}
	if !slices.Equal(next, current) {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, machineSearchListKey, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("windns: opening the machine search list: %w", err)
		}
		err = key.SetStringValue("SearchList", strings.Join(next, ","))
		_ = key.Close()
		if err != nil {
			return fmt.Errorf("windns: writing the machine search list: %w", err)
		}
	}
	return writeAdded(recorded)
}

func readAdded() []string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, addedSearchListKey, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer func() { _ = key.Close() }()
	values, _, err := key.GetStringsValue(addedSearchListValue)
	if err != nil {
		return nil
	}
	return values
}

func writeAdded(domains []string) error {
	if len(domains) == 0 {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, addedSearchListKey, registry.SET_VALUE)
		if err != nil {
			return nil
		}
		defer func() { _ = key.Close() }()
		if err := key.DeleteValue(addedSearchListValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("windns: forgetting the added search domains: %w", err)
		}
		return nil
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, addedSearchListKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("windns: recording the added search domains: %w", err)
	}
	defer func() { _ = key.Close() }()
	if err := key.SetStringsValue(addedSearchListValue, domains); err != nil {
		return fmt.Errorf("windns: recording the added search domains: %w", err)
	}
	return nil
}
