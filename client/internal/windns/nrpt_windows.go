//go:build windows

package windns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// localPolicyKey holds NRPT rules set on this machine.
	localPolicyKey = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// groupPolicyKey holds NRPT rules from Group Policy. While it exists, even
	// empty, the DNS client ignores every rule under localPolicyKey.
	groupPolicyKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// ruleKeyName names MeshTransit's rule under either key.
	ruleKeyName = `{6D657368-7472-616E-7369-74000000D053}`

	ruleVersion = 2
	// configGenericDNSServers tells the DNS client to use GenericDNSServers.
	configGenericDNSServers = 0x8
	ruleComment             = "MeshTransit"
)

var (
	dnsapi                    = windows.NewLazySystemDLL("dnsapi.dll")
	userenv                   = windows.NewLazySystemDLL("userenv.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
	procRefreshPolicyEx       = userenv.NewProc("RefreshPolicyEx")
)

// groupPolicyPresent reports whether Group Policy NRPT is in force.
func groupPolicyPresent() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, groupPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = key.Close()

	return true
}

func writeRule(base string, rule Rule) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, base+`\`+ruleKeyName, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("windns: creating NRPT rule: %w", err)
	}
	defer func() { _ = key.Close() }()
	errs := []error{
		key.SetDWordValue("Version", ruleVersion),
		key.SetStringsValue("Name", rule.Namespaces),
		key.SetStringValue("GenericDNSServers", rule.Server.String()),
		key.SetDWordValue("ConfigOptions", configGenericDNSServers),
		key.SetStringValue("IPSECCARestriction", ""),
		key.SetStringValue("Comment", ruleComment),
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("windns: writing NRPT rule: %w", err)
	}

	return nil
}

// readRule returns the rule stored under base, if any.
func readRule(base string) (Rule, bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+ruleKeyName, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return Rule{}, false, nil
	}
	if err != nil {
		return Rule{}, false, fmt.Errorf("windns: opening NRPT rule: %w", err)
	}
	defer func() { _ = key.Close() }()
	namespaces, _, err := key.GetStringsValue("Name")
	if err != nil {
		return Rule{}, true, fmt.Errorf("windns: reading NRPT rule names: %w", err)
	}
	server, _, err := key.GetStringValue("GenericDNSServers")
	if err != nil {
		return Rule{}, true, fmt.Errorf("windns: reading NRPT rule server: %w", err)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(server))
	if err != nil {
		return Rule{}, true, nil
	}
	slices.Sort(namespaces)

	return Rule{Namespaces: namespaces, Server: address}, true, nil
}

func deleteRule(base string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, base+`\`+ruleKeyName)
	if err == nil || errors.Is(err, registry.ErrNotExist) {
		return nil
	}

	return fmt.Errorf("windns: removing NRPT rule: %w", err)
}

// reloadPolicy makes the DNS client use the rules now in the registry. It
// watches the local key itself; the flush drops answers cached under the
// previous rules. Rules under the Group Policy key are read when machine
// policy is applied, so that case also asks for a policy refresh. The refresh
// is not forced: extensions whose settings did not change do not run.
func reloadPolicy(groupPolicy bool) error {
	if groupPolicy {
		if ok, _, err := procRefreshPolicyEx.Call(1, 0); ok == 0 {
			return fmt.Errorf("windns: refreshing machine policy: %w", err)
		}
	}
	if ok, _, err := procDnsFlushResolverCache.Call(); ok == 0 {
		return fmt.Errorf("windns: flushing the DNS cache: %w", err)
	}

	return nil
}
