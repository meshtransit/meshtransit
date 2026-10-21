//go:build windows && (amd64 || arm64)

package winfw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The kill switch's objects have fixed keys ("meshtransit" in hex), so any
// run, or "meshd release-exit", finds and removes what an earlier one left.
var (
	providerKey = windows.GUID{
		Data1: 0x6d657368, Data2: 0x7472, Data3: 0x616e,
		Data4: [8]byte{0x73, 0x69, 0x74, 0x00, 0x00, 0xe7, 0x00, 0x01},
	}
	sublayerKey = windows.GUID{
		Data1: 0x6d657368, Data2: 0x7472, Data3: 0x616e,
		Data4: [8]byte{0x73, 0x69, 0x74, 0x00, 0x00, 0xe7, 0x00, 0x02},
	}
)

// transactionWait bounds how long a change waits for another transaction
// of the filter engine: the service's adapter changes wait behind it.
const transactionWait = 10_000 // milliseconds

// filterKey is the key of the kill switch's filter at index, below
// maximumRules.
func filterKey(index int) windows.GUID {
	return windows.GUID{
		Data1: 0x6d657368, Data2: 0x7472, Data3: 0x616e,
		Data4: [8]byte{0x73, 0x69, 0x74, 0x00, 0xe7, 0xf1, 0x00, byte(index % maximumRules)}, //nolint:gosec // G115: below 32
	}
}

// Enable installs, or replaces in one transaction, the kill switch of
// config: there is no moment without it once it is in place.
func Enable(config Config) error {
	rules := Rules(config)
	if len(rules) > maximumRules {
		return fmt.Errorf("winfw: %d filters exceed %d", len(rules), maximumRules)
	}
	appID, err := serviceAppID()
	if err != nil {
		return err
	}
	defer fwpmFreeMemory0(&appID)
	system, err := systemDescriptor()
	if err != nil {
		return err
	}
	return transact(func(engine uintptr) error {
		if err := ensureBase(engine); err != nil {
			return err
		}
		if err := deleteFilters(engine); err != nil {
			return err
		}
		for index, rule := range rules {
			if err := addFilter(engine, index, rule, appID, system); err != nil {
				return fmt.Errorf("winfw: adding %q: %w", rule.Name, err)
			}
		}
		return nil
	})
}

// Disable removes the kill switch, whatever run installed it.
func Disable() error {
	return transact(func(engine uintptr) error {
		if err := deleteFilters(engine); err != nil {
			return err
		}
		for _, object := range []struct {
			get, remove *windows.LazyProc
			key         *windows.GUID
		}{
			{procFwpmSubLayerGetByKey0, procFwpmSubLayerDeleteByKey0, &sublayerKey},
			{procFwpmProviderGetByKey0, procFwpmProviderDeleteByKey0, &providerKey},
		} {
			found, err := exists(object.get, engine, object.key)
			if err != nil {
				return err
			}
			if found {
				if err := deleteByKey(object.remove, engine, object.key); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Installed reports whether any filter of a kill switch is in place.
func Installed() (bool, error) {
	installed := false
	err := transact(func(engine uintptr) error {
		for index := range maximumRules {
			key := filterKey(index)
			found, err := exists(procFwpmFilterGetByKey0, engine, &key)
			if err != nil || found {
				installed = found
				return err
			}
		}
		return nil
	})
	return installed, err
}

// transact runs operation in one WFP transaction of a session whose
// objects outlive it.
func transact(operation func(engine uintptr) error) error {
	name, description := display("MeshTransit", "MeshTransit exit kill switch")
	session := fwpmSession0{
		displayData:          fwpmDisplayData0{name: name, description: description},
		txnWaitTimeoutInMSec: transactionWait,
	}
	var engine uintptr
	if err := fwpmEngineOpen0(&session, &engine); err != nil {
		return fmt.Errorf("winfw: opening the filter engine: %w", err)
	}
	defer func() { _ = fwpmEngineClose0(engine) }()
	if err := fwpmTransactionBegin0(engine); err != nil {
		return fmt.Errorf("winfw: beginning a transaction: %w", err)
	}
	if err := operation(engine); err != nil {
		return errors.Join(err, fwpmTransactionAbort0(engine))
	}
	if err := fwpmTransactionCommit0(engine); err != nil {
		return errors.Join(fmt.Errorf("winfw: committing: %w", err), fwpmTransactionAbort0(engine))
	}
	return nil
}

// ensureBase adds the provider and sublayer unless they are in place.
func ensureBase(engine uintptr) error {
	name, description := display("MeshTransit", "MeshTransit exit kill switch")
	found, err := exists(procFwpmProviderGetByKey0, engine, &providerKey)
	if err != nil {
		return fmt.Errorf("winfw: reading the provider: %w", err)
	}
	if !found {
		provider := fwpmProvider0{
			providerKey: providerKey, flags: fwpmProviderFlagPersistent,
			displayData: fwpmDisplayData0{name: name, description: description},
		}
		if err := fwpmProviderAdd0(engine, &provider); err != nil {
			return fmt.Errorf("winfw: adding the provider: %w", err)
		}
	}
	found, err = exists(procFwpmSubLayerGetByKey0, engine, &sublayerKey)
	if err != nil {
		return fmt.Errorf("winfw: reading the sublayer: %w", err)
	}
	if !found {
		sublayer := fwpmSublayer0{
			subLayerKey: sublayerKey, flags: fwpmSublayerFlagPersistent, providerKey: &providerKey,
			displayData: fwpmDisplayData0{name: name, description: description}, weight: ^uint16(0),
		}
		if err := fwpmSubLayerAdd0(engine, &sublayer); err != nil {
			return fmt.Errorf("winfw: adding the sublayer: %w", err)
		}
	}
	return nil
}

// deleteFilters removes every filter a kill switch may have installed.
func deleteFilters(engine uintptr) error {
	for index := range maximumRules {
		key := filterKey(index)
		found, err := exists(procFwpmFilterGetByKey0, engine, &key)
		if err != nil {
			return fmt.Errorf("winfw: reading filter %d: %w", index, err)
		}
		if !found {
			continue
		}
		if err := deleteByKey(procFwpmFilterDeleteByKey0, engine, &key); err != nil {
			return fmt.Errorf("winfw: removing filter %d: %w", index, err)
		}
	}
	return nil
}

// addFilter installs rule as the filter at index.
func addFilter(engine uintptr, index int, rule Rule, appID *fwpByteBlob, system []byte) error {
	var keep []any
	conditions := make([]fwpmFilterCondition0, 0, 8)
	add := func(field windows.GUID, match fwpMatchType, kind fwpDataType, value uintptr) {
		conditions = append(conditions, fwpmFilterCondition0{
			fieldKey: field, matchType: match, conditionValue: fwpValue0{kind: kind, value: value},
		})
	}
	if rule.Service {
		add(conditionALEAppID, fwpMatchEqual, fwpByteBlobType, uintptr(unsafe.Pointer(appID))) //nolint:gosec // G103: WFP keeps no reference past the call.
		descriptor := &fwpByteBlob{size: uint32(len(system)), data: &system[0]}                //nolint:gosec // G115: a small descriptor
		keep = append(keep, descriptor)
		add(conditionALEUserID, fwpMatchEqual, fwpSecurityDescriptorType, uintptr(unsafe.Pointer(descriptor))) //nolint:gosec // G103: WFP keeps no reference past the call.
	}
	if rule.Loopback {
		add(conditionFlags, fwpMatchFlagsAllSet, fwpUint32, fwpConditionFlagIsLoopback)
	}
	interfaceField, remoteField := conditionIPLocalInterface, conditionIPRemoteAddress
	if rule.Forward {
		interfaceField, remoteField = conditionIPForwardInterface, conditionIPDestinationAddress
	}
	for _, match := range []struct {
		field windows.GUID
		luid  uint64
	}{
		{interfaceField, rule.Adapter},
		{conditionIPPhysicalArrivalInterface, rule.Arrival},
		{conditionIPLocalInterface, rule.ArrivalLocal},
	} {
		if match.luid == 0 {
			continue
		}
		luid := new(uint64)
		*luid = match.luid
		keep = append(keep, luid)
		add(match.field, fwpMatchEqual, fwpUint64, uintptr(unsafe.Pointer(luid))) //nolint:gosec // G103: WFP keeps no reference past the call.
	}
	if rule.Protocol != 0 {
		add(conditionIPProtocol, fwpMatchEqual, fwpUint8, uintptr(rule.Protocol))
	}
	if rule.LocalPort != 0 {
		add(conditionIPLocalPort, fwpMatchEqual, fwpUint16, uintptr(rule.LocalPort))
	}
	if rule.RemotePort != 0 {
		add(conditionIPRemotePort, fwpMatchEqual, fwpUint16, uintptr(rule.RemotePort))
	}
	if rule.MatchICMP {
		add(conditionICMPType, fwpMatchEqual, fwpUint16, uintptr(rule.ICMPType))
	}
	for _, prefix := range rule.Remote {
		if prefix.Addr().Is4() {
			address := prefix.Addr().As4()
			mask := uint32(0)
			if prefix.Bits() > 0 {
				mask = ^uint32(0) << (32 - prefix.Bits())
			}
			value := &fwpV4AddrAndMask{addr: binary.BigEndian.Uint32(address[:]), mask: mask}
			keep = append(keep, value)
			add(remoteField, fwpMatchEqual, fwpV4AddrMask, uintptr(unsafe.Pointer(value))) //nolint:gosec // G103: WFP keeps no reference past the call.
			continue
		}
		value := &fwpV6AddrAndMask{addr: prefix.Addr().As16(), prefixLength: uint8(prefix.Bits())} //nolint:gosec // G115: at most 128
		keep = append(keep, value)
		add(remoteField, fwpMatchEqual, fwpV6AddrMask, uintptr(unsafe.Pointer(value))) //nolint:gosec // G103: WFP keeps no reference past the call.
	}
	name, description := display(rule.Name, "MeshTransit exit kill switch")
	layer := layerALEAuthConnectV4
	switch {
	case rule.Forward && rule.IPv6:
		layer = layerIPForwardV6
	case rule.Forward:
		layer = layerIPForwardV4
	case rule.IPv6:
		layer = layerALEAuthConnectV6
	}
	action := fwpActionPermit
	if rule.Block {
		action = fwpActionBlock
	}
	filter := fwpmFilter0{
		filterKey:   filterKey(index),
		displayData: fwpmDisplayData0{name: name, description: description},
		flags:       fwpmFilterFlagPersistent,
		providerKey: &providerKey,
		layerKey:    layer,
		subLayerKey: sublayerKey,
		weight:      fwpValue0{kind: fwpUint8, value: uintptr(rule.Weight)},
		action:      fwpmAction0{kind: action},
	}
	if len(conditions) > 0 {
		filter.numFilterConditions = uint32(len(conditions)) //nolint:gosec // G115: a few conditions
		filter.filterCondition = &conditions[0]
	}
	err := fwpmFilterAdd0(engine, &filter)
	runtime.KeepAlive(keep)
	runtime.KeepAlive(conditions)
	runtime.KeepAlive(system)
	return err
}

// serviceAppID is the application ID of the running executable, the
// service's.
func serviceAppID() (*fwpByteBlob, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("winfw: locating the service executable: %w", err)
	}
	path, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, fmt.Errorf("winfw: service path: %w", err)
	}
	var blob *fwpByteBlob
	if err := fwpmGetAppIDFromFileName0(path, &blob); err != nil {
		return nil, fmt.Errorf("winfw: application ID of %s: %w", executable, err)
	}
	return blob, nil
}

// systemDescriptor is a self-relative security descriptor matching
// LocalSystem, the service's account: the executable run by a user does not
// match.
func systemDescriptor() ([]byte, error) {
	sid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("winfw: LocalSystem SID: %w", err)
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fwpActrlMatchFilter,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return nil, fmt.Errorf("winfw: access list: %w", err)
	}
	descriptor, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, fmt.Errorf("winfw: security descriptor: %w", err)
	}
	if err := descriptor.SetDACL(dacl, true, false); err != nil {
		return nil, fmt.Errorf("winfw: security descriptor access list: %w", err)
	}
	relative, err := descriptor.ToSelfRelative()
	if err != nil {
		return nil, fmt.Errorf("winfw: self-relative descriptor: %w", err)
	}
	length := relative.Length()
	// A copy: the descriptor is the bytes of a self-relative SECURITY_DESCRIPTOR.
	return slices.Clone(unsafe.Slice((*byte)(unsafe.Pointer(relative)), length)), nil //nolint:gosec // G103: length bytes.
}

// display returns UTF-16 copies of a name and description; text with a NUL
// gives empty ones.
func display(name, description string) (*uint16, *uint16) {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		namePointer = new(uint16)
	}
	descriptionPointer, err := windows.UTF16PtrFromString(description)
	if err != nil {
		descriptionPointer = new(uint16)
	}
	return namePointer, descriptionPointer
}
