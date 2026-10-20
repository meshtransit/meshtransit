//go:build windows && (amd64 || arm64)

package winfw

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fwpuclnt                      = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0     = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0          = fwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderGetByKey0     = fwpuclnt.NewProc("FwpmProviderGetByKey0")
	procFwpmProviderDeleteByKey0  = fwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerAdd0          = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerGetByKey0     = fwpuclnt.NewProc("FwpmSubLayerGetByKey0")
	procFwpmSubLayerDeleteByKey0  = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterGetByKey0       = fwpuclnt.NewProc("FwpmFilterGetByKey0")
	procFwpmFilterDeleteByKey0    = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmGetAppIDFromFileName0 = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// fwpResult turns a WFP function's DWORD result into an error: these
// functions return their error code, they do not set the last error. Only
// the low 32 bits of the register are the result.
func fwpResult(code uintptr) error {
	result := uint32(code) //nolint:gosec // G115: a DWORD in a wider register.
	if result == 0 {
		return nil
	}
	return syscall.Errno(result)
}

// call runs proc. Pointers converted to uintptr in the call expression stay
// on the heap and alive until it returns (go:uintptrescapes), as for
// LazyProc.Call.
//
//go:uintptrescapes
func call(proc *windows.LazyProc, args ...uintptr) error {
	if err := proc.Find(); err != nil {
		return err
	}
	code, _, _ := proc.Call(args...)
	return fwpResult(code)
}

func fwpmEngineOpen0(session *fwpmSession0, engine *uintptr) error {
	return call(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0,
		uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(engine))) //nolint:gosec // G103: a syscall argument.
}

func fwpmEngineClose0(engine uintptr) error { return call(procFwpmEngineClose0, engine) }

func fwpmTransactionBegin0(engine uintptr) error { return call(procFwpmTransactionBegin0, engine, 0) }

func fwpmTransactionCommit0(engine uintptr) error { return call(procFwpmTransactionCommit0, engine) }

func fwpmTransactionAbort0(engine uintptr) error { return call(procFwpmTransactionAbort0, engine) }

func fwpmProviderAdd0(engine uintptr, provider *fwpmProvider0) error {
	return call(procFwpmProviderAdd0, engine, uintptr(unsafe.Pointer(provider)), 0) //nolint:gosec // G103: a syscall argument.
}

func fwpmSubLayerAdd0(engine uintptr, sublayer *fwpmSublayer0) error {
	return call(procFwpmSubLayerAdd0, engine, uintptr(unsafe.Pointer(sublayer)), 0) //nolint:gosec // G103: a syscall argument.
}

func fwpmFilterAdd0(engine uintptr, filter *fwpmFilter0) error {
	var id uint64
	return call(procFwpmFilterAdd0, engine, uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&id))) //nolint:gosec // G103: a syscall argument.
}

// exists reports whether getByKey finds the object of key; the object
// returned is freed.
func exists(getByKey *windows.LazyProc, engine uintptr, key *windows.GUID) (bool, error) {
	var object uintptr
	err := call(getByKey, engine, uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(&object))) //nolint:gosec // G103: a syscall argument.
	if err == nil {
		fwpmFreeMemory0(&object)
		return true, nil
	}
	if errors.Is(err, syscall.Errno(fwpErrorFilterNotFound)) || errors.Is(err, syscall.Errno(fwpErrorSublayerNotFound)) ||
		errors.Is(err, syscall.Errno(fwpErrorProviderNotFound)) {
		return false, nil
	}
	return false, err
}

func deleteByKey(proc *windows.LazyProc, engine uintptr, key *windows.GUID) error {
	return call(proc, engine, uintptr(unsafe.Pointer(key))) //nolint:gosec // G103: a syscall argument.
}

func fwpmGetAppIDFromFileName0(path *uint16, blob **fwpByteBlob) error {
	return call(procFwpmGetAppIDFromFileName0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(blob))) //nolint:gosec // G103: a syscall argument.
}

// fwpmFreeMemory0 frees what pointer points at and clears it.
func fwpmFreeMemory0[T any](pointer *T) {
	if procFwpmFreeMemory0.Find() != nil {
		return
	}
	_, _, _ = procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(pointer))) //nolint:gosec // G103: a syscall argument.
}
