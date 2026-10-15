//go:build windows

package peercred

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PipeCaller reads the access token of the client end of a connected named
// pipe by impersonating it: the token belongs to this connection, not to
// whatever process now has the client's PID (a PID can be reused, and a pipe
// handle can outlive or move away from the process that opened it). The
// client must connect with at least SECURITY_IDENTIFICATION; an anonymous
// client is refused. The pipe's security descriptor already limits who can
// connect; this is the per-request evidence the local API checks.
func PipeCaller(pipe windows.Handle) (Caller, error) {
	type result struct {
		caller Caller
		err    error
	}
	done := make(chan result, 1)
	// Impersonation applies to an OS thread, so it runs on a goroutine of its
	// own, locked to its thread. If reverting fails, that goroutine exits still
	// locked and the runtime discards the thread: no other goroutine ever runs
	// as the client.
	go func() {
		runtime.LockOSThread()
		caller, reverted, err := impersonatedCaller(pipe)
		if reverted {
			runtime.UnlockOSThread()
		}
		done <- result{caller: caller, err: err}
	}()
	outcome := <-done

	return outcome.caller, outcome.err
}

// impersonatedCaller reads the pipe client's token while impersonating it on
// the current, locked thread. reverted is false only when the thread may
// still impersonate the client.
func impersonatedCaller(pipe windows.Handle) (caller Caller, reverted bool, resultErr error) {
	if err := impersonateNamedPipeClient(pipe); err != nil {
		return Caller{}, true, fmt.Errorf("peercred: impersonating pipe client: %w", err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("peercred: reverting impersonation: %w", err))
			caller = Caller{}
			reverted = false
			return
		}
		reverted = true
	}()
	var token windows.Token
	// openAsSelf: open the token with the service's own rights, not the
	// impersonated client's.
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return Caller{}, false, fmt.Errorf("peercred: opening pipe client token: %w", err)
	}
	defer func() { _ = token.Close() }()
	level, err := impersonationLevel(token)
	if err != nil {
		return Caller{}, false, err
	}
	if level < windows.SecurityIdentification {
		return Caller{}, false, errors.New("peercred: pipe client is anonymous")
	}
	caller, err = tokenCaller(token)

	return caller, false, err
}

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func impersonateNamedPipeClient(pipe windows.Handle) error {
	if err := procImpersonateNamedPipeClient.Find(); err != nil {
		return err
	}
	result, _, err := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if result == 0 {
		return err
	}
	return nil
}

func impersonationLevel(token windows.Token) (uint32, error) {
	var level uint32
	var length uint32
	if err := windows.GetTokenInformation(token, windows.TokenImpersonationLevel,
		(*byte)(unsafe.Pointer(&level)), uint32(unsafe.Sizeof(level)), &length); err != nil { //nolint:gosec // TOKEN_INFORMATION output buffer.
		return 0, fmt.Errorf("peercred: reading pipe client impersonation level: %w", err)
	}
	return level, nil
}

func tokenCaller(token windows.Token) (Caller, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return Caller{}, fmt.Errorf("peercred: reading pipe client user: %w", err)
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return Caller{}, fmt.Errorf("peercred: reading pipe client groups: %w", err)
	}
	caller := Caller{UserSID: user.User.Sid.String()}
	for _, group := range groups.AllGroups() {
		caller.Groups = append(caller.Groups, Group{
			SID:     group.Sid.String(),
			Enabled: group.Attributes&windows.SE_GROUP_ENABLED != 0,
		})
	}
	if caller.UserSID == "" {
		return Caller{}, errors.New("peercred: pipe client has no user")
	}
	return caller, nil
}

// OperatorsSID returns the SID of the local operators group, or "" when the
// group does not exist (the installer has not created it).
func OperatorsSID() (string, error) {
	sid, _, _, err := windows.LookupSID("", OperatorsGroupName)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("peercred: looking up %s: %w", OperatorsGroupName, err)
	}

	return sid.String(), nil
}
