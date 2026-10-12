//go:build windows

package peercred

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// PipeCaller reads the access token of the process at the client end of a
// connected named pipe. The pipe's security descriptor already limits who
// can connect; this is the per-request evidence the local API checks.
func PipeCaller(pipe windows.Handle) (Caller, error) {
	var processID uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &processID); err != nil {
		return Caller{}, fmt.Errorf("peercred: reading pipe client process: %w", err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return Caller{}, fmt.Errorf("peercred: opening pipe client process: %w", err)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return Caller{}, fmt.Errorf("peercred: opening pipe client token: %w", err)
	}
	defer func() { _ = token.Close() }()

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
