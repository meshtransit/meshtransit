package routesettings

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// How long a writer waits for the lock, and between tries.
const (
	lockWait  = 3 * time.Second
	lockPause = 10 * time.Millisecond
)

// lockSettings takes an exclusive lock on path.lock, beside the settings
// in their private directory, until the returned function releases it:
// meshd (for the operators and the apps) and an administrator's meshctl
// both write the settings, and neither may undo what the other just wrote.
// The lock file is never a link or junction: whoever replaced it would
// not get a write through it, but a missed lock would lose an update.
func lockSettings(path string) (func(), error) {
	name, err := windows.UTF16PtrFromString(path + ".lock")
	if err != nil {
		return nil, fmt.Errorf("routesettings: locking %s: %w", path, err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("routesettings: locking %s: %w", path, err)
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("routesettings: locking %s: %w", path, err)
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%w: lock file of %s", ErrUnsafeFile, path)
	}
	overlapped := new(windows.Overlapped)
	// A writer holds the lock for a read, a write and a rename: a lock held
	// past lockWait is a stuck writer, and this one gives up.
	deadline := time.Now().Add(lockWait)
	for {
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0,
			overlapped)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) || time.Now().After(deadline) {
			_ = windows.CloseHandle(handle)
			return nil, fmt.Errorf("routesettings: locking %s: %w", path, err)
		}
		time.Sleep(lockPause)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = windows.CloseHandle(handle)
	}, nil
}
