//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"meshtransit.net/client/internal/privatefile"
	"meshtransit.net/client/internal/routesettings/routescli"
	"meshtransit.net/client/internal/windns"
	"meshtransit.net/client/internal/winfw"
)

const (
	// serviceName is the Windows service the installer registers.
	serviceName = "MeshTransit"
	// serviceLogPath receives meshd's log while it runs as a service, which
	// has no console.
	serviceLogPath = `C:\ProgramData\MeshTransit\logs\meshd.log`
)

// entry runs meshd under the Windows service manager when it starts it, and
// in the foreground otherwise (for debugging from an elevated console).
func entry(args []string) int {
	if len(args) > 0 && args[0] == "routes" {
		// Windows has no helper: the service binary edits the subnet route
		// settings it reads, from an elevated console.
		command := routescli.Command{Program: "meshd", Privilege: "administrator rights", Privileged: elevated}
		return command.Run(args[1:], os.Stdout, os.Stderr)
	}
	if len(args) > 0 && args[0] == "release-exit" {
		return releaseExit(args[1:], os.Stdout, os.Stderr)
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "meshd: detecting the service manager: %v\n", err)

		return 1
	}
	if !isService {
		return run(args, os.Stdout, os.Stderr)
	}
	handler := &serviceHandler{args: args}
	if err := svc.Run(serviceName, handler); err != nil {
		return 1
	}

	return int(handler.exitCode)
}

// releaseExit lifts the exit kill switch and the DNS rule any run left: the
// way out for an administrator whose host the kill switch keeps closed
// (exit node design §6.4). It does not change the settings: a running
// service applies them again within seconds, so stop the service or turn
// exit-use off first.
func releaseExit(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: meshd release-exit")

		return 2
	}
	if !elevated() {
		_, _ = fmt.Fprintln(stderr, "meshd: release-exit needs administrator rights")

		return 1
	}
	if err := errors.Join(winfw.Disable(), windns.RemoveRule()); err != nil {
		_, _ = fmt.Fprintf(stderr, "meshd: releasing the exit route: %v\n", err)

		return 1
	}
	_, _ = fmt.Fprintln(stdout, "The exit kill switch and DNS rule are removed.")

	return 0
}

// elevated reports whether meshd runs with an administrator's full token.
func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// serviceHandler adapts meshd to the service control protocol: it reports
// running once started and cancels meshd on stop or shutdown.
type serviceHandler struct {
	args     []string
	exitCode uint32
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	logFile, err := openServiceLog()
	if err != nil {
		h.exitCode = 1

		return true, h.exitCode
	}
	defer func() { _ = logFile.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- runContext(ctx, h.args, logFile, logFile) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case code := <-done:
			h.exitCode = uint32(code) //nolint:gosec // Exit codes are small and non-negative.

			return code != 0, h.exitCode
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		}
	}
}

// openServiceLog appends to the service log in a directory only SYSTEM and
// Administrators can read.
func openServiceLog() (*os.File, error) {
	dir := filepath.Dir(serviceLogPath)
	// The data directory first: only the last directory of a path is created.
	// Restricting it also closes a directory an older meshd left open to
	// users, before anything else is created in it.
	for _, path := range []string{filepath.Dir(dir), dir} {
		if err := privatefile.PrepareDir(path, 0o700); err != nil {
			return nil, err
		}
		if err := privatefile.RestrictDir(path); err != nil {
			return nil, err
		}
	}
	logs, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = logs.Close() }()

	return openPrivateLog(logs, serviceLogPath)
}

// openPrivateLog opens name in root for appending. A log an older meshd left
// in a directory users could write may have been replaced by a link to
// another file, which meshd would then write to as SYSTEM, or created by a
// user who can still read and change it: a name that is a link, a reparse
// point, a file with other hard links or a file beyond SYSTEM and
// Administrators is removed and the log started afresh.
func openPrivateLog(root *os.Root, path string) (*os.File, error) {
	const appendFlags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	name := filepath.Base(path)
	if info, err := root.Lstat(name); err == nil && info.Mode().IsRegular() {
		file, err := root.OpenFile(name, appendFlags, 0o600)
		if err == nil {
			if isPlainFile(file) && privatefile.CheckFile(path, info) == nil {
				return file, nil
			}
			_ = file.Close()
		}
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing a linked service log: %w", err)
	}

	return root.OpenFile(name, appendFlags|os.O_EXCL, 0o600)
}

// isPlainFile reports an ordinary file with no other name.
func isPlainFile(file *os.File) bool {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return false
	}

	return info.NumberOfLinks == 1 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
