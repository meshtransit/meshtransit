//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"

	"meshtransit.net/client/internal/privatefile"
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := privatefile.RestrictDir(dir); err != nil {
		return nil, err
	}

	return os.OpenFile(serviceLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}
