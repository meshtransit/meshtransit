//go:build windows

package localapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// dialer connects to meshd's named pipe and requires SYSTEM, which runs the
// service, to own it, so meshctl never talks to an impostor pipe. It opens
// the pipe at the identification impersonation level: meshd reads this
// connection's own token from it, and the level does not let meshd act as
// the caller.
func dialer(socketPath string, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		return dialPipe(dialCtx, socketPath)
	}
}

// pipeOpenFlags open the pipe for overlapped I/O, so the file has deadlines,
// and let the server identify, never impersonate, this client.
const pipeOpenFlags = windows.FILE_FLAG_OVERLAPPED | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION

func dialPipe(ctx context.Context, path string) (net.Conn, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	for {
		handle, err = windows.CreateFile(path16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, pipeOpenFlags, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		// Every instance is busy: wait for one, as the namedpipe package does.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("localapi: every instance of pipe %s stayed busy: %w", path, ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := requireSystemOwner(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	// Since Go 1.25, NewFile takes an overlapped handle into the runtime's
	// I/O completion port, which gives the file deadlines.
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("localapi: wrapping pipe %s", path)
	}
	return &pipeConn{File: file, address: pipeAddress(path)}, nil
}

func requireSystemOwner(handle windows.Handle) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("localapi: building the SYSTEM SID: %w", err)
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("localapi: reading the pipe owner: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("localapi: reading the pipe owner: %w", err)
	}
	if !owner.Equals(system) {
		return fmt.Errorf("localapi: pipe is owned by %s, not SYSTEM", owner)
	}
	return nil
}

type pipeAddress string

func (address pipeAddress) Network() string { return "pipe" }
func (address pipeAddress) String() string  { return string(address) }

// pipeConn is a client pipe as a net.Conn.
type pipeConn struct {
	*os.File
	address pipeAddress
}

func (conn *pipeConn) LocalAddr() net.Addr  { return conn.address }
func (conn *pipeConn) RemoteAddr() net.Addr { return conn.address }
