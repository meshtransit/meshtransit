//go:build windows

package peercred

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// A client that lets the server identify it is read from its own token; an
// anonymous client is refused rather than read through its process ID.
func TestPipeCallerReadsTheConnectionsOwnToken(t *testing.T) {
	path := fmt.Sprintf(`\\.\pipe\meshtransit-peercred-test-%d`, os.Getpid())
	listener, err := (&namedpipe.ListenConfig{}).Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	process := windows.GetCurrentProcessToken()
	self, err := process.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	for name, flags := range map[string]uint32{
		"identification": windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION,
		"anonymous":      windows.SECURITY_SQOS_PRESENT | windows.SECURITY_ANONYMOUS,
	} {
		t.Run(name, func(t *testing.T) {
			accepted := make(chan net.Conn, 1)
			go func() {
				connection, err := listener.Accept()
				if err == nil {
					accepted <- connection
				}
			}()
			path16, _ := windows.UTF16PtrFromString(path)
			var client windows.Handle
			for attempt := 0; ; attempt++ {
				client, err = windows.CreateFile(path16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
					windows.OPEN_EXISTING, flags, 0)
				if err == nil {
					break
				}
				if !errors.Is(err, windows.ERROR_PIPE_BUSY) || attempt == 500 {
					t.Fatal(err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			defer func() { _ = windows.CloseHandle(client) }()
			var server net.Conn
			select {
			case server = <-accepted:
			case <-time.After(5 * time.Second):
				t.Fatal("no connection accepted")
			}
			defer func() { _ = server.Close() }()
			// The client has not written yet: identification does not wait
			// for the request.
			pipe, ok := server.(interface{ Handle() windows.Handle })
			if !ok {
				t.Fatalf("accepted %T, not a pipe", server)
			}
			handle := pipe.Handle()
			caller, err := PipeCaller(handle)
			if name == "anonymous" {
				if err == nil {
					t.Fatalf("an anonymous client was identified as %s", caller.UserSID)
				}
				return
			}
			if err != nil || caller.UserSID != self.User.Sid.String() || len(caller.Groups) == 0 {
				t.Fatalf("PipeCaller = %+v, %v; want %s", caller, err, self.User.Sid)
			}
		})
	}
}
