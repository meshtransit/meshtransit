package dataplane

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// utun kernel-control constants from <sys/sys_domain.h> and <net/if_utun.h>.
const (
	sysprotoControl = 2 // SYSPROTO_CONTROL
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
	// utunHeaderBytes is the address family utun puts before each packet.
	utunHeaderBytes = 4
)

// openInheritedTUN wraps the helper's utun descriptor in utunDevice.
//
// wireguard-go's own darwin TUN also watches a routing socket: it turns
// interface messages into up/down events and any routing socket error (such
// as a buffer overflow while routes churn at boot) into a TUN read error, and
// either stops the device or closes it. meshd brings the device up itself
// and only needs packets, as Linux's unmonitored TUN gives it.
func openInheritedTUN(descriptor int) (tun.Device, string, error) {
	name, err := unix.GetsockoptString(descriptor, sysprotoControl, utunOptIfname)
	if err != nil {
		return nil, "", fmt.Errorf("dataplane: reading utun name: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		return nil, "", errors.New("dataplane: invalid utun descriptor")
	}
	return &utunDevice{file: file, name: name, events: make(chan tun.Event)}, name, nil
}

// utunDevice reads and writes packets on a macOS utun descriptor. It never
// emits events; its MTU is read from the interface on demand.
type utunDevice struct {
	file      *os.File
	name      string
	events    chan tun.Event
	closeOnce sync.Once
	closeErr  error
}

func (t *utunDevice) File() *os.File { return t.file }

func (t *utunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < utunHeaderBytes {
		return 0, io.ErrShortBuffer
	}
	read, err := t.file.Read(bufs[0][offset-utunHeaderBytes:])
	if read <= utunHeaderBytes {
		return 0, err
	}
	sizes[0] = read - utunHeaderBytes
	return 1, err
}

func (t *utunDevice) Write(bufs [][]byte, offset int) (int, error) {
	if offset < utunHeaderBytes {
		return 0, io.ErrShortBuffer
	}
	for index, packet := range bufs {
		if len(packet) <= offset {
			return index, errors.New("dataplane: empty packet")
		}
		frame := packet[offset-utunHeaderBytes:]
		frame[0], frame[1], frame[2] = 0, 0, 0
		switch frame[utunHeaderBytes] >> 4 {
		case 4:
			frame[3] = unix.AF_INET
		case 6:
			frame[3] = unix.AF_INET6
		default:
			return index, unix.EAFNOSUPPORT
		}
		if _, err := t.file.Write(frame); err != nil {
			return index, err
		}
	}
	return len(bufs), nil
}

func (t *utunDevice) MTU() (int, error) {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(socket) }()
	request, err := unix.IoctlGetIfreqMTU(socket, t.name)
	if err != nil {
		return 0, fmt.Errorf("dataplane: reading %s mtu: %w", t.name, err)
	}
	return int(request.MTU), nil
}

func (t *utunDevice) Name() (string, error) { return t.name, nil }

func (t *utunDevice) Events() <-chan tun.Event { return t.events }

func (t *utunDevice) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.file.Close()
		close(t.events)
	})
	return t.closeErr
}

func (t *utunDevice) BatchSize() int { return 1 }
