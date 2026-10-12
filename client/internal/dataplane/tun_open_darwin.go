package dataplane

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

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

// inheritedTUNOpenerFor opens utun descriptors that report empty-read
// episodes to logger.
func inheritedTUNOpenerFor(logger *slog.Logger) inheritedTUNOpener {
	return func(descriptor int) (tun.Device, string, error) {
		return openUTUN(descriptor, logger)
	}
}

// openUTUN wraps the helper's utun descriptor in utunDevice.
//
// wireguard-go's own darwin TUN also watches a routing socket: it turns
// interface messages into up/down events and any routing socket error (such
// as a buffer overflow while routes churn at boot) into a TUN read error, and
// either stops the device or closes it. meshd brings the device up itself
// and only needs packets, as Linux's unmonitored TUN gives it.
func openUTUN(descriptor int, logger *slog.Logger) (tun.Device, string, error) {
	name, err := unix.GetsockoptString(descriptor, sysprotoControl, utunOptIfname)
	if err != nil {
		return nil, "", fmt.Errorf("dataplane: reading utun name: %w", err)
	}
	// Nonblocking, so the Go poller waits on kqueue and a read never sleeps
	// in the kernel, as wireguard-go's own darwin TUN reads utun.
	if err := unix.SetNonblock(descriptor, true); err != nil {
		return nil, "", fmt.Errorf("dataplane: setting utun nonblocking: %w", err)
	}
	if receiveShut(descriptor) {
		if logger != nil {
			logger.Warn("utun arrived with its receive side shut", "interface", name)
		}
		return nil, "", errTUNReceiveShut
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		return nil, "", errors.New("dataplane: invalid utun descriptor")
	}
	return &utunDevice{
		file: file, name: name, events: make(chan tun.Event), opened: time.Now(), logger: logger,
	}, name, nil
}

// utunDevice reads and writes packets on a macOS utun descriptor. It never
// emits events; its MTU is read from the interface on demand.
type utunDevice struct {
	file      *os.File
	name      string
	events    chan tun.Event
	closeOnce sync.Once
	closeErr  error
	opened    time.Time
	packets   atomic.Uint64
	// emptyReads counts the empty reads skipped; isAttached replaces the
	// kernel check in tests.
	emptyReads atomic.Uint64
	isAttached func() bool
	// logger, when set, records empty-read episodes the device rode out.
	logger *slog.Logger
	// emptyReadGrace and emptyReadPause override the defaults in tests.
	emptyReadGrace time.Duration
	emptyReadPause time.Duration
}

func (t *utunDevice) File() *os.File { return t.file }

// Around boot and network changes macOS can make a fresh utun read empty,
// over and over, for a while, although the descriptor is still the utun and
// the link exists. WireGuard takes an empty read as EOF and closes the device,
// and a rebuilt device hits the same window. Read rides it out instead.
const (
	defaultEmptyReadGrace = 10 * time.Second
	defaultEmptyReadPause = 20 * time.Millisecond
)

func (t *utunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < utunHeaderBytes {
		return 0, io.ErrShortBuffer
	}
	grace, pause := t.emptyReadGrace, t.emptyReadPause
	if grace == 0 {
		grace = defaultEmptyReadGrace
	}
	if pause == 0 {
		pause = defaultEmptyReadPause
	}
	var emptySince time.Time
	var empties uint64
	for {
		read, err := t.file.Read(bufs[0][offset-utunHeaderBytes:])
		if read == 0 && (err == nil || errors.Is(err, io.EOF)) {
			if emptySince.IsZero() {
				emptySince = time.Now()
			}
			if time.Since(emptySince) < grace && t.attached() {
				empties++
				t.emptyReads.Add(1)
				time.Sleep(pause)
				continue
			}
			return 0, t.emptyReadError()
		}
		if !emptySince.IsZero() && t.logger != nil {
			t.logger.Info("utun empty reads ended", "interface", t.name, "empty_reads", empties,
				"duration", time.Since(emptySince).Round(time.Millisecond),
				"device_age", time.Since(t.opened).Round(time.Millisecond))
		}
		if read <= utunHeaderBytes {
			return 0, err
		}
		t.packets.Add(1)
		sizes[0] = read - utunHeaderBytes
		return 1, err
	}
}

// attached reports whether the descriptor is still this utun and its link
// still exists.
func (t *utunDevice) attached() bool {
	if t.isAttached != nil {
		return t.isAttached()
	}
	_, socketMatches, _ := t.describeSocket()
	if !socketMatches {
		return false
	}
	_, err := net.InterfaceByName(t.name)
	return err == nil
}

// describeSocket reads the utun name the descriptor answers with.
func (t *utunDevice) describeSocket() (string, bool, error) {
	raw, err := t.file.SyscallConn()
	if err != nil {
		return "", false, err
	}
	var name string
	var nameErr error
	if err := raw.Control(func(descriptor uintptr) {
		name, nameErr = unix.GetsockoptString(int(descriptor), sysprotoControl, utunOptIfname)
	}); err != nil {
		return "", false, err
	}
	if nameErr != nil {
		return "", false, nameErr
	}
	return name, name == t.name, nil
}

// emptyReadError describes an empty read that could not be skipped: whether
// the descriptor is still this utun, whether the link still exists, and how
// long the device lived.
func (t *utunDevice) emptyReadError() error {
	socket := "still this utun"
	if name, matches, err := t.describeSocket(); err != nil {
		socket = fmt.Sprintf("no utun name (%v)", err)
	} else if !matches {
		socket = fmt.Sprintf("answers %q", name)
	}
	link := "present"
	if _, err := net.InterfaceByName(t.name); err != nil {
		link = "missing"
	}
	return fmt.Errorf("dataplane: empty read on %s (arrived readable): descriptor %s, link %s, %s queued, after %s, %d packets and %d empty reads: %w",
		t.name, socket, link, t.queuedBytes(), time.Since(t.opened).Round(time.Millisecond),
		t.packets.Load(), t.emptyReads.Load(), io.EOF)
}

// queuedBytes reports the bytes waiting in the socket (SO_NREAD): non-zero
// while reads come back empty means empty records are queued, zero means the
// socket reports end of data.
func (t *utunDevice) queuedBytes() string {
	raw, err := t.file.SyscallConn()
	if err != nil {
		return "unknown bytes"
	}
	queued, queuedErr := 0, error(nil)
	if err := raw.Control(func(descriptor uintptr) {
		queued, queuedErr = unix.GetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_NREAD)
	}); err != nil || queuedErr != nil {
		return "unknown bytes"
	}
	return fmt.Sprintf("%d bytes", queued)
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

// receiveShut peeks at a nonblocking utun without consuming a packet: an
// idle utun has nothing to read (EAGAIN), one whose receive side is shut
// reads 0 bytes at once. Recvmsg may fail to parse a source address after a
// successful read; that error still means the read happened.
func receiveShut(descriptor int) bool {
	var buffer [1]byte
	read, _, _, _, err := unix.Recvmsg(descriptor, buffer[:], nil, unix.MSG_PEEK|unix.MSG_DONTWAIT)
	return read == 0 && (err == nil || errors.Is(err, unix.EAFNOSUPPORT))
}
