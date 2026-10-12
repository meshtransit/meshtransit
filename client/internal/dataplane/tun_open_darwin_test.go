package dataplane

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// pairDevice wraps one end of a datagram socketpair as a utunDevice; the other
// end stands in for the kernel side of the utun link.
func pairDevice(t *testing.T) (*utunDevice, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Nonblocking, as openUTUN makes the utun descriptor.
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	device := &utunDevice{
		file: os.NewFile(uintptr(fds[0]), "utun99"), name: "utun99", events: make(chan tun.Event), opened: time.Now(),
	}
	kernel := os.NewFile(uintptr(fds[1]), "kernel")
	t.Cleanup(func() {
		_ = device.Close()
		_ = kernel.Close()
	})
	return device, kernel
}

func TestUTUNDeviceFramesPacketsWithTheAddressFamily(t *testing.T) {
	t.Parallel()
	device, kernel := pairDevice(t)
	const offset = 16
	ipv4 := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	ipv6 := []byte{0x60, 0, 0, 0, 5, 6, 7, 8}
	bufs := [][]byte{append(make([]byte, offset), ipv4...), append(make([]byte, offset), ipv6...)}
	if written, err := device.Write(bufs, offset); err != nil || written != 2 {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	for _, want := range [][]byte{
		append([]byte{0, 0, 0, unix.AF_INET}, ipv4...),
		append([]byte{0, 0, 0, unix.AF_INET6}, ipv6...),
	} {
		frame := make([]byte, 64)
		read, err := kernel.Read(frame)
		if err != nil || !bytes.Equal(frame[:read], want) {
			t.Fatalf("kernel read %x, %v; want %x", frame[:read], err, want)
		}
	}
	if _, err := device.Write([][]byte{append(make([]byte, offset), 0x10)}, offset); err == nil {
		t.Fatal("Write() accepted a packet that is neither IPv4 nor IPv6")
	}

	if _, err := kernel.Write(append([]byte{0, 0, 0, unix.AF_INET}, ipv4...)); err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{make([]byte, 128)}
	sizes := []int{0}
	if count, err := device.Read(packets, sizes, offset); err != nil || count != 1 ||
		!bytes.Equal(packets[0][offset:offset+sizes[0]], ipv4) {
		t.Fatalf("Read() = %d %x, %v", count, packets[0][offset:offset+sizes[0]], err)
	}
}

func TestUTUNDeviceHasNoEventsAndClosesOnce(t *testing.T) {
	t.Parallel()
	device, _ := pairDevice(t)
	if name, _ := device.Name(); name != "utun99" || device.BatchSize() != 1 {
		t.Fatalf("name %q batch %d", name, device.BatchSize())
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if _, open := <-device.Events(); open {
		t.Fatal("events stayed open after Close")
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
}

func TestUTUNDeviceFailsAnEmptyReadOnADetachedDescriptor(t *testing.T) {
	t.Parallel()
	device, kernel := pairDevice(t)
	if _, err := kernel.Write(nil); err != nil {
		t.Fatal(err)
	}
	_, err := device.Read([][]byte{make([]byte, 128)}, []int{0}, 16)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v, want EOF", err)
	}
	for _, detail := range []string{"empty read on utun99", "link missing", "0 packets and 0 empty reads"} {
		if !strings.Contains(err.Error(), detail) {
			t.Fatalf("error %q lacks %q", err, detail)
		}
	}
}

func TestUTUNDeviceSkipsEmptyReadsWhileAttached(t *testing.T) {
	t.Parallel()
	device, kernel := pairDevice(t)
	device.isAttached = func() bool { return true }
	device.emptyReadPause = time.Millisecond
	ipv4 := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	for range 3 {
		if _, err := kernel.Write(nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := kernel.Write(append([]byte{0, 0, 0, unix.AF_INET}, ipv4...)); err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{make([]byte, 128)}
	sizes := []int{0}
	count, err := device.Read(packets, sizes, 16)
	if err != nil || count != 1 || !bytes.Equal(packets[0][16:16+sizes[0]], ipv4) {
		t.Fatalf("Read() = %d, %v", count, err)
	}
	if device.emptyReads.Load() != 3 {
		t.Fatalf("empty reads = %d, want 3", device.emptyReads.Load())
	}
}

func TestUTUNDeviceFailsWhenEmptyReadsOutlastTheGrace(t *testing.T) {
	t.Parallel()
	device, kernel := pairDevice(t)
	device.isAttached = func() bool { return true }
	device.emptyReadGrace = 50 * time.Millisecond
	device.emptyReadPause = time.Millisecond
	// The socketpair holds few datagrams, so keep writing while Read drains.
	stop := make(chan struct{})
	written := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				written <- nil
				return
			default:
			}
			if _, err := kernel.Write(nil); err != nil && !errors.Is(err, unix.ENOBUFS) {
				written <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	_, err := device.Read([][]byte{make([]byte, 128)}, []int{0}, 16)
	close(stop)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v, want EOF once the grace ends", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestUTUNDeviceCloseEndsAWaitingRead(t *testing.T) {
	t.Parallel()
	device, _ := pairDevice(t)
	result := make(chan error, 1)
	go func() {
		_, err := device.Read([][]byte{make([]byte, 128)}, []int{0}, 16)
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read() error = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the waiting Read")
	}
}

func TestReceiveShutTellsAShutSocketFromAnIdleOne(t *testing.T) {
	t.Parallel()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	if receiveShut(fds[0]) {
		t.Fatal("an idle socket reported its receive side shut")
	}
	if _, err := unix.Write(fds[1], []byte{0, 0, 0, 2, 0x45}); err != nil {
		t.Fatal(err)
	}
	if receiveShut(fds[0]) {
		t.Fatal("a socket with a queued packet reported its receive side shut")
	}
	buffer := make([]byte, 16)
	if read, err := unix.Read(fds[0], buffer); err != nil || read != 5 {
		t.Fatalf("peek consumed the packet: read %d, %v", read, err)
	}
	if err := unix.Shutdown(fds[0], unix.SHUT_RD); err != nil {
		t.Fatal(err)
	}
	if !receiveShut(fds[0]) {
		t.Fatal("a socket shut for reading was not reported")
	}
}
