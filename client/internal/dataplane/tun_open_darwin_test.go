package dataplane

import (
	"bytes"
	"os"
	"testing"

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
	device := &utunDevice{file: os.NewFile(uintptr(fds[0]), "utun99"), name: "utun99", events: make(chan tun.Event)}
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
