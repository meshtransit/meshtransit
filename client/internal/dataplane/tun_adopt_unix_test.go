//go:build linux || darwin

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

func TestAdoptTUNClosesTheFileItRefuses(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := AdoptTUN(reader, 100, nil); err == nil {
		t.Fatal("AdoptTUN() accepted an MTU of 100")
	}
	if _, err := reader.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("file after a refused AdoptTUN: Stat() error = %v, want os.ErrClosed", err)
	}
}

// Not parallel: it checks a descriptor number, which a parallel test could reuse.
func TestAdoptLeavesATakenDescriptorToItsOpener(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	var taken int
	_, err = adoptPrivilegedTUNDescriptor(reader, 1280, func(descriptor int) (tun.Device, string, error) {
		taken = descriptor
		return nil, "", fmt.Errorf("%w: not a tun", errDescriptorTaken)
	})
	if err == nil {
		t.Fatal("adoptPrivilegedTUNDescriptor() succeeded")
	}
	// Still open: the opener owns it now.
	if _, err := unix.FcntlInt(uintptr(taken), unix.F_GETFD, 0); err != nil {
		t.Fatalf("taken descriptor was closed: %v", err)
	}
	_ = unix.Close(taken)
}

// Not parallel: it checks a descriptor number, which a parallel test could reuse.
func TestAdoptClosesADescriptorTheOpenerRefused(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	var refused int
	_, err = adoptPrivilegedTUNDescriptor(reader, 1280, func(descriptor int) (tun.Device, string, error) {
		refused = descriptor
		return nil, "", errors.New("not a tun")
	})
	if err == nil {
		t.Fatal("adoptPrivilegedTUNDescriptor() succeeded")
	}
	if _, err := unix.FcntlInt(uintptr(refused), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("refused descriptor: F_GETFD error = %v, want EBADF", err)
	}
}
