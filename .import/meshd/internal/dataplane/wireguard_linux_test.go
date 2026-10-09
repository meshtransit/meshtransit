//go:build linux

package dataplane

import (
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

func TestAdoptPrivilegedTUNDescriptor(t *testing.T) {
	tests := []struct {
		name       string
		actualName string
		actualMTU  int
		wantErr    string
	}{
		{
			name:       "matching helper metadata",
			actualName: "mesh0",
			actualMTU:  1280,
		},
		{
			name:       "missing interface name",
			actualName: "",
			actualMTU:  1280,
			wantErr:    "name is empty",
		},
		{
			name:       "different mtu",
			actualName: "mesh0",
			actualMTU:  1420,
			wantErr:    "mtu does not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptors, err := unix.Socketpair(
				unix.AF_UNIX,
				unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
				0,
			)
			if err != nil {
				t.Fatalf("creating descriptor pair: %v", err)
			}
			source := os.NewFile(uintptr(descriptors[0]), "source")
			peer := os.NewFile(uintptr(descriptors[1]), "peer")
			t.Cleanup(func() {
				_ = source.Close()
				_ = peer.Close()
			})

			device, err := adoptPrivilegedTUNDescriptor(
				source,
				1280,
				func(descriptor int) (tun.Device, string, error) {
					file := os.NewFile(uintptr(descriptor), "adopted")
					return &fakeInheritedTUN{
						file:   file,
						name:   tt.actualName,
						mtu:    tt.actualMTU,
						events: make(chan tun.Event),
					}, tt.actualName, nil
				},
			)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("adopting descriptor error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("adopting descriptor: %v", err)
			}
			t.Cleanup(func() { _ = device.Close() })

			if _, err := source.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("source descriptor error = %v, want os.ErrClosed", err)
			}
			payload := []byte("mesh")
			if _, err := device.File().Write(payload); err != nil {
				t.Fatalf("writing adopted descriptor: %v", err)
			}
			if descriptors[1] < 0 || descriptors[1] > math.MaxInt32 {
				t.Fatalf("peer descriptor is outside poll range: %d", descriptors[1])
			}
			peerDescriptor := int32(descriptors[1]) //nolint:gosec // Bounds checked above.
			poll := []unix.PollFd{{
				Fd:     peerDescriptor,
				Events: unix.POLLIN,
			}}
			ready, err := unix.Poll(poll, 1000)
			if err != nil {
				t.Fatalf("polling peer descriptor: %v", err)
			}
			if ready != 1 || poll[0].Revents&unix.POLLIN == 0 {
				t.Fatalf("peer descriptor readiness = (%d, %d), want readable", ready, poll[0].Revents)
			}
			got := make([]byte, len(payload))
			if _, err := unix.Read(descriptors[1], got); err != nil {
				t.Fatalf("reading peer descriptor: %v", err)
			}
			if string(got) != string(payload) {
				t.Fatalf("peer payload = %q, want %q", got, payload)
			}
		})
	}
}

type fakeInheritedTUN struct {
	file   *os.File
	name   string
	mtu    int
	events chan tun.Event
}

func (t *fakeInheritedTUN) File() *os.File { return t.file }

func (t *fakeInheritedTUN) Read([][]byte, []int, int) (int, error) {
	return 0, errors.New("unexpected read")
}

func (t *fakeInheritedTUN) Write([][]byte, int) (int, error) {
	return 0, errors.New("unexpected write")
}

func (t *fakeInheritedTUN) MTU() (int, error) { return t.mtu, nil }

func (t *fakeInheritedTUN) Name() (string, error) { return t.name, nil }

func (t *fakeInheritedTUN) Events() <-chan tun.Event { return t.events }

func (t *fakeInheritedTUN) Close() error {
	close(t.events)

	return t.file.Close()
}

func (t *fakeInheritedTUN) BatchSize() int { return 1 }
