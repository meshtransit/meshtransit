package dataplane

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"

	"meshtransit.net/client/internal/underlay"
)

// The tests in this file install the process-wide underlay protector, so
// none of them runs in parallel; parallel tests resume only after them.

// peekableBind is a fake bind whose sockets are visible like StdNetBind's
// on Android. A family with fd 0 is not open: asking for it panics, as
// StdNetBind does.
type peekableBind struct {
	*fakeInnerBind
	fd4, fd6 int
}

func (b *peekableBind) PeekLookAtSocketFd4() (int, error) { return peek(b.fd4) }
func (b *peekableBind) PeekLookAtSocketFd6() (int, error) { return peek(b.fd6) }

func peek(fd int) (int, error) {
	if fd == 0 {
		var closed *struct{ fd int }
		return closed.fd, nil // nil dereference, like StdNetBind
	}
	return fd, nil
}

type protectRecorder struct {
	mu   sync.Mutex
	fds  []uintptr
	fail bool
}

func installProtector(t *testing.T, fail bool) *protectRecorder {
	t.Helper()
	record := &protectRecorder{fail: fail}
	underlay.SetProtector(func(fd uintptr) error {
		record.mu.Lock()
		defer record.mu.Unlock()
		record.fds = append(record.fds, fd)
		if record.fail {
			return errors.New("VPN revoked")
		}
		return nil
	})
	t.Cleanup(func() { underlay.SetProtector(nil) })
	return record
}

func TestProtectBindSocketsWithoutAProtectorDoesNothing(t *testing.T) {
	if err := protectBindSockets(newFakeInnerBind()); err != nil {
		t.Fatalf("protectBindSockets() error = %v", err)
	}
}

func TestProtectBindSocketsProtectsEveryOpenFamily(t *testing.T) {
	for name, test := range map[string]struct {
		bind conn.Bind
		want []uintptr
	}{
		"both families": {bind: &peekableBind{fakeInnerBind: newFakeInnerBind(), fd4: 41, fd6: 42}, want: []uintptr{41, 42}},
		"no IPv6":       {bind: &peekableBind{fakeInnerBind: newFakeInnerBind(), fd4: 41}, want: []uintptr{41}},
		"no IPv4":       {bind: &peekableBind{fakeInnerBind: newFakeInnerBind(), fd6: 42}, want: []uintptr{42}},
	} {
		t.Run(name, func(t *testing.T) {
			record := installProtector(t, false)
			if err := protectBindSockets(test.bind); err != nil {
				t.Fatalf("protectBindSockets() error = %v", err)
			}
			if !slices.Equal(record.fds, test.want) {
				t.Fatalf("protected %v, want %v", record.fds, test.want)
			}
		})
	}
}

func TestProtectBindSocketsFailsClosed(t *testing.T) {
	for name, test := range map[string]struct {
		bind conn.Bind
		fail bool
	}{
		"bind without descriptors": {bind: newFakeInnerBind()},
		"no family open":           {bind: &peekableBind{fakeInnerBind: newFakeInnerBind()}},
		"platform refuses":         {bind: &peekableBind{fakeInnerBind: newFakeInnerBind(), fd4: 41}, fail: true},
	} {
		t.Run(name, func(t *testing.T) {
			installProtector(t, test.fail)
			if err := protectBindSockets(test.bind); err == nil {
				t.Fatal("protectBindSockets() succeeded")
			}
		})
	}
}

func TestSharedBindDoesNotOpenUnprotectedSockets(t *testing.T) {
	installProtector(t, true)
	inner := &peekableBind{fakeInnerBind: newFakeInnerBind(), fd4: 41}
	shared, err := newSharedBind(inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := shared.Open(0); !errors.Is(err, underlay.ErrNotProtected) {
		t.Fatalf("Open() error = %v, want ErrNotProtected", err)
	}
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if inner.isOpen {
		t.Fatal("the inner bind stayed open")
	}
}

func TestPeekSocketPassesOnPanicsThatAreNotTheNilSocket(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("peekSocket() swallowed a panic of the bind's own")
		}
	}()
	_, _, _ = peekSocket(func() (int, error) { panic("bind bug") })
}
