package dataplane

import (
	"errors"
	"fmt"
	"runtime"

	"golang.zx2c4.com/wireguard/conn"

	"meshtransit.net/client/internal/underlay"
)

// protectBindSockets excludes the bind's UDP sockets from the platform VPN
// when the embedding app installed an underlay protector. Without one there
// is nothing to do. With one, a bind that cannot show its sockets fails:
// an unprotected packet path would loop through the mesh TUN.
func protectBindSockets(bind conn.Bind) error {
	if !underlay.Active() {
		return nil
	}
	peek, ok := bind.(conn.PeekLookAtSocketFd)
	if !ok {
		return errors.New("dataplane: the wireguard bind cannot expose its sockets to the VPN")
	}
	protected := 0
	for _, family := range []struct {
		name string
		look func() (int, error)
	}{
		{name: "IPv4", look: peek.PeekLookAtSocketFd4},
		{name: "IPv6", look: peek.PeekLookAtSocketFd6},
	} {
		fd, open, err := peekSocket(family.look)
		if err != nil {
			return fmt.Errorf("dataplane: reaching the %s wireguard socket: %w", family.name, err)
		}
		if !open {
			continue
		}
		if err := underlay.Protect(uintptr(fd)); err != nil {
			return fmt.Errorf("dataplane: %s wireguard socket: %w", family.name, err)
		}
		protected++
	}
	if protected == 0 {
		return errors.New("dataplane: the wireguard bind opened no socket")
	}
	return nil
}

// peekSocket reads one address family's socket descriptor. wireguard-go's
// StdNetBind leaves a family nil when the system cannot open it (IPv6 off)
// and dereferences it when asked, so that panic means "not open".
func peekSocket(look func() (int, error)) (fd int, open bool, err error) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		if _, isRuntime := recovered.(runtime.Error); !isRuntime {
			panic(recovered)
		}
		fd, open, err = -1, false, nil
	}()
	fd, err = look()
	if err != nil {
		return -1, false, err
	}
	if fd < 0 {
		return -1, false, errors.New("invalid descriptor")
	}
	return fd, true, nil
}
