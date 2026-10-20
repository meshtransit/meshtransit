package underlay

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"meshtransit.net/client/internal/overlayframe"
)

// ExitSource is what holds the client's sockets on the physical path while
// the host routes its Internet traffic into the mesh.
type ExitSource uint32

const (
	// ExitRequested: meshd asks for an exit route, or one is in place.
	ExitRequested ExitSource = 1 << iota
	// ExitHeld: the exit routes or their kill switch are in place, whoever
	// asked for them (root's settings hold them on their own): the host's
	// own resolver is cut off.
	ExitHeld
	// ExitChosen: root's settings name a pool, so a helper holds the kill
	// switch, before meshd asks for anything.
	ExitChosen
)

var (
	exitSources atomic.Uint32
	// physicalGeneration changes whenever sockets bound to the physical
	// path must be bound again: the exit route came or went, or the host's
	// networks changed.
	physicalGeneration atomic.Uint64
)

// SetExitBound records whether source wants the client's own sockets kept
// off the exit routes where they follow the host's routes (FollowsRoutes):
// while any does, every socket to an address outside the mesh is bound to
// the physical path, and names are resolved from the client's own sockets
// (exit node design §6.1). It is process-wide, as the routes are.
func SetExitBound(source ExitSource, on bool) {
	for {
		previous := exitSources.Load()
		next := previous &^ uint32(source)
		if on {
			next |= uint32(source)
		}
		if previous == next {
			return
		}
		if exitSources.CompareAndSwap(previous, next) {
			if (previous != 0) != (next != 0) {
				forgetPhysicalInterfaces()
				physicalGeneration.Add(1)
				reportExitBound(next)
				runExitHooks()
			}
			return
		}
	}
}

var exitHooks struct {
	sync.Mutex
	next  int
	hooks map[int]func()
}

// OnExitBoundChange runs hook, in a goroutine of its own, each time the
// client's sockets start or stop keeping off the exit routes, and returns
// what stops it. Where a connected socket keeps the route it took
// (ReconnectOnExitChange), its owner reconnects then.
func OnExitBoundChange(hook func()) (stop func()) {
	exitHooks.Lock()
	defer exitHooks.Unlock()
	if exitHooks.hooks == nil {
		exitHooks.hooks = map[int]func(){}
	}
	id := exitHooks.next
	exitHooks.next++
	exitHooks.hooks[id] = hook
	return func() {
		exitHooks.Lock()
		defer exitHooks.Unlock()
		delete(exitHooks.hooks, id)
	}
}

func runExitHooks() {
	exitHooks.Lock()
	hooks := make([]func(), 0, len(exitHooks.hooks))
	for _, hook := range exitHooks.hooks {
		hooks = append(hooks, hook)
	}
	exitHooks.Unlock()
	for _, hook := range hooks {
		go hook()
	}
}

// ExitBound reports whether any source keeps the sockets off the exit
// routes.
func ExitBound() bool { return exitSources.Load() != 0 }

// RebindPhysical asks sockets bound to the physical path to be bound again,
// as after a change of the host's networks.
func RebindPhysical() {
	forgetPhysicalInterfaces()
	physicalGeneration.Add(1)
}

// PhysicalGeneration changes whenever sockets bound to the physical path
// must be bound again.
func PhysicalGeneration() uint64 { return physicalGeneration.Load() }

// physicalBound reports whether a socket to address must be bound to the
// physical path: inside an installed subnet route, or anywhere outside the
// mesh and the host itself while the Internet goes into the mesh.
func physicalBound(address netip.Addr) bool {
	if Routed(address) {
		return true
	}
	if !ExitBound() || !address.IsValid() {
		return false
	}
	address = address.Unmap()
	return !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() &&
		!address.IsLinkLocalUnicast() && !overlayframe.Contains(netip.PrefixFrom(address, address.BitLen()))
}
