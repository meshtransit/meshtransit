package dataplane

import (
	"context"
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/internet"
)

// servedExitSetter is the helper's exit node forwarding operation.
type servedExitSetter interface {
	SetServedExit(ctx context.Context, exit netadmin.ExitRequest) (netadmin.ExitServing, error)
}

// ExitNodeStatus is how the node forwards as an exit node (mtcp-v1 §7.7).
type ExitNodeStatus struct {
	// Pool is the served Exit Pool's reference; empty when it serves none.
	Pool string
	// Serving, with the limits the host applies, or Refused (helper reason).
	Serving              bool
	ConntrackPerConsumer int
	SMTP                 bool
	MaxConsumers         int
	Refused              string
	// Error is the last failure to configure the helper.
	Error string
	// Health is the pool's health as the exit node measures it; nil until
	// measured.
	Health *ExitHealth
}

// maximumExitPublic bounds the public addresses of the host the helper
// leaves out of the Internet (netadmin's own bound).
const maximumExitPublic = 64

// exitDesired is what the helper is asked for an exit node: the served
// pool, and the host's own addresses as seen from outside, which are no
// Internet for its consumers (exit node design §4.1).
type exitDesired struct {
	pools  []networkmap.ServedExit
	public []netip.Addr
}

// syncServedExitLocked records the Exit Pool the map has the node serve and
// has the worker send it to the helper when it changed.
func (e *WireGuardEngine) syncServedExitLocked(served []networkmap.ServedExit) {
	e.syncExitLocked(exitDesired{pools: served, public: e.exitPublic})
}

// SetExitPublicAddresses records the host's addresses as peers see them
// (its reflexive endpoints): an exit node never forwards a consumer to its
// own public address, such as a cloud's elastic address that loops back.
func (e *WireGuardEngine) SetExitPublicAddresses(addresses []netip.Addr) {
	if e == nil {
		return
	}
	public := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address = address.Unmap(); internet.Contains(address) {
			public = append(public, address)
		}
	}
	slices.SortFunc(public, netip.Addr.Compare)
	public = slices.Compact(public)
	public = public[:min(len(public), maximumExitPublic)]
	e.mu.Lock()
	defer e.mu.Unlock()
	if slices.Equal(public, e.exitPublic) {
		return
	}
	e.exitPublic = public
	if e.device != nil {
		e.syncExitLocked(exitDesired{pools: e.servedExit.desired.pools, public: public})
	}
}

func (e *WireGuardEngine) syncExitLocked(desired exitDesired) {
	served := desired.pools
	setter, supported := e.opener.(servedExitSetter)
	if !supported {
		e.exitStatus = ExitNodeStatus{}
		if len(served) != 0 {
			e.exitStatus = ExitNodeStatus{Pool: served[0].Ref, Error: "exit nodes are not supported on this platform"}
		}
		e.filter.SetExitInstalled(nil, nil, 0)
		return
	}
	e.servedExit.setLocked(e, desired, helperExchange[exitDesired, netadmin.ExitServing]{
		empty: func(desired exitDesired) bool { return len(desired.pools) == 0 },
		equal: func(first, second exitDesired) bool {
			return equalServedExits(first.pools, second.pools) && slices.Equal(first.public, second.public)
		},
		clone: func(desired exitDesired) exitDesired {
			return exitDesired{
				pools:  append([]networkmap.ServedExit{}, desired.pools...),
				public: slices.Clone(desired.public),
			}
		},
		send: func(ctx context.Context, desired exitDesired) (netadmin.ExitServing, error) {
			return setter.SetServedExit(ctx, exitRequestOf(desired))
		},
		record: e.recordServedExitLocked,
		giveUp: func(err error) {
			if e.logger != nil {
				e.logger.Warn("stopping exit forwarding keeps failing; giving up until the next change", "error", err)
			}
			e.exitStatus = ExitNodeStatus{}
		},
	})
}

// exitRequestOf asks the helper to serve the first (only) pool, leaving the
// host's public addresses out, or to stop.
func exitRequestOf(desired exitDesired) netadmin.ExitRequest {
	if len(desired.pools) == 0 {
		return netadmin.ExitRequest{}
	}
	request := netadmin.ExitRequest{
		Serve: true, ConntrackPerConsumer: desired.pools[0].ConntrackPerConsumer,
		SMTP: desired.pools[0].SMTPAllowed,
	}
	for _, address := range desired.public {
		request.Excluded = append(request.Excluded, netip.PrefixFrom(address, address.BitLen()))
	}
	return request
}

// recordServedExitLocked keeps what the helper did and admits the pool's
// rules in the filter only while the helper forwards.
func (e *WireGuardEngine) recordServedExitLocked(desired exitDesired, result netadmin.ExitServing, err error) {
	requested := desired.pools
	previous := e.exitStatus
	status := ExitNodeStatus{Health: previous.Health}
	if len(requested) != 0 {
		status.Pool = requested[0].Ref
	}
	if status.Pool != previous.Pool {
		// Another pool: its own probes, nothing measured of it yet.
		e.stopExitHealthLocked()
		status.Health = nil
	}
	if err != nil {
		status.Error = err.Error()
		result = netadmin.ExitServing{}
	}
	status.Serving, status.ConntrackPerConsumer, status.SMTP = result.Serving, result.ConntrackPerConsumer, result.SMTP
	status.MaxConsumers, status.Refused = result.MaxConsumers, result.Refused
	e.exitStatus = status
	if len(requested) == 0 {
		e.stopExitHealthLocked()
	} else {
		e.startExitHealthLocked()
	}
	if !result.Serving || len(requested) == 0 {
		e.filter.SetExitInstalled(nil, nil, 0)
	} else {
		var local []netip.Addr
		if e.hostAddresses != nil {
			var err error
			if local, err = e.hostAddresses(); err != nil && e.logger != nil {
				e.logger.Warn("reading the exit node's own addresses failed; the kernel rules alone guard them",
					"error", err)
			}
		}
		// The host's public addresses are its own too.
		local = append(local, desired.public...)
		e.filter.SetExitInstalled(requested[0].Rules, local, result.MaxConsumers)
	}
	if e.logger == nil || equalExitNodeStatus(previous, e.exitStatus) {
		return
	}
	if err != nil {
		e.logger.Warn("exit forwarding failed", "pool", status.Pool, "error", err)
		return
	}
	e.logger.Info("exit forwarding applied", "pool", status.Pool, "serving", status.Serving,
		"refused", status.Refused, "conntrack_per_consumer", status.ConntrackPerConsumer, "smtp", status.SMTP)
}

// resetServedExitLocked forgets what a closed device forwarded as an exit
// node.
func (e *WireGuardEngine) resetServedExitLocked() {
	e.stopExitHealthLocked()
	e.servedExit.resetLocked()
	e.exitStatus = ExitNodeStatus{}
	e.filter.SetExitInstalled(nil, nil, 0)
}

// ExitNode returns how the node forwards as an exit node.
func (e *WireGuardEngine) ExitNode() ExitNodeStatus {
	if e == nil {
		return ExitNodeStatus{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.exitStatus
	if status.Health != nil {
		health := *status.Health
		status.Health = &health
	}
	return status
}

func equalExitNodeStatus(first, second ExitNodeStatus) bool {
	first.Health, second.Health = nil, nil
	return first == second
}

func equalServedExits(first, second []networkmap.ServedExit) bool {
	return slices.EqualFunc(first, second, func(left, right networkmap.ServedExit) bool {
		return left.Ref == right.Ref && left.ConntrackPerConsumer == right.ConntrackPerConsumer &&
			left.SMTPAllowed == right.SMTPAllowed && slices.Equal(left.Probes, right.Probes) &&
			slices.Equal(left.DNSUpstreams, right.DNSUpstreams) &&
			slices.EqualFunc(left.Rules, right.Rules, func(a, b networkmap.Rule) bool {
				return slices.Equal(a.Sources, b.Sources) && slices.Equal(a.Destinations, b.Destinations) &&
					slices.Equal(a.Protocols, b.Protocols)
			})
	})
}
