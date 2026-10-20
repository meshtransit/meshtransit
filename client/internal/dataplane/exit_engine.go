package dataplane

import (
	"context"
	"net/netip"
	"slices"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
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
}

// syncServedExitLocked records the Exit Pool the map has the node serve and
// has the worker send it to the helper when it changed.
func (e *WireGuardEngine) syncServedExitLocked(served []networkmap.ServedExit) {
	setter, supported := e.opener.(servedExitSetter)
	if !supported {
		e.exitStatus = ExitNodeStatus{}
		if len(served) != 0 {
			e.exitStatus = ExitNodeStatus{Pool: served[0].Ref, Error: "exit nodes are not supported on this platform"}
		}
		e.filter.SetExitInstalled(nil, nil, 0)
		return
	}
	e.servedExit.setLocked(e, served, helperExchange[[]networkmap.ServedExit, netadmin.ExitServing]{
		empty: func(pools []networkmap.ServedExit) bool { return len(pools) == 0 },
		equal: equalServedExits,
		clone: func(pools []networkmap.ServedExit) []networkmap.ServedExit {
			return append([]networkmap.ServedExit{}, pools...)
		},
		send: func(ctx context.Context, pools []networkmap.ServedExit) (netadmin.ExitServing, error) {
			return setter.SetServedExit(ctx, exitRequestOf(pools))
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

// exitRequestOf asks the helper to serve the first (only) pool, or to stop.
func exitRequestOf(pools []networkmap.ServedExit) netadmin.ExitRequest {
	if len(pools) == 0 {
		return netadmin.ExitRequest{}
	}
	return netadmin.ExitRequest{
		Serve: true, ConntrackPerConsumer: pools[0].ConntrackPerConsumer,
		SMTP: pools[0].SMTPAllowed,
	}
}

// recordServedExitLocked keeps what the helper did and admits the pool's
// rules in the filter only while the helper forwards.
func (e *WireGuardEngine) recordServedExitLocked(requested []networkmap.ServedExit, result netadmin.ExitServing,
	err error,
) {
	previous := e.exitStatus
	status := ExitNodeStatus{}
	if len(requested) != 0 {
		status.Pool = requested[0].Ref
	}
	if err != nil {
		status.Error = err.Error()
		result = netadmin.ExitServing{}
	}
	status.Serving, status.ConntrackPerConsumer, status.SMTP = result.Serving, result.ConntrackPerConsumer, result.SMTP
	status.MaxConsumers, status.Refused = result.MaxConsumers, result.Refused
	e.exitStatus = status
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
		e.filter.SetExitInstalled(requested[0].Rules, local, result.MaxConsumers)
	}
	if e.logger == nil || previous == status {
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
	return e.exitStatus
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
