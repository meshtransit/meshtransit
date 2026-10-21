package dataplane

import (
	"time"

	"meshtransit.net/client/internal/packetmeta"
)

// ExitActivity is what this node sent to the Internet through the exit node
// it uses and heard back: the evidence that the exit node no longer reaches
// the Internet although it still answers (exit node design §9.1).
type ExitActivity struct {
	// Node is the exit node (a device ID); the rest is about it alone.
	Node string
	// NewConnections counts the TCP connections opened through it since
	// its last answer, the first at WaitingSince; LastAnswered is that
	// answer.
	NewConnections int
	WaitingSince   time.Time
	LastAnswered   time.Time
	// LastSent is the last packet sent through it: with LastAnswered, when
	// the node last used the exit node at all.
	LastSent time.Time
}

// noteExitLocked records a packet sent to (sent) or a reply from an
// Internet address reached through the exit node. Only the first packet of
// a TCP connection counts as sent: retransmissions are no new evidence.
func (f *policyFilter) noteExitLocked(header packetmeta.Header, sent bool, now time.Time) {
	address := header.Source
	if sent {
		address = header.Destination
	}
	if prefix, _, found := f.routed.lookup(address); found {
		if _, installed := f.routedInstalled[prefix]; installed {
			return // a Site's
		}
	}
	if _, viaExit := f.routed.exitFor(address); !viaExit {
		return
	}
	if node := f.routed.exit.nodeRef; f.exitActivity.Node != node {
		f.exitActivity = ExitActivity{Node: node}
	}
	if !sent {
		f.exitActivity.NewConnections, f.exitActivity.WaitingSince, f.exitActivity.LastAnswered = 0, time.Time{}, now
		return
	}
	f.exitActivity.LastSent = now
	if header.Protocol != packetmeta.ProtocolTCP || !startsTrackableFlow(header) {
		return
	}
	if key, stateful := outboundFlowKey(header); stateful {
		if state, tracked := f.flows[key]; tracked && state.expiresAt.After(now) {
			return
		}
	}
	if f.exitActivity.NewConnections == 0 {
		f.exitActivity.WaitingSince = now
	}
	f.exitActivity.NewConnections++
}

// ExitActivity returns what this node sent through the exit node it uses.
func (f *policyFilter) ExitActivity() ExitActivity {
	if f == nil {
		return ExitActivity{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exitActivity
}

// ExitActivity returns what this node sent through the exit node it uses
// and heard back.
func (e *WireGuardEngine) ExitActivity() ExitActivity {
	if e == nil {
		return ExitActivity{}
	}
	return e.filter.ExitActivity()
}
