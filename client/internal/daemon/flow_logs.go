package daemon

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/flowreport"
)

// flowCounterDataPlane counts the packet filter's decisions for connection
// logs.
type flowCounterDataPlane interface {
	SetFlowCounter(*flowcount.Counter)
}

// flowLogs keeps the connection log reporter, the profile it logs for and
// the map revision the counts are taken under.
type flowLogs struct {
	reporter    *flowreport.Reporter
	mapRevision atomic.Uint64
	mu          sync.Mutex
	profile     string
	// setTicket is the reporter's SetTicket.
	setTicket func(controlplane.FlowTicket)
}

// newFlowLogs returns connection logging when the data plane can count and
// dir is set, nil otherwise: logging then never starts, whatever Core sends.
func newFlowLogs(dir string, dataPlane any, logger *slog.Logger) *flowLogs {
	counting, ok := dataPlane.(flowCounterDataPlane)
	if dir == "" || !ok {
		return nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	logs := &flowLogs{}
	enforced, _ := dataPlane.(enforcedPolicyDataPlane)
	logs.reporter = flowreport.New(flowreport.Config{
		Dir: dir, SetCounter: counting.SetFlowCounter, Logger: logger.With("component", "connection_logs"),
		Policy: func() flowreport.Policy {
			policy := flowreport.Policy{MapRevision: logs.mapRevision.Load()}
			if enforced != nil {
				if current, ok := enforced.EnforcedPolicy(); ok {
					policy.Digest = current.Digest[:]
				}
			}
			return policy
		},
	})
	logs.setTicket = logs.reporter.SetTicket
	return logs
}

// tickets is the stream's FlowTickets option for profile: nil keeps
// flow.report1 off. A ticket from a profile no longer served is dropped.
func (logs *flowLogs) tickets(profile string) func(controlplane.FlowTicket) {
	if logs == nil {
		return nil
	}
	return func(ticket controlplane.FlowTicket) {
		logs.mu.Lock()
		defer logs.mu.Unlock()
		if logs.profile == profile {
			logs.setTicket(ticket)
		}
	}
}

// serve logs for profile from now on, "" for none: any other profile's
// logging stops at once, its spool kept on disk.
func (logs *flowLogs) serve(profile string) {
	if logs == nil {
		return
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if logs.profile != profile {
		logs.profile = profile
		logs.setTicket(controlplane.FlowTicket{})
	}
}

func (logs *flowLogs) mapApplied(revision uint64) {
	if logs != nil {
		logs.mapRevision.Store(revision)
	}
}

// Status is what the local API shows; the zero value is off.
func (logs *flowLogs) status() flowreport.Status {
	if logs == nil {
		return flowreport.Status{}
	}
	return logs.reporter.Status()
}
