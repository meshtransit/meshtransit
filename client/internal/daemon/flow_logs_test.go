package daemon

import (
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/flowreport"
)

type countingPlane struct{ counter *flowcount.Counter }

func (p *countingPlane) SetFlowCounter(counter *flowcount.Counter) { p.counter = counter }

// Logging needs a directory and a counting data plane; a ticket from a
// profile no longer served never reaches the reporter.
func TestFlowLogsFollowTheProfile(t *testing.T) {
	t.Parallel()
	if newFlowLogs("", &countingPlane{}, nil) != nil || newFlowLogs(t.TempDir(), struct{}{}, nil) != nil {
		t.Fatal("logging without a directory or a counting data plane")
	}
	var none *flowLogs
	if none.tickets("a") != nil || none.status() != (flowreport.Status{}) {
		t.Fatal("nil logs declare flow.report1")
	}
	none.serve("a")
	none.mapApplied(1)
	logs := newFlowLogs(t.TempDir(), &countingPlane{}, nil)
	received := make(chan controlplane.FlowTicket, 4)
	logs.setTicket = func(ticket controlplane.FlowTicket) { received <- ticket }
	logs.serve("a")
	<-received // serving a profile first turns any other off
	fromA, fromB := logs.tickets("a"), logs.tickets("b")
	fromB(controlplane.FlowTicket{Token: []byte("b")})
	select {
	case ticket := <-received:
		t.Fatalf("a ticket of another profile arrived: %q", ticket.Token)
	default:
	}
	fromA(controlplane.FlowTicket{Token: []byte("a")})
	if ticket := <-received; string(ticket.Token) != "a" {
		t.Fatalf("ticket %q", ticket.Token)
	}
	logs.serve("b")
	if ticket := <-received; len(ticket.Token) != 0 {
		t.Fatal("a profile change did not turn logging off")
	}
}
