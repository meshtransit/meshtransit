package mtcp

import (
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// gatewayMap is a map that carries its peers' Kubernetes access.
func gatewayMap(t *testing.T, revision int64) mapsession.Snapshot {
	t.Helper()
	return streamFixture(t, revision).WithKubernetes(must(mapsession.NewKubernetesView(nil)))
}

// freshMessages returns the MapFresh messages the node got since the last
// read.
func freshMessages(node *nodeView) []*mtcpv1.MapFresh {
	var fresh []*mtcpv1.MapFresh
	for {
		kind, message, ok := node.read()
		if !ok {
			return fresh
		}
		if kind == sharedmtcp.MessageMapFresh {
			fresh = append(fresh, message.(*mtcpv1.MapFresh))
		}
	}
}

// waitFresh waits for the MapFresh an acknowledgement sends, from another
// goroutine.
func waitFresh(t *testing.T, node *nodeView) []*mtcpv1.MapFresh {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if fresh := freshMessages(node); len(fresh) != 0 || time.Now().After(deadline) {
			return fresh
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A gateway that negotiated gateway.kube.v1 hears, once it acknowledged a
// map's authority, that it was current as of its read; connectivity does
// not move the view confirmed (mtcp-v1 §7.9).
func TestSinkConfirmsAnAcknowledgedGatewayMap(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	sink.confirmFreshness()
	initial := gatewayMap(t, 7)
	if err := sink.SendSnapshot(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	if fresh := freshMessages(node); len(fresh) != 0 {
		t.Fatalf("confirmed before the acknowledgement: %v", fresh)
	}
	// Not yet acknowledged: the stream's confirmation waits too.
	if err := sink.ConfirmFresh(t.Context(), initial, time.Now()); err != nil || len(freshMessages(node)) != 0 {
		t.Fatalf("ConfirmFresh() before the ack: %v", err)
	}
	sink.ack(&mtcpv1.View{Epoch: sink.epoch, Seq: 1})
	fresh := waitFresh(t, node)
	if len(fresh) != 1 || fresh[0].GetView().GetSeq() != 1 || fresh[0].GetView().GetEpoch() != sink.epoch ||
		fresh[0].GetAsOfMs() != initial.ReadAtLocal().UnixMilli() || fresh[0].GetAgeMs() < 0 ||
		len(fresh[0].GetNetworkRevisions()) != 1 || fresh[0].GetNetworkRevisions()[0].GetRevision() != 7 {
		t.Fatalf("after the ack: %v", fresh)
	}
	// The same acknowledgement again confirms nothing more.
	sink.ack(&mtcpv1.View{Epoch: sink.epoch, Seq: 1})
	time.Sleep(50 * time.Millisecond)
	if again := freshMessages(node); len(again) != 0 {
		t.Fatalf("confirmed twice: %v", again)
	}
	// The stream confirms the same view later, as of its read.
	later := time.Now()
	if err := sink.ConfirmFresh(t.Context(), initial, later); err != nil {
		t.Fatal(err)
	}
	if fresh := freshMessages(node); len(fresh) != 1 || fresh[0].GetAsOfMs() != later.UnixMilli() ||
		fresh[0].GetView().GetSeq() != 1 {
		t.Fatalf("stream confirmation: %v", fresh)
	}
	// Not for a map of another revision than the node holds.
	if err := sink.ConfirmFresh(t.Context(), gatewayMap(t, 8), later); err != nil || len(freshMessages(node)) != 0 {
		t.Fatalf("a revision the node does not hold was confirmed: %v", err)
	}
	// A newer authority waits for its own acknowledgement: one of an
	// earlier view confirms nothing, and the stream confirms nothing either.
	if err := sink.SendAuthorityDelta(t.Context(), must(mapsession.NewAuthorityDelta(initial,
		gatewayMap(t, 8)))); err != nil {
		t.Fatal(err)
	}
	sink.ack(&mtcpv1.View{Epoch: sink.epoch, Seq: 1})
	if err := sink.ConfirmFresh(t.Context(), gatewayMap(t, 8), time.Now()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if fresh := freshMessages(node); len(fresh) != 0 {
		t.Fatalf("an unacknowledged authority was confirmed: %v", fresh)
	}
	sink.ack(&mtcpv1.View{Epoch: sink.epoch, Seq: 2})
	if fresh := waitFresh(t, node); len(fresh) != 1 || fresh[0].GetView().GetSeq() != 2 {
		t.Fatalf("the newer authority: %v", fresh)
	}
	initial = gatewayMap(t, 8)
	// A suspension stops confirmations.
	if err := sink.SendAuthorityPause(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	if err := sink.ConfirmFresh(t.Context(), initial, time.Now()); err != nil || len(freshMessages(node)) != 0 {
		t.Fatalf("a suspended map was confirmed: %v", err)
	}
}

// No other map is ever confirmed: a session without gateway.kube.v1, or a
// gateway's map that withholds its peers' access (K1a3 Q8).
func TestSinkConfirmsOnlyGatewayMapsWithAccess(t *testing.T) {
	for name, test := range map[string]struct {
		fresh    bool
		snapshot func(*testing.T) mapsession.Snapshot
	}{
		"plain session": {snapshot: func(t *testing.T) mapsession.Snapshot { return gatewayMap(t, 7) }},
		"withheld map": {fresh: true, snapshot: func(t *testing.T) mapsession.Snapshot {
			return streamFixture(t, 7)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			session, node, control := testSession(t)
			sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}},
				time.Now)
			if test.fresh {
				sink.confirmFreshness()
			}
			snapshot := test.snapshot(t)
			if err := sink.SendSnapshot(t.Context(), snapshot); err != nil {
				t.Fatal(err)
			}
			sink.ack(&mtcpv1.View{Epoch: sink.epoch, Seq: 1})
			if err := sink.ConfirmFresh(t.Context(), snapshot, time.Now()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
			if fresh := freshMessages(node); len(fresh) != 0 {
				t.Fatalf("confirmed: %v", fresh)
			}
		})
	}
}
