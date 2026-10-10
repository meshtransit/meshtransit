package mtcpclient

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// FuzzMapState feeds meshd arbitrary map snapshots and deltas from Core: the
// state refuses them or builds a snapshot that passes product validation.
func FuzzMapState(f *testing.F) {
	self := device("01890f00-0000-7000-8000-000000000701", 1, "100.64.0.1")
	peer := device("01890f00-0000-7000-8000-000000000702", 2, "100.64.0.2")
	snapshot, _ := proto.Marshal(&mtcpv1.MapSnapshot{
		View: &mtcpv1.View{Epoch: 1, Seq: 1}, Self: self,
		Peers: []*mtcpv1.Device{peer}, PacketFilter: filterFixture(),
	})
	delta, _ := proto.Marshal(&mtcpv1.MapDelta{
		View:        &mtcpv1.View{Epoch: 1, Seq: 2},
		PeersRemove: []string{peer.GetDeviceId()},
	})
	f.Add(snapshot, delta)
	f.Add(snapshot, []byte{})
	f.Fuzz(func(t *testing.T, encodedSnapshot, encodedDelta []byte) {
		first := &mtcpv1.MapSnapshot{}
		if proto.Unmarshal(encodedSnapshot, first) != nil {
			return
		}
		state := newMapState()
		if state.applySnapshot(first) != nil {
			return
		}
		input := snapshotInput{revision: 1, controlTime: time.Now(), now: time.Now()}
		_, _ = state.build(input)
		next := &mtcpv1.MapDelta{}
		if proto.Unmarshal(encodedDelta, next) != nil || state.applyDelta(next) != nil {
			return
		}
		_, _ = state.build(input)
	})
}
