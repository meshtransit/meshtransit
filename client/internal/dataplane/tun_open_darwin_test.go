package dataplane

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type eventTUN struct {
	tun.Device
	events chan tun.Event
}

func (t *eventTUN) Events() <-chan tun.Event { return t.events }

func TestManagedUpTUNDropsUpAndDownEvents(t *testing.T) {
	t.Parallel()
	inner := &eventTUN{events: make(chan tun.Event, 4)}
	wrapped := newManagedUpTUN(inner)
	inner.events <- tun.EventDown
	inner.events <- tun.EventUp | tun.EventMTUUpdate
	inner.events <- tun.EventUp
	close(inner.events)
	var got []tun.Event
	timeout := time.After(2 * time.Second)
	for {
		select {
		case event, ok := <-wrapped.Events():
			if !ok {
				if len(got) != 1 || got[0] != tun.EventMTUUpdate {
					t.Fatalf("events = %v, want only the MTU update", got)
				}
				return
			}
			got = append(got, event)
		case <-timeout:
			t.Fatal("wrapped events did not close")
		}
	}
}
