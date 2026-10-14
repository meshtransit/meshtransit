package mobile

import (
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// TestWireGuardDeviceSurvivesARouteChange runs a real wireguard-go device on
// a replaceableTUN: a TUN read error stops such a device, so it must keep
// running and reading from the new interface after Replace.
func TestWireGuardDeviceSurvivesARouteChange(t *testing.T) {
	t.Parallel()
	first, second := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	replaceable := newReplaceableTUN(first.TUN(), tuntest.DefaultMTU, nil)
	wireguard := device.NewDevice(replaceable, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(wireguard.Close)
	if err := wireguard.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if err := replaceable.Replace(func() (tun.Device, error) { return second.TUN(), nil }); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}
	ping := tuntest.Ping(netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr("100.64.0.5"))
	select {
	case second.Outbound <- ping: // the device reads the new interface
	case <-wireguard.Wait():
		t.Fatal("the device stopped after the route change")
	case <-time.After(5 * time.Second):
		t.Fatal("the device does not read the new interface")
	}
	select {
	case <-wireguard.Wait():
		t.Fatal("the device stopped after the route change")
	case <-time.After(50 * time.Millisecond):
	}
}
