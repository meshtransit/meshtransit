package dnsconfig

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// A resolver address another socket holds is named as such (TD-SEC-25).
func TestListenErrorNamesATakenAddress(t *testing.T) {
	t.Parallel()
	var listen net.ListenConfig
	held, err := listen.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	address := netip.MustParseAddrPort(held.LocalAddr().String())
	_, err = listen.ListenPacket(context.Background(), "udp4", address.String())
	if err == nil {
		t.Fatal("a second socket took the resolver's address")
	}
	if wrapped := listenError("udp", address, err); !errors.Is(wrapped, ErrResolverAddressTaken) {
		t.Fatalf("listenError = %v", wrapped)
	}
	if other := listenError("udp", address, errors.New("no such device")); errors.Is(other, ErrResolverAddressTaken) {
		t.Fatalf("an unrelated failure is a taken address: %v", other)
	}
}
