package dataplane

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/meshtransit/meshd/internal/networkmap"
	"golang.zx2c4.com/wireguard/tun"
)

func TestObservedTUNReportsSuccessfulPackets(t *testing.T) {
	t.Parallel()

	device := &fakeTUNDevice{
		readPacket: []byte{1, 2, 3},
		writeCount: 1,
	}
	observer := &recordingPacketObserver{}
	wrapped := &observedTUN{Device: device, observer: observer}
	buffer := make([]byte, 16)
	sizes := make([]int, 1)
	if count, err := wrapped.Read([][]byte{buffer}, sizes, 2); err != nil || count != 1 {
		t.Fatalf("Read() = %d, %v", count, err)
	}
	if count, err := wrapped.Write([][]byte{{9, 8, 7}}, 1); err != nil || count != 1 {
		t.Fatalf("Write() = %d, %v", count, err)
	}
	if len(observer.packets) != 2 || observer.directions[0] != PacketOutbound ||
		observer.directions[1] != PacketInbound {
		t.Fatalf("observations = %#v %#v", observer.directions, observer.packets)
	}
	if got := observer.packets[0]; len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("outbound packet = %v", got)
	}
	if got := observer.packets[1]; len(got) != 2 || got[0] != 8 || got[1] != 7 {
		t.Fatalf("inbound packet = %v", got)
	}
}

func TestObservedTUNFiltersBeforeForwardingAndObservation(t *testing.T) {
	t.Parallel()

	allowedOutbound := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 3},
		[4]byte{100, 64, 0, 4},
		48326,
		18080,
		6,
		0x02,
	)
	deniedOutbound := append([]byte{}, allowedOutbound...)
	copy(deniedOutbound[12:16], []byte{100, 64, 0, 9})
	allowedInbound := testIPv4TransportPacket(
		[4]byte{100, 64, 0, 4},
		[4]byte{100, 64, 0, 3},
		42000,
		18080,
		6,
		0x02,
	)
	deniedInbound := append([]byte{}, allowedInbound...)
	deniedInbound[23] = 0xa1
	device := &batchTUNDevice{readPackets: [][]byte{deniedOutbound, allowedOutbound}}
	filter := newPolicyFilter()
	filter.UpdateNetwork(testPolicySnapshot())
	observer := &recordingPacketObserver{}
	wrapped := &observedTUN{Device: device, filter: filter, observer: observer}
	buffers := [][]byte{make([]byte, 128), make([]byte, 128)}
	sizes := make([]int, len(buffers))
	count, err := wrapped.Read(buffers, sizes, 4)
	if err != nil || count != 1 {
		t.Fatalf("Read() = %d, %v", count, err)
	}
	if !bytes.Equal(buffers[0][4:4+sizes[0]], allowedOutbound) {
		t.Fatal("Read() did not compact the allowed packet")
	}
	count, err = wrapped.Write([][]byte{deniedInbound, allowedInbound}, 0)
	if err != nil || count != 1 || len(device.writtenPackets) != 1 {
		t.Fatalf("Write() = %d, %v, written=%d", count, err, len(device.writtenPackets))
	}
	if !bytes.Equal(device.writtenPackets[0], allowedInbound) {
		t.Fatal("Write() forwarded the wrong packet")
	}
	if len(observer.packets) != 2 || !bytes.Equal(observer.packets[0], allowedOutbound) ||
		!bytes.Equal(observer.packets[1], allowedInbound) {
		t.Fatalf("observed packets = %#v", observer.packets)
	}
}

type recordingPacketObserver struct {
	directions []PacketDirection
	packets    [][]byte
}

func (*recordingPacketObserver) UpdateNetwork(networkmap.Snapshot) {}

func (o *recordingPacketObserver) ObservePacket(direction PacketDirection, packet []byte) {
	o.directions = append(o.directions, direction)
	o.packets = append(o.packets, append([]byte(nil), packet...))
}

type fakeTUNDevice struct {
	readPacket []byte
	writeCount int
}

func (d *fakeTUNDevice) File() *os.File                   { return nil }
func (d *fakeTUNDevice) MTU() (int, error)                { return 1280, nil }
func (d *fakeTUNDevice) Name() (string, error)            { return "mesh0", nil }
func (d *fakeTUNDevice) Events() <-chan tun.Event         { return nil }
func (d *fakeTUNDevice) Close() error                     { return nil }
func (d *fakeTUNDevice) BatchSize() int                   { return 1 }
func (d *fakeTUNDevice) Write([][]byte, int) (int, error) { return d.writeCount, nil }

func (d *fakeTUNDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset+len(d.readPacket) > len(bufs[0]) {
		return 0, errors.New("invalid read buffer")
	}
	copy(bufs[0][offset:], d.readPacket)
	sizes[0] = len(d.readPacket)

	return 1, nil
}

type batchTUNDevice struct {
	readPackets    [][]byte
	writtenPackets [][]byte
}

func (*batchTUNDevice) File() *os.File           { return nil }
func (*batchTUNDevice) MTU() (int, error)        { return 1280, nil }
func (*batchTUNDevice) Name() (string, error)    { return "mesh0", nil }
func (*batchTUNDevice) Events() <-chan tun.Event { return nil }
func (*batchTUNDevice) Close() error             { return nil }
func (d *batchTUNDevice) BatchSize() int         { return len(d.readPackets) }

func (d *batchTUNDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) < len(d.readPackets) || len(sizes) < len(d.readPackets) {
		return 0, errors.New("invalid read buffers")
	}
	for index, packet := range d.readPackets {
		if offset+len(packet) > len(bufs[index]) {
			return 0, errors.New("read buffer is too small")
		}
		copy(bufs[index][offset:], packet)
		sizes[index] = len(packet)
	}

	return len(d.readPackets), nil
}

func (d *batchTUNDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buffer := range bufs {
		d.writtenPackets = append(d.writtenPackets, append([]byte{}, buffer[offset:]...))
	}

	return len(bufs), nil
}
