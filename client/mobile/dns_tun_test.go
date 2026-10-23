package mobile

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/packetmeta"
)

// batchDevice reads the batches a test queues and records what is written.
type batchDevice struct {
	batches chan [][]byte
	written chan []byte
	closed  chan struct{}
	once    sync.Once
}

func newBatchDevice() *batchDevice {
	return &batchDevice{batches: make(chan [][]byte, 8), written: make(chan []byte, 64), closed: make(chan struct{})}
}

func (device *batchDevice) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	select {
	case batch := <-device.batches:
		for index, packet := range batch {
			sizes[index] = copy(buffers[index][offset:], packet)
		}
		return len(batch), nil
	case <-device.closed:
		return 0, os.ErrClosed
	}
}

func (device *batchDevice) Write(buffers [][]byte, offset int) (int, error) {
	for _, buffer := range buffers {
		device.written <- append([]byte(nil), buffer[offset:]...)
	}
	return len(buffers), nil
}

func (device *batchDevice) Close() error {
	device.once.Do(func() { close(device.closed) })
	return nil
}

func (device *batchDevice) File() *os.File           { return nil }
func (device *batchDevice) MTU() (int, error)        { return 1280, nil }
func (device *batchDevice) Name() (string, error)    { return "test", nil }
func (device *batchDevice) Events() <-chan tun.Event { return nil }
func (device *batchDevice) BatchSize() int           { return 4 }

var deviceAddress = netip.MustParseAddr("100.64.1.10")

func readBatch(t *testing.T, device tun.Device) []string {
	t.Helper()
	buffers := make([][]byte, 4)
	for index := range buffers {
		buffers[index] = make([]byte, 16+1500)
	}
	sizes := make([]int, 4)
	count, err := device.Read(buffers, sizes, 16)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	var read []string
	for index := range count {
		read = append(read, string(buffers[index][16:16+sizes[index]]))
	}
	return read
}

func written(t *testing.T, device *batchDevice) packetmeta.Header {
	t.Helper()
	select {
	case packet := <-device.written:
		header, err := packetmeta.Parse(packet)
		if err != nil {
			t.Fatalf("written packet: %v", err)
		}
		return header
	case <-time.After(5 * time.Second):
		t.Fatal("nothing written")
		return packetmeta.Header{}
	}
}

func TestDNSTUNAnswersQuestionsAndPassesTheRest(t *testing.T) {
	t.Parallel()
	device := newBatchDevice()
	answered := make(chan []byte, 4)
	wrapped := newDNSTUN(device, func(_ context.Context, query []byte) []byte {
		answered <- query
		return append([]byte("answer:"), query...)
	})
	t.Cleanup(func() { _ = wrapped.Close() })

	question := packetmeta.UDPDatagram(deviceAddress, resolverAddress, 40000, dnsPort, []byte("question"))
	peer := packetmeta.UDPDatagram(deviceAddress, netip.MustParseAddr("100.64.1.20"), 40000, dnsPort, []byte("peer"))
	// A whole batch of questions is read through, never returned empty.
	device.batches <- [][]byte{question}
	device.batches <- [][]byte{question, peer}
	if read := readBatch(t, wrapped); len(read) != 1 || read[0] != string(peer) {
		t.Fatalf("read = %d packets", len(read))
	}
	for range 2 {
		header := written(t, device)
		if header.Source != resolverAddress || header.Destination != deviceAddress || header.SourcePort != dnsPort ||
			header.DestinationPort != 40000 || header.Protocol != packetmeta.ProtocolUDP {
			t.Fatalf("answer header = %+v", header)
		}
	}
	if query := <-answered; string(query) != "question" {
		t.Fatalf("query = %q", query)
	}
}

func TestDNSTUNResetsTCPToTheResolver(t *testing.T) {
	t.Parallel()
	device := newBatchDevice()
	wrapped := newDNSTUN(device, func(context.Context, []byte) []byte { return nil })
	t.Cleanup(func() { _ = wrapped.Close() })
	peer := packetmeta.UDPDatagram(deviceAddress, netip.MustParseAddr("100.64.1.20"), 1, 2, nil)

	for _, port := range []uint16{53, 853} {
		syn := packetmeta.TCPSegment(deviceAddress, resolverAddress, 41000, port, 1000, 0, packetmeta.TCPFlagSYN)
		device.batches <- [][]byte{syn, peer}
		if read := readBatch(t, wrapped); len(read) != 1 {
			t.Fatalf("read = %d packets", len(read))
		}
		header := written(t, device)
		if header.Protocol != packetmeta.ProtocolTCP || header.SourcePort != port || header.DestinationPort != 41000 ||
			header.TCPFlags != packetmeta.TCPFlagRST|packetmeta.TCPFlagACK {
			t.Fatalf("reset = %+v", header)
		}
	}
	// A reset is never answered.
	rst := packetmeta.TCPSegment(deviceAddress, resolverAddress, 41000, 53, 1, 0, packetmeta.TCPFlagRST)
	device.batches <- [][]byte{rst, peer}
	readBatch(t, wrapped)
	select {
	case packet := <-device.written:
		t.Fatalf("answered a reset with %d bytes", len(packet))
	case <-time.After(50 * time.Millisecond):
	}
}

func TestDNSTUNDropsQuestionsBeyondItsSlots(t *testing.T) {
	t.Parallel()
	device := newBatchDevice()
	release := make(chan struct{})
	wrapped := newDNSTUN(device, func(context.Context, []byte) []byte {
		<-release
		return nil
	})
	question := packetmeta.UDPDatagram(deviceAddress, resolverAddress, 40000, dnsPort, []byte("q"))
	peer := packetmeta.UDPDatagram(deviceAddress, netip.MustParseAddr("100.64.1.20"), 1, 2, nil)
	for range maxDNSQueries + 3 {
		wrapped.take(question)
	}
	if dropped := wrapped.dropped(); dropped != 3 {
		t.Fatalf("dropped = %d", dropped)
	}
	// The read still goes on while every slot waits.
	device.batches <- [][]byte{question, peer}
	if read := readBatch(t, wrapped); len(read) != 1 {
		t.Fatalf("read = %d", len(read))
	}
	close(release)
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSTUNIgnoresOtherPacketsToTheResolver(t *testing.T) {
	t.Parallel()
	device := newBatchDevice()
	wrapped := newDNSTUN(device, func(context.Context, []byte) []byte { return []byte("never") })
	t.Cleanup(func() { _ = wrapped.Close() })
	otherPort := packetmeta.UDPDatagram(deviceAddress, resolverAddress, 40000, 5353, []byte("q"))
	echo := packetmeta.EchoRequest(deviceAddress, resolverAddress, 1, 1)
	truncated := packetmeta.UDPDatagram(deviceAddress, resolverAddress, 40000, dnsPort, []byte("q"))
	binary.BigEndian.PutUint16(truncated[2:4], 24) // shorter than its UDP header says
	for _, packet := range [][]byte{otherPort, echo, truncated} {
		if !wrapped.take(packet) {
			t.Fatal("a packet to the resolver went to the data plane")
		}
	}
	select {
	case packet := <-device.written:
		t.Fatalf("answered with %d bytes", len(packet))
	case <-time.After(50 * time.Millisecond):
	}
}
