package mobile

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/packetmeta"
)

const (
	// dnsPort is where the in-process resolver answers.
	dnsPort = 53
	// maxDNSQueries bounds the questions answered at once, as the desktop
	// resolver does; one more is dropped and the asker asks again.
	maxDNSQueries = 256
	// maxDNSWrites bounds the answers and resets waiting to be written.
	maxDNSWrites = 256
	// defaultWriteOffset is the headroom WireGuard leaves before a packet it
	// writes, until a read tells the offset in use.
	defaultWriteOffset = 16
	// tcpFlagFIN takes a sequence number, as SYN does (RFC 9293).
	tcpFlagFIN uint8 = 0x01
)

// resolverAddress is where the VPN interface sends the device's questions
// when MeshTransit answers them (DNS design D4 §3.1): TEST-NET-1, never a
// host, as on the desktop (meshnetd --dns-address).
var resolverAddress = netip.MustParseAddr("192.0.2.53")

// answerFunc answers one DNS message that arrived over UDP; nil sends none.
type answerFunc func(ctx context.Context, query []byte) []byte

// dnsTUN takes the packets the device sends the in-process resolver out of
// the TUN before the data plane sees them (DNS design D4 §3.2): it sits
// below the packet policy, as the desktop's resolver link is local. UDP
// questions to port 53 are answered, TCP to any port of the resolver is
// reset, anything else to it is dropped. The data plane's read never waits
// on the resolver nor writes: answers and resets go through one writer.
type dnsTUN struct {
	tun.Device
	answer answerFunc
	ctx    context.Context
	cancel context.CancelFunc
	slots  chan struct{}
	writes chan []byte
	// writer ends with the writeLoop; questions in flight are not waited
	// for: their answers are dropped once closed.
	writer sync.WaitGroup
	offset atomic.Int64
	busy   atomic.Uint64
	once   sync.Once
}

func newDNSTUN(device tun.Device, answer answerFunc) *dnsTUN {
	ctx, cancel := context.WithCancel(context.Background())
	wrapped := &dnsTUN{
		Device: device, answer: answer, ctx: ctx, cancel: cancel,
		slots: make(chan struct{}, maxDNSQueries), writes: make(chan []byte, maxDNSWrites),
	}
	wrapped.offset.Store(defaultWriteOffset)
	wrapped.writer.Add(1)
	go wrapped.writeLoop()
	return wrapped
}

// Read returns the packets for the data plane, without those to the
// resolver; it reads again rather than return none.
func (d *dnsTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if offset < 0 || len(sizes) < len(buffers) {
		return 0, errors.New("mobile: invalid tun read buffers")
	}
	d.offset.Store(int64(offset))
	for {
		count, err := d.Device.Read(buffers, sizes, offset)
		if count <= 0 || count > len(buffers) {
			return count, err
		}
		kept := 0
		for index := range count {
			if sizes[index] < 0 || offset+sizes[index] > len(buffers[index]) {
				continue
			}
			packet := buffers[index][offset : offset+sizes[index]]
			if d.take(packet) {
				continue
			}
			if kept != index {
				copy(buffers[kept][offset:], packet)
			}
			sizes[kept] = len(packet)
			kept++
		}
		if kept > 0 || err != nil {
			return kept, err
		}
	}
}

// take handles a packet to the resolver and reports whether it was one.
func (d *dnsTUN) take(packet []byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 || netip.AddrFrom4([4]byte(packet[16:20])) != resolverAddress {
		return false
	}
	header, err := packetmeta.Parse(packet)
	if err != nil {
		return true
	}
	switch header.Protocol {
	case packetmeta.ProtocolUDP:
		if header.DestinationPort == dnsPort {
			d.query(header, packet)
		}
	case packetmeta.ProtocolTCP:
		d.reset(header, packet)
	}
	return true
}

// query answers a UDP question on a goroutine of its own, or drops it when
// as many are being answered as allowed.
func (d *dnsTUN) query(header packetmeta.Header, packet []byte) {
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength+8 > header.Length {
		return
	}
	payload := append([]byte(nil), packet[headerLength+8:header.Length]...)
	select {
	case d.slots <- struct{}{}:
	default:
		d.busy.Add(1)
		return
	}
	go func() {
		defer func() { <-d.slots }()
		response := d.answer(d.ctx, payload)
		if len(response) == 0 {
			return
		}
		d.send(packetmeta.UDPDatagram(resolverAddress, header.Source, dnsPort, header.SourcePort, response))
	}()
}

// reset answers a TCP segment to the resolver with a reset (RFC 9293
// §3.10.7.1): DNS over TCP, and Android's Private DNS probe on port 853,
// fail at once.
func (d *dnsTUN) reset(header packetmeta.Header, packet []byte) {
	if header.TCPFlags&packetmeta.TCPFlagRST != 0 {
		return
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength+20 > header.Length {
		return
	}
	segment := packet[headerLength:header.Length]
	sequence := binary.BigEndian.Uint32(segment[4:8])
	acknowledgment := binary.BigEndian.Uint32(segment[8:12])
	if header.TCPFlags&packetmeta.TCPFlagACK != 0 {
		d.send(packetmeta.TCPSegment(resolverAddress, header.Source, header.DestinationPort, header.SourcePort,
			acknowledgment, 0, packetmeta.TCPFlagRST))
		return
	}
	length := uint32(header.Length - headerLength - int(segment[12]>>4)*4) //nolint:gosec // G115: within the packet
	if header.TCPFlags&packetmeta.TCPFlagSYN != 0 {
		length++
	}
	if header.TCPFlags&tcpFlagFIN != 0 {
		length++
	}
	d.send(packetmeta.TCPSegment(resolverAddress, header.Source, header.DestinationPort, header.SourcePort,
		0, sequence+length, packetmeta.TCPFlagRST|packetmeta.TCPFlagACK))
}

// send queues a packet for the writer, dropping it when the queue is full.
func (d *dnsTUN) send(packet []byte) {
	if packet == nil {
		return
	}
	select {
	case d.writes <- packet:
	case <-d.ctx.Done():
	default:
		d.busy.Add(1)
	}
}

// writeLoop writes the queued packets into the TUN: a write may wait for
// an interface being replaced, never the data plane's read.
func (d *dnsTUN) writeLoop() {
	defer d.writer.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case packet := <-d.writes:
			offset := int(d.offset.Load())
			buffer := make([]byte, offset+len(packet))
			copy(buffer[offset:], packet)
			_, _ = d.Write([][]byte{buffer}, offset)
		}
	}
}

// Close stops answering and closes the device; an answer still being
// looked up is dropped.
func (d *dnsTUN) Close() error {
	var err error
	d.once.Do(func() {
		d.cancel()
		err = d.Device.Close()
		d.writer.Wait()
	})
	return err
}

// dropped returns the questions and packets dropped as too many.
func (d *dnsTUN) dropped() uint64 { return d.busy.Load() }
