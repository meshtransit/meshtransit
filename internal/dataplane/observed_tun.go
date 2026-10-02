package dataplane

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// observedTUN enforces packet policy before forwarding and exposes only
// ephemeral slices of accepted packets to an observer. The observer contract
// forbids retaining the bytes.
type observedTUN struct {
	tun.Device
	filter   *policyFilter
	observer PacketObserver
}

func (d *observedTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < 0 || len(sizes) < len(bufs) {
		return 0, errors.New("dataplane: invalid tun read buffers")
	}
	for {
		count, err := d.Device.Read(bufs, sizes, offset)
		if count < 0 || count > len(bufs) || count > len(sizes) {
			return 0, errors.New("dataplane: invalid tun read count")
		}
		allowed := 0
		for index := range count {
			packet, valid := packetFromReadBuffer(bufs[index], sizes[index], offset)
			if !valid || (d.filter != nil && !d.filter.ProcessPacket(PacketOutbound, packet)) {
				continue
			}
			if allowed != index {
				if len(packet) > len(bufs[allowed])-offset {
					return 0, errors.New("dataplane: tun read packet cannot be compacted")
				}
				copy(bufs[allowed][offset:], packet)
			}
			sizes[allowed] = len(packet)
			if d.observer != nil {
				d.observer.ObservePacket(
					PacketOutbound,
					bufs[allowed][offset:offset+len(packet)],
				)
			}
			allowed++
		}
		if allowed > 0 || err != nil || count == 0 {
			return allowed, err
		}
	}
}

func (d *observedTUN) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, errors.New("dataplane: invalid tun write offset")
	}
	allowed := make([][]byte, 0, len(bufs))
	for _, buffer := range bufs {
		if offset > len(buffer) {
			continue
		}
		packet := buffer[offset:]
		if d.filter != nil && !d.filter.ProcessPacket(PacketInbound, packet) {
			continue
		}
		allowed = append(allowed, buffer)
	}
	if len(allowed) == 0 {
		return 0, nil
	}
	// Native Linux TUN writes report bytes, while this interface reports
	// packets. A nil error means every allowed buffer was accepted; normalize
	// the result so callers see the portable packet-count contract.
	_, err := d.Device.Write(allowed, offset)
	if err != nil {
		return 0, err
	}
	if d.observer != nil {
		for _, buffer := range allowed {
			d.observer.ObservePacket(PacketInbound, buffer[offset:])
		}
	}

	return len(allowed), nil
}

func packetFromReadBuffer(buffer []byte, size, offset int) ([]byte, bool) {
	if size < 0 || offset > len(buffer) || size > len(buffer)-offset {
		return nil, false
	}

	return buffer[offset : offset+size], true
}
