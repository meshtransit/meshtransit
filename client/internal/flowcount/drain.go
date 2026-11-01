package flowcount

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
)

// Window is one window's records, ready for a FlowBatch.
type Window struct {
	StartMS, EndMS int64
	Records        []*flowlogv1.FlowRecord
	Overflow       Overflow
}

// Drain ends the current window at now and returns its records. cluster is
// the gateway's cluster, or the zero ID on any other node.
//
// All shards are swapped first, so the next window's keys never compete
// with this one's for the cap. The window's bounds widen to cover every
// record (a packet counted while the shards were swapped, a clock step), and
// end is always after start. A window longer than the receiver takes (twice
// window_s, after a suspend) is the batch builder's to split or drop. The
// next window starts at now, so it may overlap a widened one.
func (c *Counter) Drain(now time.Time, cluster ID) Window {
	type taken struct {
		flows   map[flowKey]*flowCount
		denials map[denyKey]*denyCount
	}
	var all [shardCount]taken
	end := now.UnixMilli()
	start := c.windowStart.Swap(end)
	for index := range c.shards {
		shard := &c.shards[index]
		shard.mu.Lock()
		all[index] = taken{flows: shard.flows, denials: shard.deny}
		shard.flows, shard.deny = map[flowKey]*flowCount{}, map[denyKey]*denyCount{}
		shard.mu.Unlock()
	}
	// The budget comes back only once every shard holds the new window:
	// a shard still on this one must not take it.
	flowKeys, denyKeys := 0, 0
	for _, shard := range all {
		flowKeys, denyKeys = flowKeys+len(shard.flows), denyKeys+len(shard.denials)
	}
	c.flowKeys.Add(-int64(flowKeys))
	c.denyKeys.Add(-int64(denyKeys))
	keys := flowKeys + denyKeys
	var overflowKeys [overflowWords]uint64
	for index := range c.overflow.keys {
		overflowKeys[index] = c.overflow.keys[index].Swap(0)
	}
	window := Window{Records: make([]*flowlogv1.FlowRecord, 0, keys), Overflow: Overflow{
		Keys: uint64(linearCount(overflowKeys[:])), Packets: c.overflow.packets.Swap(0),
		Bytes: c.overflow.bytes.Swap(0),
	}}
	for _, shard := range all {
		for key, count := range shard.flows {
			start, end = min(start, count.firstSeen), max(end, count.lastSeen)
			window.Records = append(window.Records, c.flowRecord(key, count, cluster))
		}
		for key, count := range shard.denials {
			start, end = min(start, count.firstSeen), max(end, count.lastSeen)
			window.Records = append(window.Records, denyRecord(key, count, cluster))
		}
	}
	window.StartMS, window.EndMS = start, max(end, start+1)
	return window
}

func (c *Counter) flowRecord(key flowKey, count *flowCount, cluster ID) *flowlogv1.FlowRecord {
	record := &flowlogv1.FlowRecord{
		Kind: flowlogv1.FlowRecord_FLOW, Class: recordClass(key.class), Protocol: uint32(key.protocol),
		SourceIp: addressBytes(key.source), DestinationIp: addressBytes(key.destination),
		DestinationPort: uint32(key.destinationPort), Primary: primary(key.class, key.direction),
		Direction: recordDirection(key.direction), Initiator: flowlogv1.FlowRecord_SOURCE,
		TcpState:   flowlogv1.FlowRecord_TcpState(count.tcpState),
		PacketsOut: count.packetsOut, BytesOut: count.bytesOut, PacketsIn: count.packetsIn, BytesIn: count.bytesIn,
		Connections: count.connections, FirstSeenMs: count.firstSeen, LastSeenMs: count.lastSeen, Ended: count.ended,
		FlowId: c.flowID(key),
	}
	setIDs(record, key.class, key.direction, key.peer, key.scope, cluster)
	return record
}

func denyRecord(key denyKey, count *denyCount, cluster ID) *flowlogv1.FlowRecord {
	record := &flowlogv1.FlowRecord{
		Kind: flowlogv1.FlowRecord_DENY, Class: recordClass(key.class), Protocol: uint32(key.protocol),
		SourceIp: addressBytes(key.source), DestinationIp: addressBytes(key.destination), Primary: true,
		PacketsOut: count.packets, BytesOut: count.bytes, FirstSeenMs: count.firstSeen, LastSeenMs: count.lastSeen,
		DenyReason:    flowlogv1.FlowRecord_DenyReason(key.reason),
		DistinctPorts: count.ports.distinct(), SamplePorts: count.ports.samplePorts(),
	}
	// A denial's source is the packet's sender.
	record.Direction = recordDirection(key.direction)
	setIDs(record, key.class, key.direction, key.peer, key.scope, cluster)
	return record
}

// setIDs names the other end and the share, Site or pool from this node's
// map; this node itself is the batch's reporter.
func setIDs(record *flowlogv1.FlowRecord, class Class, direction Direction, peer, scope, cluster ID) {
	if peer != (ID{}) {
		if direction == DirectionOutbound {
			record.DestinationDeviceId = peer[:]
		} else {
			record.SourceDeviceId = peer[:]
		}
	}
	if scope != (ID{}) {
		switch class {
		case ClassShare:
			record.TrustContractId = scope[:]
		case ClassSite:
			record.SiteId = scope[:]
		case ClassExit:
			record.ExitPoolId = scope[:]
		case ClassMesh:
		}
	}
	if cluster != (ID{}) {
		record.ClusterId = cluster[:]
	}
}

// primary marks the one record of a piece of traffic a SIEM counts
// (flowlog-v1 §6): the receiving node of mesh traffic, each Workspace's side
// of a share, the router of a Site, the exit node.
func primary(class Class, direction Direction) bool {
	switch class {
	case ClassMesh:
		return direction == DirectionInbound
	case ClassShare:
		return true
	case ClassSite, ClassExit:
		return direction == DirectionForwarded
	default:
		return false
	}
}

// flowID is stable across the windows of one key and this counter, and
// reveals nothing of the key without the counter's secret.
func (c *Counter) flowID(key flowKey) []byte {
	hash := sha256.New()
	hash.Write(c.flowSecret[:])
	hash.Write([]byte{byte(key.class), byte(key.direction), key.protocol})
	source, destination := key.source.As16(), key.destination.As16()
	hash.Write(source[:])
	hash.Write(destination[:])
	hash.Write(binary.BigEndian.AppendUint16(nil, key.destinationPort))
	hash.Write(key.peer[:])
	hash.Write(key.scope[:])
	return hash.Sum(nil)[:16]
}

func addressBytes(address netip.Addr) []byte {
	if !address.IsValid() {
		return nil
	}
	return address.Unmap().AsSlice()
}

func recordClass(class Class) flowlogv1.FlowRecord_Class {
	return flowlogv1.FlowRecord_Class(class)
}

func recordDirection(direction Direction) flowlogv1.FlowRecord_Direction {
	return flowlogv1.FlowRecord_Direction(direction)
}
