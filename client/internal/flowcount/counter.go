package flowcount

import (
	"crypto/rand"
	"encoding/binary"
	"hash/maphash"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/packetmeta"
)

const (
	shardCount = 16
	// MaxWindowRecords is the most records a batch holds (flowlog-v1 §6):
	// flow and denial keys of one window together never exceed it.
	MaxWindowRecords = 65536
	// DeviceKeys and ForwarderKeys bound the flow keys of one window: a
	// Device's, and a router's, exit node's or gateway's (design §7).
	DeviceKeys    = 4096
	ForwarderKeys = MaxWindowRecords - ForwarderDenyKeys
	// DeviceDenyKeys and ForwarderDenyKeys bound the denial keys.
	DeviceDenyKeys    = 1024
	ForwarderDenyKeys = 4096
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// TCP states a record ends a window in (flowlog-v1 FlowRecord.TcpState).
const (
	tcpStateNone uint8 = iota
	tcpStateObserved
	tcpStateSYN
	tcpStateEstablished
	tcpStateClosing
	tcpStateReset
)

type flowKey struct {
	class           Class
	direction       Direction
	protocol        uint8
	source          netip.Addr
	destination     netip.Addr
	destinationPort uint16
	peer            ID
	scope           ID
}

type flowCount struct {
	packetsOut, bytesOut uint64
	packetsIn, bytesIn   uint64
	connections          uint32
	firstSeen, lastSeen  int64
	tcpState             uint8
	ended                bool
}

type denyKey struct {
	class       Class
	direction   Direction
	reason      DenyReason
	protocol    uint8
	source      netip.Addr
	destination netip.Addr
	peer        ID
	scope       ID
}

type denyCount struct {
	packets, bytes      uint64
	firstSeen, lastSeen int64
	ports               portSketch
}

// shard is padded to two cache lines so neighbouring shards' locks never
// share one.
type shard struct {
	mu    sync.Mutex
	flows map[flowKey]*flowCount
	deny  map[denyKey]*denyCount
	_     [104]byte
}

// Overflow is what a window could not key, flows and denials together: the
// traffic is counted, its endpoints are not. Keys estimates the distinct
// keys refused (linear counting over 4,096 slots; it saturates near 34,000).
type Overflow struct {
	Keys, Packets, Bytes uint64
}

// Counter counts one Network's traffic of the current window. It is safe for
// concurrent use; Observe takes one shard lock and does one map lookup.
type Counter struct {
	// Read on every packet, never written after NewCounter.
	seed       maphash.Seed
	sketchSeed [4]byte
	maxFlows   int64
	maxDenials int64
	flowSecret [32]byte
	_          [64]byte
	// Written when a key is added; each on its own cache line.
	flowKeys    atomic.Int64
	_           [56]byte
	denyKeys    atomic.Int64
	_           [56]byte
	overflow    overflowCounters
	windowStart atomic.Int64
	shards      [shardCount]shard
}

const overflowWords = 64

type overflowCounters struct {
	keys           [overflowWords]atomic.Uint64
	packets, bytes atomic.Uint64
}

// NewCounter returns a counter whose windows hold at most maxFlows flow keys
// and maxDenials denial keys, together at most MaxWindowRecords; larger
// caps are a configuration bug and panic.
func NewCounter(maxFlows, maxDenials int, now time.Time) *Counter {
	if maxFlows < 0 || maxDenials < 0 || maxFlows+maxDenials > MaxWindowRecords {
		panic("flowcount: caps exceed a batch")
	}
	counter := &Counter{seed: maphash.MakeSeed(), maxFlows: int64(maxFlows), maxDenials: int64(maxDenials)}
	// Never fail (crypto/rand); the sketch seed is apart from the flow
	// secret, so distinct_ports tells nothing of the flow IDs' key.
	_, _ = rand.Read(counter.flowSecret[:])
	_, _ = rand.Read(counter.sketchSeed[:])
	for index := range counter.shards {
		counter.shards[index].flows = map[flowKey]*flowCount{}
		counter.shards[index].deny = map[denyKey]*denyCount{}
	}
	counter.windowStart.Store(now.UnixMilli())
	return counter
}

// valid holds an observation to the values a record may carry: anything
// else is a filter bug, dropped rather than allowed to spoil a batch.
func (observation Observation) valid() bool {
	return observation.Class >= ClassMesh && observation.Class <= ClassExit &&
		observation.Direction >= DirectionInbound && observation.Direction <= DirectionForwarded &&
		observation.Deny <= DenyNoise
}

// Observe counts one packet. Noise is not counted at all, allowed or denied.
func (c *Counter) Observe(observation Observation, now time.Time) {
	if c == nil || observation.Deny == DenyNoise || !observation.valid() || isNoise(observation.Header) {
		return
	}
	at := now.UnixMilli()
	if observation.Deny != DenyNone {
		c.observeDenial(observation, at)
		return
	}
	key := flowKeyOf(observation)
	hash := maphash.Comparable(c.seed, key)
	shard := &c.shards[hash%shardCount]
	shard.mu.Lock()
	count, exists := shard.flows[key]
	if !exists {
		if !reserve(&c.flowKeys, c.maxFlows) {
			shard.mu.Unlock()
			c.addOverflow(hash, observation.Header)
			return
		}
		count = &flowCount{firstSeen: at, lastSeen: at}
		if !isTCP(observation.Header) {
			count.connections = 1
		}
		shard.flows[key] = count
	}
	count.add(observation, at)
	shard.mu.Unlock()
}

func (c *Counter) observeDenial(observation Observation, at int64) {
	key := denyKeyOf(observation)
	hash := maphash.Comparable(c.seed, key)
	shard := &c.shards[hash%shardCount]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	count, exists := shard.deny[key]
	if !exists {
		if !reserve(&c.denyKeys, c.maxDenials) {
			c.addOverflow(hash, observation.Header)
			return
		}
		count = &denyCount{firstSeen: at, lastSeen: at}
		shard.deny[key] = count
	}
	count.packets++
	count.bytes += uint64(max(observation.Header.Length, 0))
	count.firstSeen, count.lastSeen = min(count.firstSeen, at), max(count.lastSeen, at)
	if protocol := observation.Header.Protocol; protocol == packetmeta.ProtocolTCP || protocol == packetmeta.ProtocolUDP {
		count.ports.add(observation.Header.DestinationPort, binary.BigEndian.Uint32(c.sketchSeed[:]))
	}
}

// reserve takes one of limit keys; at the limit it costs one atomic load.
func reserve(keys *atomic.Int64, limit int64) bool {
	if keys.Load() >= limit {
		return false
	}
	if keys.Add(1) > limit {
		keys.Add(-1)
		return false
	}
	return true
}

func (c *Counter) addOverflow(hash uint64, header packetmeta.Header) {
	slot := (hash >> 32) % (overflowWords * 64)
	word := &c.overflow.keys[slot/64]
	if bit := uint64(1) << (slot % 64); word.Load()&bit == 0 {
		word.Or(bit)
	}
	c.overflow.packets.Add(1)
	c.overflow.bytes.Add(uint64(max(header.Length, 0)))
}

func isTCP(header packetmeta.Header) bool { return header.Protocol == packetmeta.ProtocolTCP }

func (count *flowCount) add(observation Observation, at int64) {
	length := uint64(max(observation.Header.Length, 0))
	if observation.Reply {
		count.packetsIn++
		count.bytesIn += length
	} else {
		count.packetsOut++
		count.bytesOut += length
	}
	count.firstSeen, count.lastSeen = min(count.firstSeen, at), max(count.lastSeen, at)
	if !isTCP(observation.Header) {
		return
	}
	flags := observation.Header.TCPFlags
	switch {
	case flags&(tcpSYN|tcpACK) == tcpSYN:
		// A SYN from the source opens a connection; a retransmitted SYN
		// counts again.
		if !observation.Reply {
			count.connections++
		}
		count.tcpState = tcpStateSYN
	case flags&tcpRST != 0:
		count.tcpState, count.ended = tcpStateReset, true
	case flags&tcpFIN != 0:
		if count.tcpState != tcpStateReset {
			count.tcpState = tcpStateClosing
		}
		count.ended = true
	case count.tcpState == tcpStateClosing || count.tcpState == tcpStateReset:
		// The last ACKs of a close keep the close.
	case flags&tcpACK != 0:
		count.tcpState = tcpStateEstablished
	default:
		count.tcpState = tcpStateObserved
	}
}

// flowKeyOf puts the flow's source first, collapses the source's ephemeral
// port and strips every Internet address (flowlog-v1 §6).
func flowKeyOf(observation Observation) flowKey {
	header := observation.Header
	source, destination := header.Source.Unmap(), header.Destination.Unmap()
	destinationPort := header.DestinationPort
	if observation.Reply {
		source, destination = destination, source
		destinationPort = header.SourcePort
	}
	key := flowKey{
		class: observation.Class, direction: observation.Direction, protocol: header.Protocol,
		destinationPort: destinationPort, scope: observation.Scope,
	}
	key.source, key.destination, key.peer = keyEndpoints(observation.Class, source, destination, observation.Peer)
	return key
}

func denyKeyOf(observation Observation) denyKey {
	header := observation.Header
	key := denyKey{
		class: observation.Class, direction: observation.Direction, reason: observation.Deny,
		protocol: header.Protocol, scope: observation.Scope,
	}
	key.source, key.destination, key.peer = keyEndpoints(observation.Class, header.Source.Unmap(),
		header.Destination.Unmap(), observation.Peer)
	return key
}

// keyEndpoints applies the privacy rules flows and denials share: a share
// names only its contract, never the other Workspace's Device; an exit
// node keeps only pool, protocol and destination port; an Internet address
// never leaves the node.
func keyEndpoints(class Class, source, destination netip.Addr, peer ID) (netip.Addr, netip.Addr, ID) {
	if class == ClassShare {
		peer = ID{}
	}
	if class == ClassExit || !isPrivate(source) {
		source, peer = netip.Addr{}, ID{}
	}
	if !isPrivate(destination) {
		destination = netip.Addr{}
	}
	return source, destination, peer
}
