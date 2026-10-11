package mapsession

import (
	"bytes"
	"encoding/binary"
	"math/bits"

	"meshtransit.net/core/internal/domain/node"
)

// connectivityMap is a persistent hash array mapped trie from Node to its
// latest transient connectivity. set returns a new map that shares every
// untouched branch with the old one (O(log32 N) copying), so many streams
// can hold different versions of one Network's table at no per-stream cost.
// The zero value is an empty map.
type connectivityMap struct {
	root *hamtNode
	size int
}

const (
	hamtBits = 5
	hamtMask = 1<<hamtBits - 1
)

// hamtNode holds one slot per set bit of bitmap, in bit order. A slot is
// either a child node or a leaf of values sharing one full 64-bit hash.
type hamtNode struct {
	bitmap uint32
	slots  []hamtSlot
}

type hamtSlot struct {
	child  *hamtNode
	hash   uint64
	values []Connectivity // leaf; more than one only on a full hash collision
}

// hashNodeID mixes all 128 bits of a Node ID (UUIDv7 leads with a
// timestamp, so its first bytes alone would cluster).
func hashNodeID(id node.ID) uint64 {
	raw := [16]byte(id)
	high := binary.BigEndian.Uint64(raw[:8])
	low := binary.BigEndian.Uint64(raw[8:])
	value := high ^ bits.RotateLeft64(low, 29) ^ 0x9e3779b97f4a7c15
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	return value ^ value>>31
}

// compareNodeIDs orders Node IDs as their canonical strings would sort,
// without formatting them.
func compareNodeIDs(left, right node.ID) int {
	leftRaw, rightRaw := [16]byte(left), [16]byte(right)
	return bytes.Compare(leftRaw[:], rightRaw[:])
}

func (values connectivityMap) len() int { return values.size }

func (values connectivityMap) get(id node.ID) (Connectivity, bool) {
	return values.root.lookup(hashNodeID(id), id)
}

// set returns a map with value stored under its Node, replacing any value
// the Node had.
func (values connectivityMap) set(value Connectivity) connectivityMap {
	id := value.key.nodeID
	hash := hashNodeID(id)
	_, existed := values.root.lookup(hash, id)
	next := connectivityMap{root: values.root.insert(hash, 0, value), size: values.size}
	if !existed {
		next.size++
	}
	return next
}

// each visits every value once, in no particular order.
func (values connectivityMap) each(visit func(Connectivity)) { values.root.each(visit) }

func (current *hamtNode) lookup(hash uint64, id node.ID) (Connectivity, bool) {
	for shift := uint(0); current != nil; shift += hamtBits {
		bit := uint32(1) << (hash >> shift & hamtMask)
		if current.bitmap&bit == 0 {
			return Connectivity{}, false
		}
		slot := current.slots[bits.OnesCount32(current.bitmap&(bit-1))]
		if slot.child != nil {
			current = slot.child
			continue
		}
		if slot.hash != hash {
			return Connectivity{}, false
		}
		for _, value := range slot.values {
			if value.key.nodeID == id {
				return value, true
			}
		}
		return Connectivity{}, false
	}
	return Connectivity{}, false
}

// insert returns a copy of the path to value's slot with value stored.
func (current *hamtNode) insert(hash uint64, shift uint, value Connectivity) *hamtNode {
	bit := uint32(1) << (hash >> shift & hamtMask)
	if current == nil {
		return &hamtNode{bitmap: bit, slots: []hamtSlot{{hash: hash, values: []Connectivity{value}}}}
	}
	position := bits.OnesCount32(current.bitmap & (bit - 1))
	if current.bitmap&bit == 0 {
		slots := make([]hamtSlot, len(current.slots)+1)
		copy(slots, current.slots[:position])
		slots[position] = hamtSlot{hash: hash, values: []Connectivity{value}}
		copy(slots[position+1:], current.slots[position:])
		return &hamtNode{bitmap: current.bitmap | bit, slots: slots}
	}
	slots := append([]hamtSlot(nil), current.slots...)
	slot := slots[position]
	switch {
	case slot.child != nil:
		slots[position] = hamtSlot{child: slot.child.insert(hash, shift+hamtBits, value)}
	case slot.hash == hash:
		values := make([]Connectivity, 0, len(slot.values)+1)
		replaced := false
		for _, existing := range slot.values {
			if existing.key.nodeID == value.key.nodeID {
				existing, replaced = value, true
			}
			values = append(values, existing)
		}
		if !replaced {
			values = append(values, value)
		}
		slots[position] = hamtSlot{hash: hash, values: values}
	default:
		// Two hashes that agree on every bit so far differ at a later level.
		child := (*hamtNode)(nil)
		for _, existing := range slot.values {
			child = child.insert(slot.hash, shift+hamtBits, existing)
		}
		slots[position] = hamtSlot{child: child.insert(hash, shift+hamtBits, value)}
	}
	return &hamtNode{bitmap: current.bitmap, slots: slots}
}

func (current *hamtNode) each(visit func(Connectivity)) {
	if current == nil {
		return
	}
	for _, slot := range current.slots {
		if slot.child != nil {
			slot.child.each(visit)
			continue
		}
		for _, value := range slot.values {
			visit(value)
		}
	}
}
