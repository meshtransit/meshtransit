package flowcount

import (
	"math"
	"math/bits"
	"slices"
)

const (
	sketchBits  = 1024
	sketchWords = sketchBits / 64
	// MaxSamplePorts bounds the destination ports a denial record names.
	MaxSamplePorts = 8
)

// portSketch estimates how many distinct destination ports a denial saw in
// 128 bytes (linear counting), and keeps the first ports as samples, so a
// port scan costs the same as one denied packet.
type portSketch struct {
	bitmap  [sketchWords]uint64
	samples [MaxSamplePorts]uint16
	sampled uint8
}

// add takes seed from the counter, so a scanner cannot pick ports that share
// a slot and report fewer than it probed.
func (s *portSketch) add(port uint16, seed uint32) {
	// Linear counting needs a random-looking slot: consecutive ports, as a
	// scan sends them, must not fill the bitmap evenly (lowbias32 mixer).
	slot := uint32(port) ^ seed
	slot ^= slot >> 16
	slot *= 0x7feb352d
	slot ^= slot >> 15
	slot *= 0x846ca68b
	slot ^= slot >> 16
	slot %= sketchBits
	word, bit := slot/64, slot%64
	if s.bitmap[word]&(1<<bit) != 0 {
		return
	}
	s.bitmap[word] |= 1 << bit
	// A new slot is a new port: samples never repeat, and never outnumber
	// distinct().
	if int(s.sampled) < MaxSamplePorts {
		s.samples[s.sampled] = port
		s.sampled++
	}
}

// distinct is the linear counting estimate, never below the slots set (so
// never below the samples); a full bitmap reports its largest estimate
// rather than infinity.
func (s *portSketch) distinct() uint32 {
	return linearCount(s.bitmap[:])
}

// linearCount estimates the distinct values hashed into words: about 3 %
// off typically while under twice as many values as bits.
func linearCount(words []uint64) uint32 {
	slots := len(words) * 64
	set := 0
	for _, word := range words {
		set += bits.OnesCount64(word)
	}
	if set == 0 {
		return 0
	}
	empty := max(slots-set, 1)
	estimate := -float64(slots) * math.Log(float64(empty)/float64(slots))
	return uint32(max(math.Round(estimate), float64(set)))
}

func (s *portSketch) samplePorts() []uint32 {
	ports := make([]uint32, 0, s.sampled)
	for _, port := range s.samples[:s.sampled] {
		ports = append(ports, uint32(port))
	}
	slices.Sort(ports)
	return ports
}
