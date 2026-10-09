// Package runtimehealth exposes bounded, aggregate Go runtime health data.
package runtimehealth

import "runtime"

// Snapshot contains process-wide counters that are safe for the authenticated
// local status API. It intentionally excludes stack traces, labels, addresses,
// command lines, and allocation profiles.
type Snapshot struct {
	Goroutines      int
	HeapAllocBytes  uint64
	HeapInUseBytes  uint64
	HeapObjects     uint64
	StackInUseBytes uint64
	SysBytes        uint64
	GCCycles        uint32
}

// Read returns a point-in-time process runtime snapshot.
func Read() Snapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)

	return Snapshot{
		Goroutines:      runtime.NumGoroutine(),
		HeapAllocBytes:  memory.HeapAlloc,
		HeapInUseBytes:  memory.HeapInuse,
		HeapObjects:     memory.HeapObjects,
		StackInUseBytes: memory.StackInuse,
		SysBytes:        memory.Sys,
		GCCycles:        memory.NumGC,
	}
}
