package meshgw

import (
	"context"
	"log/slog"
	"math"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// memoryLimitShare of the container's limit is the Go runtime's soft
	// limit, leaving room for what it does not count (K1b design §8).
	memoryLimitShare = 0.85
	// heapWatermark of the soft limit is where new watches, followed logs,
	// upgrades and lists are refused, until the live heap falls back under
	// heapRelease of it, so pressure does not flap each GC cycle.
	heapWatermark = 0.70
	heapRelease   = 0.60
	// memoryCheck paces the heap reading.
	memoryCheck = time.Second
)

// cgroupLimitFiles hold the container's memory limit: cgroup v2, then v1.
var cgroupLimitFiles = []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}

// applyMemoryLimit sets the runtime's soft memory limit to 85% of the
// container's, unless GOMEMLIMIT set one, and returns the limit in force;
// math.MaxInt64 for none.
//
// set is debug.SetMemoryLimit.
func applyMemoryLimit(getenv func(string) string, readFile func(string) ([]byte, error), set func(int64) int64,
	logger *slog.Logger,
) int64 {
	if getenv("GOMEMLIMIT") != "" {
		limit := set(-1)
		logger.Info("memory limit from GOMEMLIMIT", "soft_bytes", limit)
		return limit
	}
	for _, path := range cgroupLimitFiles {
		raw, err := readFile(path)
		if err != nil {
			continue
		}
		limit, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		// "max", or v1's huge number for none.
		if err != nil || limit <= 0 || limit >= math.MaxInt64/2 {
			logger.Info("no container memory limit", "file", path)
			return set(-1)
		}
		soft := int64(float64(limit) * memoryLimitShare)
		set(soft)
		logger.Info("memory limit set", "container_bytes", limit, "soft_bytes", soft)
		return soft
	}
	limit := set(-1)
	logger.Info("memory limit in force", "soft_bytes", limit)
	return limit
}

// memoryWatch reports the heap past its watermark of the soft limit.
type memoryWatch struct {
	watermark uint64 // 0: no limit, never pressed
	release   uint64
	pressed   atomic.Bool
	heap      atomic.Uint64
	read      func() uint64
}

func newMemoryWatch(limit int64) *memoryWatch {
	watch := &memoryWatch{read: heapBytes}
	if limit > 0 && limit < math.MaxInt64 {
		watch.watermark = uint64(float64(limit) * heapWatermark)
		watch.release = uint64(float64(limit) * heapRelease)
	}
	return watch
}

// Pressure reports the heap past its watermark at the last reading.
func (watch *memoryWatch) Pressure() bool { return watch.pressed.Load() }

// Run reads the heap every second until ctx ends.
func (watch *memoryWatch) Run(ctx context.Context) error {
	ticker := time.NewTicker(memoryCheck)
	defer ticker.Stop()
	for {
		watch.check()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (watch *memoryWatch) check() {
	heap := watch.read()
	watch.heap.Store(heap)
	switch {
	case watch.watermark == 0:
	case heap > watch.watermark:
		watch.pressed.Store(true)
	case heap < watch.release:
		watch.pressed.Store(false)
	}
}

// heapBytes is the live heap as the last GC marked it: not the garbage not
// swept yet, which the heap's objects count would add (review b6b H1).
func heapBytes() uint64 {
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}

// readFile is os.ReadFile, for applyMemoryLimit.
func readFile(path string) ([]byte, error) { return os.ReadFile(path) } //nolint:gosec // fixed cgroup paths
