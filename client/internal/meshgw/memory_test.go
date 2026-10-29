package meshgw

import (
	"errors"
	"log/slog"
	"math"
	"testing"
)

// The soft limit is 85% of the container's, unless GOMEMLIMIT set one or
// there is none.
func TestApplyMemoryLimit(t *testing.T) {
	t.Parallel()
	var set []int64
	fake := func(limit int64) int64 {
		set = append(set, limit)
		if limit < 0 {
			return math.MaxInt64
		}
		return limit
	}
	files := func(content string) func(string) ([]byte, error) {
		return func(path string) ([]byte, error) {
			if path == cgroupLimitFiles[0] {
				return []byte(content), nil
			}
			return nil, errors.New("absent")
		}
	}
	none := func(string) string { return "" }
	logger := slog.New(slog.DiscardHandler)
	if got := applyMemoryLimit(none, files("1073741824\n"), fake, logger); got != 912680550 || set[0] != 912680550 {
		t.Fatalf("1 GiB: %d, %v", got, set)
	}
	if got := applyMemoryLimit(none, files("max\n"), fake, logger); got != math.MaxInt64 {
		t.Fatalf("no limit: %d", got)
	}
	gomemlimit := func(name string) string {
		if name == "GOMEMLIMIT" {
			return "700MiB"
		}
		return ""
	}
	set = nil
	applyMemoryLimit(gomemlimit, files("1073741824"), fake, logger)
	if len(set) != 1 || set[0] != -1 {
		t.Fatalf("GOMEMLIMIT set: %v", set)
	}
}

// The heap past 70% of the soft limit presses; no limit never does.
func TestMemoryWatch(t *testing.T) {
	t.Parallel()
	for value, want := range map[uint64]bool{600: false, 700: false, 701: true} {
		watch := newMemoryWatch(1000)
		watch.read = func() uint64 { return value }
		watch.check()
		if watch.Pressure() != want {
			t.Fatalf("heap %d: %t", value, watch.Pressure())
		}
	}
	unlimited := newMemoryWatch(math.MaxInt64)
	unlimited.read = func() uint64 { return math.MaxUint64 }
	unlimited.check()
	if unlimited.Pressure() {
		t.Fatal("pressed without a limit")
	}
}

// Pressure holds until the heap falls under 60%, so it does not flap with
// each GC cycle (review b6b H1).
func TestMemoryWatchHysteresis(t *testing.T) {
	t.Parallel()
	heap := uint64(0)
	watch := newMemoryWatch(1000)
	watch.read = func() uint64 { return heap }
	for _, step := range []struct {
		heap uint64
		want bool
	}{{650, false}, {710, true}, {650, true}, {610, true}, {590, false}, {650, false}} {
		heap = step.heap
		watch.check()
		if watch.Pressure() != step.want {
			t.Fatalf("heap %d: %t", step.heap, watch.Pressure())
		}
	}
}

// The v1 file is read when v2's is absent; v1's unlimited sentinel and
// garbage mean no limit.
func TestApplyMemoryLimitCgroupV1(t *testing.T) {
	t.Parallel()
	identity := func(limit int64) int64 {
		if limit < 0 {
			return math.MaxInt64
		}
		return limit
	}
	v1 := func(content string) func(string) ([]byte, error) {
		return func(path string) ([]byte, error) {
			if path == cgroupLimitFiles[1] {
				return []byte(content), nil
			}
			return nil, errors.New("absent")
		}
	}
	none := func(string) string { return "" }
	logger := slog.New(slog.DiscardHandler)
	if got := applyMemoryLimit(none, v1("536870912"), identity, logger); got != 456340275 {
		t.Fatalf("v1 512 MiB: %d", got)
	}
	for _, content := range []string{"9223372036854771712", "lots"} {
		if got := applyMemoryLimit(none, v1(content), identity, logger); got != math.MaxInt64 {
			t.Fatalf("%q: %d", content, got)
		}
	}
	if got := applyMemoryLimit(none, func(string) ([]byte, error) { return nil, errors.New("absent") }, identity,
		logger); got != math.MaxInt64 {
		t.Fatalf("no file: %d", got)
	}
}

// The replica's connections and streams fit its memory, at most the
// design's counts (review TD-CLI-82 M1).
func TestLimitsForMemory(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		limit                int64
		connections, streams int
	}{
		"512 MiB pod": {456340275, 514, 858},
		"1 GiB pod":   {912680550, 1024, 1972},
		"128 MiB pod": {114085068, 64, 128},
		"no limit":    {math.MaxInt64, 1024, 2048},
	} {
		limits := limitsFor(test.limit)
		if limits.Connections != test.connections || limits.Streams != test.streams {
			t.Errorf("%s: %d connections, %d streams", name, limits.Connections, limits.Streams)
		}
	}
}
