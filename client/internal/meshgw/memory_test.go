package meshgw

import (
	"errors"
	"log/slog"
	"math"
	"testing"

	"meshtransit.net/client/internal/kubeproxy"
	"meshtransit.net/client/internal/rbaccheck"
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
		limits := limitsFor(test.limit, DefaultTCPBuffers())
		if limits.Connections != test.connections || limits.Streams != test.streams {
			t.Errorf("%s: %d connections, %d streams", name, limits.Connections, limits.Streams)
		}
	}
}

// Larger TCP buffers leave fewer connections in the same memory, never
// fewer than the floor (K1c Q88).
func TestLimitsForTCPBuffers(t *testing.T) {
	t.Parallel()
	const soft = 456340275 // a 512 MiB pod
	defaults := limitsFor(soft, DefaultTCPBuffers())
	larger := limitsFor(soft, TCPBuffers{Receive: 1 << 20, Send: 1 << 20})
	if larger.Connections >= defaults.Connections || larger.Streams != defaults.Streams {
		t.Fatalf("1 MiB buffers: %+v, defaults %+v", larger, defaults)
	}
	// 0.6 of 335 MiB left over 2,096 KiB a connection.
	if larger.Connections != 98 {
		t.Fatalf("1 MiB buffers: %d connections, want 98", larger.Connections)
	}
	if huge := limitsFor(soft, TCPBuffers{Receive: 4 << 20, Send: 4 << 20}); huge.Connections != 64 {
		t.Fatalf("4 MiB buffers: %d connections, want the floor of 64", huge.Connections)
	}
}

// A replica serves only once rbaccheck has turned some group on (K1c Q87).
func TestAnyGroupEnabled(t *testing.T) {
	t.Parallel()
	groups := []kubeproxy.Group{{Name: "view"}, {Name: "edit"}}
	verdicts := map[string]rbaccheck.Verdict{}
	verdict := func(name string) rbaccheck.Verdict { return verdicts[name] }
	if anyGroupEnabled(groups, verdict) {
		t.Fatal("enabled before any pass")
	}
	verdicts["edit"] = rbaccheck.Verdict{Enabled: true}
	if !anyGroupEnabled(groups, verdict) {
		t.Fatal("not enabled with edit on")
	}
	if anyGroupEnabled(nil, verdict) {
		t.Fatal("enabled without groups")
	}
}

// A small stack buffer does not let more connections in: HTTP/2 may still
// queue its whole window (review K1c c1 M2).
func TestLimitsForSmallBuffers(t *testing.T) {
	t.Parallel()
	const soft = 456340275
	small := limitsFor(soft, TCPBuffers{Receive: 16 << 10, Send: 96 << 10})
	if defaults := limitsFor(soft, DefaultTCPBuffers()); small.Connections != defaults.Connections {
		t.Fatalf("16 KiB receive: %d connections, defaults %d", small.Connections, defaults.Connections)
	}
}

// Buffers whose fewest connections overrun the pod's memory are flagged
// (review K1c c1 M3).
func TestBuffersFit(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		limit int64
		tcp   TCPBuffers
		fit   bool
	}{
		"defaults, 512 MiB": {456340275, DefaultTCPBuffers(), true},
		"4 MiB, 512 MiB":    {456340275, TCPBuffers{Receive: 4 << 20, Send: 4 << 20}, false},
		"2 MiB, 1 GiB":      {912680550, TCPBuffers{Receive: 2 << 20, Send: 2 << 20}, true},
		"4 MiB, 1 GiB":      {912680550, TCPBuffers{Receive: 4 << 20, Send: 4 << 20}, false},
		"no limit":          {math.MaxInt64, TCPBuffers{Receive: 4 << 20, Send: 4 << 20}, true},
	} {
		if got := buffersFit(test.limit, test.tcp); got != test.fit {
			t.Errorf("%s: fit = %t", name, got)
		}
	}
}
