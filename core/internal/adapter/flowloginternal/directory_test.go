package flowloginternal

import (
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/workspace"
)

func testDirectory(revision int64) *connectionlog.ReceiverDirectory {
	return &connectionlog.ReceiverDirectory{
		Revision: revision, BuiltAt: time.Unix(1_900_000_000, 0),
		MeshPrefixes:  []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
		AliasPrefixes: []netip.Prefix{netip.MustParsePrefix("100.127.0.0/16")},
		Tags:          []connectionlog.ReceiverName{{ID: testID(40), Name: "prod"}},
		Groups:        []connectionlog.ReceiverName{{ID: testID(41), Name: "ops"}, {ID: testID(42), Name: "dev"}},
		Devices: []connectionlog.ReceiverDevice{
			{
				ID: node.ID(testID(10)), Kind: connectionlog.DeviceKindStandard, State: connectionlog.DeviceStateActive,
				Hostname: "laptop", Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
				OwnerKind: connectionlog.OwnerKindMember, Pseudonym: [16]byte{1, 2, 3}, Tags: []int{0}, Groups: []int{1},
			},
			{
				ID: node.ID(testID(11)), Kind: connectionlog.DeviceKindKubernetesGateway,
				State: connectionlog.DeviceStateDeleted, OwnerKind: connectionlog.OwnerKindWorkspace,
			},
		},
		Sites: []connectionlog.ReceiverSite{{
			ID: testID(50), Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			Routers: []node.ID{node.ID(testID(10))},
		}},
		ExitPools: []connectionlog.ReceiverExitPool{{ID: testID(60), Candidates: []node.ID{node.ID(testID(10))}}},
		ContractAliases: []connectionlog.ReceiverContractAlias{{
			Contract: testID(70), Address: netip.MustParseAddr("100.127.0.9"),
		}},
	}
}

func directoryPath(workspaceIndex, networkIndex int) string {
	return scopedPrefix + workspace.ID(testID(workspaceIndex)).String() + "/networks/" +
		network.ID(testID(networkIndex)).String() + "/directory"
}

// A directory answers its content, its revision in a header, and the
// time each answer is given; a build answers for a minute, and one that
// finds nothing new answers 304.
func TestDirectory(t *testing.T) {
	reader := &fakeReader{directory: testDirectory(7)}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	path := f.base + directoryPath(1, 2)
	response, body, err := get(t, client, path, nil)
	if err != nil || response.status != http.StatusOK {
		t.Fatalf("GET directory = %v, %v", response, err)
	}
	directory := decode(t, body, &flowlogv1.FlowDirectory{})
	devices := directory.GetDevices()
	if directory.GetRevision() != 7 || directory.GetBuiltAtMs() != 1_900_000_000_000 ||
		directory.GetGeneratedAtMs() != f.clock.Now().UnixMilli() || response.header.Get(DirectoryRevisionHeader) != "7" ||
		len(directory.GetMeshPrefixes()) != 2 || len(directory.GetMeshPrefixes()[0].GetAddress()) != 4 ||
		directory.GetMeshPrefixes()[1].GetBits() != 48 || len(directory.GetAliasPrefixes()) != 1 ||
		len(devices) != 2 || devices[0].GetHostname() != "laptop" || devices[0].GetOwnerPseudonym()[0] != 1 ||
		devices[0].GetGroups()[0] != 1 || devices[0].GetTags()[0] != 0 || len(devices[0].GetAddresses()[0]) != 4 ||
		devices[1].GetState() != flowlogv1.FlowDirectory_DELETED || devices[1].GetOwnerPseudonym() != nil ||
		devices[1].GetKind() != flowlogv1.FlowDirectory_KUBERNETES_GATEWAY ||
		len(directory.GetSites()[0].GetRouters()) != 1 || len(directory.GetExitPools()[0].GetCandidates()) != 1 ||
		len(directory.GetContractAliases()) != 1 || len(directory.GetContractAliases()[0].GetAddress()) != 4 ||
		len(directory.GetContractAliases()[0].GetTrustContractId()) != 16 {
		t.Fatalf("directory = %v", directory)
	}
	tag := response.header.Get("ETag")
	f.clock.advance(directoryAge - time.Second)
	if response, body, _ := get(t, client, path, nil); response.status != http.StatusOK || reader.directoriesAt != 1 ||
		decode(t, body, &flowlogv1.FlowDirectory{}).GetGeneratedAtMs() != f.clock.Now().UnixMilli() {
		t.Fatalf("within a minute: %v, %d builds", response, reader.directoriesAt)
	}
	if response.header.Get("Content-Encoding") != "" || response.header.Get(DirectoryBuiltAtHeader) != "1900000000000" {
		t.Fatalf("headers %v", response.header)
	}
	// The minute past, the stale build answers while the next is read; a
	// new build of the same content at another time keeps the tag, and its
	// 304 still says when it was built.
	f.clock.advance(time.Second)
	reader.set(func(r *fakeReader) { r.directory.BuiltAt = time.Unix(1_900_000_060, 0) })
	if response, _, err := get(t, client, path, http.Header{"If-None-Match": {tag}}); err != nil ||
		response.status != http.StatusNotModified || response.header.Get(DirectoryBuiltAtHeader) != "1900000000000" {
		t.Fatalf("the stale build: %v, %v", response, err)
	}
	waitForBuilds(t, reader, 2)
	if response, _, err := get(t, client, path, http.Header{"If-None-Match": {tag}}); err != nil ||
		response.status != http.StatusNotModified || response.header.Get(DirectoryBuiltAtHeader) != "1900000060000" ||
		response.header.Get(DirectoryGeneratedAtHeader) == "" {
		t.Fatalf("an unchanged build: %v, %v", response, err)
	}
	// A new revision is new content.
	f.clock.advance(directoryAge)
	reader.set(func(r *fakeReader) { r.directory = testDirectory(8) })
	_, _, _ = get(t, client, path, nil)
	waitForBuilds(t, reader, 3)
	if response, _, _ := get(t, client, path, http.Header{"If-None-Match": {tag}}); response.status != http.StatusOK ||
		response.header.Get(DirectoryRevisionHeader) != "8" || response.header.Get("ETag") == tag {
		t.Fatalf("a new revision: %v", response)
	}
	// A build past the serve limit is never answered: requests wait for
	// the next.
	f.clock.advance(directoryServeLimit)
	reader.set(func(r *fakeReader) { r.directory = testDirectory(9) })
	if response, _, _ := get(t, client, path, nil); response.header.Get(DirectoryRevisionHeader) != "9" {
		t.Fatalf("past the limit: %v", response)
	}
	// Each Network has its own build.
	if response, _, _ := get(t, client, f.base+directoryPath(1, 3), nil); response.status != http.StatusOK ||
		reader.directoriesAt != 5 {
		t.Fatalf("another Network: %v, %d builds", response, reader.directoriesAt)
	}
}

// waitForBuilds waits for the reader to have finished count builds and the
// cache to hold the last one.
func waitForBuilds(t *testing.T, reader *fakeReader, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		reader.mu.Lock()
		started := reader.directoriesAt
		reader.mu.Unlock()
		if started >= count {
			time.Sleep(20 * time.Millisecond) // the build's end takes the cache lock after the read
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%d builds, want %d", reader.directoriesAt, count)
}

// No destination is 404; a Network too large and an outage are 503, and
// a failure answers for five seconds.
func TestDirectoryRefusals(t *testing.T) {
	reader := &fakeReader{}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	path := f.base + directoryPath(1, 2)
	if response, _, err := get(t, client, path, nil); err != nil || response.status != http.StatusNotFound {
		t.Fatalf("no destination: %v, %v", response, err)
	}
	f.clock.advance(directoryFailureAge)
	reader.set(func(r *fakeReader) { r.fail = errors.Join(ErrDirectoryTooLarge, errors.New("store")) })
	if response, _, err := get(t, client, path, nil); err != nil || response.status != http.StatusServiceUnavailable ||
		response.header.Get("Retry-After") != "60" {
		t.Fatalf("too large: %v, %v", response, err)
	}
	f.clock.advance(directoryFailureAge)
	reader.set(func(r *fakeReader) { r.fail = errors.New("database down") })
	for range 3 {
		if response, _, err := get(t, client, path, nil); err != nil || response.status != http.StatusServiceUnavailable ||
			response.header.Get("Retry-After") != "5" {
			t.Fatalf("an outage: %v, %v", response, err)
		}
	}
	if reader.directoriesAt != 3 {
		t.Fatalf("%d builds", reader.directoriesAt)
	}
	// A directory that does not encode is an outage, never a partial one.
	reader.set(func(r *fakeReader) {
		r.fail = nil
		r.directory = testDirectory(7)
		r.directory.Devices[0].Tags = []int{5}
	})
	f.clock.advance(directoryFailureAge)
	if response, _, _ := get(t, client, path, nil); response.status != http.StatusServiceUnavailable {
		t.Fatalf("an index outside the dictionary: %v", response)
	}
	for _, target := range []string{
		scopedPrefix + "nope/networks/" + network.ID(testID(2)).String() + "/directory",
		directoryPath(1, 2) + "/extra",
	} {
		if response, _, err := get(t, client, f.base+target, nil); err != nil || response.status != http.StatusNotFound {
			t.Errorf("%s: %v, %v", target, response, err)
		}
	}
}

// Requests during one build all wait on it.
func TestDirectoryShareTheBuildInFlight(t *testing.T) {
	reader := &fakeReader{directory: testDirectory(7), directoryBlock: make(chan struct{})}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	path := f.base + directoryPath(1, 2)
	var wait sync.WaitGroup
	statuses := make(chan int, 6)
	for range 6 {
		wait.Go(func() {
			response, _, err := get(t, client, path, nil)
			if err != nil {
				statuses <- 0
				return
			}
			statuses <- response.status
		})
	}
	for {
		reader.mu.Lock()
		started := reader.directoriesAt
		reader.mu.Unlock()
		if started > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the other requests join the build
	close(reader.directoryBlock)
	wait.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
	}
	if reader.directoriesAt != 1 {
		t.Fatalf("built %d times", reader.directoriesAt)
	}
}

// The cache drops the least recently used finished builds past its bounds
// and never one in flight.
func TestDirectoryCacheEvicts(t *testing.T) {
	t.Parallel()
	cache := newDirectoryCache()
	done := make(chan struct{})
	close(done)
	add := func(index, size int, finished bool) *directoryEntry {
		scope := must(network.NewScope(workspace.ID(testID(1)), network.ID(testID(index))))
		entry := &directoryEntry{scope: scope, done: make(chan struct{}), body: make([]byte, size)}
		if finished {
			entry.done = done
		}
		entry.element = cache.order.PushFront(entry)
		cache.entries[scope] = entry
		cache.bytes += size
		return entry
	}
	inFlight := add(1, 0, false)
	oldest := add(2, directoryCacheBytes/2, true)
	add(3, directoryCacheBytes/2, true)
	add(4, 1, true)
	cache.mu.Lock()
	cache.evict()
	cache.mu.Unlock()
	if _, ok := cache.entries[oldest.scope]; ok || cache.bytes != directoryCacheBytes/2+1 {
		t.Fatalf("after evicting: %d entries, %d bytes", len(cache.entries), cache.bytes)
	}
	if _, ok := cache.entries[inFlight.scope]; !ok {
		t.Fatal("a build in flight was dropped")
	}
}
