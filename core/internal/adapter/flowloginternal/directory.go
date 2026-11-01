package flowloginternal

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// A Network's directory (connection logs design §16d, C61, C62): one build
// per Network, shared by the requests of a minute.
const (
	// directoryAge is how long a build answers; a failure answers for
	// directoryFailureAge.
	directoryAge        = time.Minute
	directoryFailureAge = 5 * time.Second
	// directoryServeLimit is the oldest build answered while its successor
	// is read (C62: never older than 2 minutes).
	directoryServeLimit = 2 * time.Minute
	// directoryBuilds bounds concurrent builds: the receiver's pool has 4
	// connections, and the other reads, revocations first, keep 2 (review
	// s4c2a H1).
	directoryBuilds = 2
	// directoryBuildTimeout bounds a build with its wait for a slot; the
	// store bounds the read itself to 30 seconds.
	directoryBuildTimeout = 40 * time.Second
	// directoryCacheBytes and directoryCacheEntries bound a replica's
	// cache; the least recently used finished builds go first.
	directoryCacheBytes   = 256 << 20
	directoryCacheEntries = 1 << 16
)

// Headers of a directory answer, on 200 and 304 alike: a receiver that
// holds the content still learns its revision and how fresh it is (review
// s4c2a H2). Times are Unix milliseconds.
const (
	DirectoryRevisionHeader    = "MeshTransit-Directory-Revision"
	DirectoryBuiltAtHeader     = "MeshTransit-Directory-Built-At"
	DirectoryGeneratedAtHeader = "MeshTransit-Directory-Generated-At"
)

// ErrDirectoryTooLarge is what a Reader answers for a Network with more
// Devices than one directory holds: the API answers 503, never a cut list.
var ErrDirectoryTooLarge = errors.New("flowloginternal: directory too large")

// directoryEntry is one Network's build; done closes when it ends, after
// which its fields never change. body is the answer without
// generated_at_ms, which each request writes after it. previous is the
// last good build, answered while this one is read and dropped when it
// ends.
type directoryEntry struct {
	scope     network.Scope
	done      chan struct{}
	startedAt time.Time
	body      []byte
	tag       string
	revision  int64
	builtAtMs int64
	err       error
	element   *list.Element
	previous  *directoryEntry
}

// directoryCache holds the builds by Network, most recently used first.
// bytes counts the bodies of the entries and of their previous builds.
type directoryCache struct {
	mu      sync.Mutex
	entries map[network.Scope]*directoryEntry
	order   *list.List
	bytes   int
	slots   chan struct{}
}

func newDirectoryCache() *directoryCache {
	return &directoryCache{
		entries: make(map[network.Scope]*directoryEntry), order: list.New(), slots: make(chan struct{}, directoryBuilds),
	}
}

func (handler *handler) serveDirectory(response http.ResponseWriter, request *http.Request) {
	scope, ok := scopeOf(request.URL.Path, "directory")
	if !ok {
		handler.metrics.request("directory", "not_found")
		http.NotFound(response, request)
		return
	}
	build := handler.sharedDirectory(scope)
	select {
	case <-build.done:
	case <-request.Context().Done():
		handler.metrics.request("directory", "canceled")
		return
	}
	switch {
	case errors.Is(build.err, ErrNotFound):
		handler.metrics.request("directory", "not_found")
		http.NotFound(response, request)
		return
	case errors.Is(build.err, ErrDirectoryTooLarge):
		handler.metrics.request("directory", "too_large")
		response.Header().Set("Retry-After", "60")
		http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	case build.err != nil:
		handler.unavailable(response, "directory")
		return
	}
	generatedAt := handler.now().UnixMilli()
	header := response.Header()
	header.Set(DirectoryRevisionHeader, strconv.FormatInt(build.revision, 10))
	header.Set(DirectoryBuiltAtHeader, strconv.FormatInt(build.builtAtMs, 10))
	header.Set(DirectoryGeneratedAtHeader, strconv.FormatInt(generatedAt, 10))
	header.Set("ETag", build.tag)
	header.Set("Cache-Control", "no-store")
	if matchesTag(request.Header.Get("If-None-Match"), build.tag) {
		handler.metrics.request("directory", "not_modified")
		response.WriteHeader(http.StatusNotModified)
		return
	}
	// The shared build goes out as it is, then generated_at_ms: fields
	// written one after another are one message (protobuf encoding). Its
	// IDs are random bytes, so it goes uncompressed and uncopied (review
	// s4c2a M2).
	trailer := protowire.AppendTag(nil, directoryGeneratedAtField, protowire.VarintType)
	trailer = protowire.AppendVarint(trailer, uint64(generatedAt))
	header.Set("Content-Type", contentType)
	header.Set("Content-Length", strconv.Itoa(len(build.body)+len(trailer)))
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(build.body); err == nil {
		_, _ = response.Write(trailer)
	}
	handler.metrics.request("directory", "ok")
	handler.metrics.responseBytes("directory", len(build.body)+len(trailer))
}

// sharedDirectory answers the Network's build when it is fresh or in
// flight, and starts one otherwise. While a build is read, the last good
// one answers if it is under directoryServeLimit (review s4c2a M3).
func (handler *handler) sharedDirectory(scope network.Scope) *directoryEntry {
	cache := handler.directories
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := handler.now()
	current, ok := cache.entries[scope]
	if !ok {
		return handler.startDirectory(scope, now, nil)
	}
	select {
	case <-current.done:
	default:
		cache.order.MoveToFront(current.element)
		if previous := current.previous; previous != nil && now.Sub(previous.startedAt) < directoryServeLimit {
			return previous
		}
		return current
	}
	age := directoryAge
	if current.err != nil {
		age = directoryFailureAge
	}
	if now.Sub(current.startedAt) < age {
		cache.order.MoveToFront(current.element)
		return current
	}
	if current.err != nil || now.Sub(current.startedAt) >= directoryServeLimit {
		cache.remove(current)
		return handler.startDirectory(scope, now, nil)
	}
	// The stale build becomes the next one's previous: its bytes stay
	// counted.
	cache.order.Remove(current.element)
	delete(cache.entries, scope)
	handler.startDirectory(scope, now, current)
	return current
}

// startDirectory starts a build; the caller holds mu.
func (handler *handler) startDirectory(scope network.Scope, now time.Time, previous *directoryEntry,
) *directoryEntry {
	cache := handler.directories
	build := &directoryEntry{scope: scope, done: make(chan struct{}), startedAt: now, previous: previous}
	build.element = cache.order.PushFront(build)
	cache.entries[scope] = build
	cache.evict()
	go handler.buildDirectory(build)
	return build
}

// remove forgets entry; the caller holds mu.
func (cache *directoryCache) remove(entry *directoryEntry) {
	cache.order.Remove(entry.element)
	delete(cache.entries, entry.scope)
	cache.bytes -= len(entry.body)
	if entry.previous != nil {
		cache.bytes -= len(entry.previous.body)
		entry.previous = nil
	}
}

// evict drops the least recently used finished builds over the bounds; the
// caller holds mu.
func (cache *directoryCache) evict() {
	for element := cache.order.Back(); element != nil &&
		(cache.bytes > directoryCacheBytes || cache.order.Len() > directoryCacheEntries); {
		previous := element.Prev()
		entry, _ := element.Value.(*directoryEntry)
		select {
		case <-entry.done:
			cache.remove(entry)
		default:
		}
		element = previous
	}
}

// buildDirectory reads the build and, when it ends, drops the previous one.
// Its goroutine ends with the read, which directoryBuildTimeout bounds.
func (handler *handler) buildDirectory(build *directoryEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), directoryBuildTimeout)
	defer cancel()
	encoded, revision, err := handler.readDirectory(ctx, build.scope)
	cache := handler.directories
	cache.mu.Lock()
	defer cache.mu.Unlock()
	listed := cache.entries[build.scope] == build
	if listed && build.previous != nil {
		cache.bytes -= len(build.previous.body)
	}
	build.previous = nil
	build.err = err
	if err == nil {
		build.body, build.revision, build.tag, build.builtAtMs = encoded.content, revision, encoded.tag, encoded.builtAtMs
		if listed {
			cache.bytes += len(encoded.content)
		}
	}
	close(build.done)
	if listed {
		cache.evict()
	}
}

// encodedDirectory is a build's answer without generated_at_ms, and the
// strong ETag of its content: built_at_ms is outside it, so a build that
// finds nothing new answers 304 (C61).
type encodedDirectory struct {
	content   []byte
	tag       string
	builtAtMs int64
}

// readDirectory reads and encodes a directory once a build slot is free.
func (handler *handler) readDirectory(ctx context.Context, scope network.Scope) (encodedDirectory, int64, error) {
	select {
	case handler.directories.slots <- struct{}{}:
		defer func() { <-handler.directories.slots }()
	case <-ctx.Done():
		return encodedDirectory{}, 0, ctx.Err()
	}
	directory, err := handler.reader.Directory(ctx, scope)
	if err != nil {
		return encodedDirectory{}, 0, err
	}
	message, err := directoryMessage(directory)
	if err != nil {
		return encodedDirectory{}, 0, err
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return encodedDirectory{}, 0, err
	}
	digest := sha256.Sum256(content)
	content = protowire.AppendTag(content, directoryBuiltAtField, protowire.VarintType)
	content = protowire.AppendVarint(content, uint64(directory.BuiltAt.UnixMilli()))
	return encodedDirectory{
		content: content, tag: `"` + base64.RawURLEncoding.EncodeToString(digest[:16]) + `"`,
		builtAtMs: directory.BuiltAt.UnixMilli(),
	}, directory.Revision, nil
}

// The fields of FlowDirectory each answer appends.
const (
	directoryBuiltAtField     protowire.Number = 2
	directoryGeneratedAtField protowire.Number = 3
)

var errInvalidDirectory = errors.New("flowloginternal: invalid directory")

var (
	directoryKinds = map[string]flowlogv1.FlowDirectory_Kind{
		connectionlog.DeviceKindStandard:          flowlogv1.FlowDirectory_STANDARD,
		connectionlog.DeviceKindKubernetesGateway: flowlogv1.FlowDirectory_KUBERNETES_GATEWAY,
	}
	directoryStates = map[string]flowlogv1.FlowDirectory_State{
		connectionlog.DeviceStateActive:    flowlogv1.FlowDirectory_ACTIVE,
		connectionlog.DeviceStateExpired:   flowlogv1.FlowDirectory_EXPIRED,
		connectionlog.DeviceStateSuspended: flowlogv1.FlowDirectory_SUSPENDED,
		connectionlog.DeviceStateRevoked:   flowlogv1.FlowDirectory_REVOKED,
		connectionlog.DeviceStateDeleted:   flowlogv1.FlowDirectory_DELETED,
	}
	directoryOwnerKinds = map[string]flowlogv1.FlowDirectory_OwnerKind{
		connectionlog.OwnerKindMember:    flowlogv1.FlowDirectory_MEMBER,
		connectionlog.OwnerKindWorkspace: flowlogv1.FlowDirectory_WORKSPACE,
	}
)

// directoryMessage encodes a directory without built_at_ms and
// generated_at_ms.
func directoryMessage(directory connectionlog.ReceiverDirectory) (*flowlogv1.FlowDirectory, error) {
	if directory.Revision < 1 {
		return nil, errInvalidDirectory
	}
	message := &flowlogv1.FlowDirectory{
		Revision:     uint64(directory.Revision),
		MeshPrefixes: directoryPrefixes(directory.MeshPrefixes), AliasPrefixes: directoryPrefixes(directory.AliasPrefixes),
		Tags: directoryNames(directory.Tags), Groups: directoryNames(directory.Groups),
	}
	for _, device := range directory.Devices {
		encoded, err := directoryDevice(device, len(directory.Tags), len(directory.Groups))
		if err != nil {
			return nil, err
		}
		message.Devices = append(message.Devices, encoded)
	}
	for _, site := range directory.Sites {
		id := site.ID.Bytes()
		message.Sites = append(message.Sites, &flowlogv1.FlowDirectory_Site{
			SiteId: id[:], Prefixes: directoryPrefixes(site.Prefixes), Routers: directoryDeviceIDs(site.Routers),
		})
	}
	for _, alias := range directory.ContractAliases {
		id := alias.Contract.Bytes()
		message.ContractAliases = append(message.ContractAliases, &flowlogv1.FlowDirectory_ContractAlias{
			TrustContractId: id[:], Address: alias.Address.AsSlice(),
		})
	}
	for _, pool := range directory.ExitPools {
		id := pool.ID.Bytes()
		message.ExitPools = append(message.ExitPools, &flowlogv1.FlowDirectory_ExitPool{
			ExitPoolId: id[:], Candidates: directoryDeviceIDs(pool.Candidates),
		})
	}
	return message, nil
}

func directoryDevice(device connectionlog.ReceiverDevice, tags, groups int) (*flowlogv1.FlowDirectory_Device, error) {
	kind, kindOK := directoryKinds[device.Kind]
	state, stateOK := directoryStates[device.State]
	ownerKind, ownerOK := directoryOwnerKinds[device.OwnerKind]
	if !kindOK || !stateOK || !ownerOK {
		return nil, errInvalidDirectory
	}
	id := publicid.ID(device.ID).Bytes()
	encoded := &flowlogv1.FlowDirectory_Device{
		DeviceId: id[:], Kind: kind, State: state, Hostname: device.Hostname, OwnerKind: ownerKind,
		NamesTruncated: device.NamesTruncated,
	}
	if device.Pseudonym != ([16]byte{}) {
		encoded.OwnerPseudonym = device.Pseudonym[:]
	}
	for _, address := range device.Addresses {
		encoded.Addresses = append(encoded.Addresses, address.AsSlice())
	}
	var err error
	if encoded.Tags, err = directoryIndexes(device.Tags, tags); err != nil {
		return nil, err
	}
	if encoded.Groups, err = directoryIndexes(device.Groups, groups); err != nil {
		return nil, err
	}
	return encoded, nil
}

func directoryIndexes(indexes []int, size int) ([]uint32, error) {
	encoded := make([]uint32, 0, len(indexes))
	for _, index := range indexes {
		if index < 0 || index >= size {
			return nil, errInvalidDirectory
		}
		encoded = append(encoded, uint32(index)) //nolint:gosec // checked within a slice's length
	}
	return encoded, nil
}

func directoryPrefixes(prefixes []netip.Prefix) []*flowlogv1.FlowDirectory_Prefix {
	encoded := make([]*flowlogv1.FlowDirectory_Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		encoded = append(encoded, &flowlogv1.FlowDirectory_Prefix{
			Address: prefix.Addr().AsSlice(), Bits: uint32(prefix.Bits()), //nolint:gosec // 0 to 128
		})
	}
	return encoded
}

func directoryNames(names []connectionlog.ReceiverName) []*flowlogv1.FlowDirectory_Name {
	encoded := make([]*flowlogv1.FlowDirectory_Name, 0, len(names))
	for _, name := range names {
		id := name.ID.Bytes()
		encoded = append(encoded, &flowlogv1.FlowDirectory_Name{Id: id[:], Name: name.Name})
	}
	return encoded
}

func directoryDeviceIDs(ids []node.ID) [][]byte {
	encoded := make([][]byte, 0, len(ids))
	for _, id := range ids {
		raw := publicid.ID(id).Bytes()
		encoded = append(encoded, raw[:])
	}
	return encoded
}
