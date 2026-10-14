package redis

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const (
	endpointKeyPrefix       = "meshtransit:v1:endpoints:node:"
	endpointPayloadVersion  = 1
	maxEndpointPayloadBytes = 8 << 10
)

var (
	// ErrObserveEndpoints classifies a failed or malformed Redis endpoint update.
	ErrObserveEndpoints = errors.New("redis: observe endpoints")
	// ErrLoadEndpoints classifies unavailable or corrupt Redis endpoint state.
	ErrLoadEndpoints = errors.New("redis: load endpoints")
	// ErrLoadConnectivity classifies unavailable or corrupt transient projection.
	ErrLoadConnectivity = errors.New("redis: load connectivity")
	// observeEndpointsScript always stores the latest observation and
	// announces a change at once when the Device announced none within the
	// interval (ARGV[8], Redis time), or, for a new disco key, none within
	// the disco spacing (ARGV[10]); otherwise it marks the change pending
	// for flushEndpointsScript. It answers {status, retry_after_ms}: -1
	// malformed, 0 stale generation, 1 announced, 2 unchanged, 3 pending.
	// A clock that went back counts as an ended interval, so nothing waits
	// for it.
	observeEndpointsScript = redisclient.NewScript(`
local current_endpoint_generation = redis.call('HGET', KEYS[1], 'generation')
local current_payload = redis.call('HGET', KEYS[1], 'payload')
if (current_endpoint_generation == false) ~= (current_payload == false) then
    return {-1, 0}
end
local current_preferred_relay_present = redis.call('HGET', KEYS[1], 'preferred_relay_present')
local current_preferred_relay = redis.call('HGET', KEYS[1], 'preferred_relay')
if (current_preferred_relay_present == false) ~= (current_preferred_relay == false) then
    return {-1, 0}
end
if current_endpoint_generation == false and current_preferred_relay_present ~= false then
    return {-1, 0}
end
local requested_generation = tonumber(ARGV[1])
local interval = tonumber(ARGV[8])
local disco_spacing = tonumber(ARGV[10])
if requested_generation == nil or interval == nil or interval <= 0 or
    disco_spacing == nil or disco_spacing <= 0 then
    return {-1, 0}
end
if current_endpoint_generation ~= false then
    local stored_generation = tonumber(current_endpoint_generation)
    if stored_generation == nil then
        return {-1, 0}
    end
    if requested_generation < stored_generation then
        return {0, 0}
    end
end

local current_presence_generation = redis.call('HGET', KEYS[2], 'generation')
if current_presence_generation ~= false then
    local presence_generation = tonumber(current_presence_generation)
    if presence_generation == nil then
        return {-1, 0}
    end
    if requested_generation < presence_generation then
        return {0, 0}
    end
end

local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local same_generation = current_endpoint_generation == ARGV[1]
local announced_at = nil
local disco_announced_at = nil
local pending = false
local disco_changed = true
if same_generation then
    announced_at = tonumber(redis.call('HGET', KEYS[1], 'announced_at'))
    disco_announced_at = tonumber(redis.call('HGET', KEYS[1], 'disco_announced_at'))
    pending = redis.call('HGET', KEYS[1], 'pending') == '1'
    disco_changed = redis.call('HGET', KEYS[1], 'disco') ~= ARGV[9]
elseif current_endpoint_generation ~= false then
    -- A new generation starts its own announcement history.
    redis.call('DEL', KEYS[1])
end
local unchanged = same_generation and current_payload == ARGV[2] and
    current_preferred_relay_present == ARGV[3] and current_preferred_relay == ARGV[4]

redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'payload', ARGV[2],
    'preferred_relay_present', ARGV[3], 'preferred_relay', ARGV[4], 'disco', ARGV[9])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
if unchanged and not pending then
    return {2, 0}
end
local due = announced_at == nil or now >= announced_at + interval or now < announced_at
if not due and disco_changed and
    (disco_announced_at == nil or now >= disco_announced_at + disco_spacing or now < disco_announced_at) then
    due = true
    redis.call('HSET', KEYS[1], 'disco_announced_at', now)
end
if due then
    redis.call('HSET', KEYS[1], 'announced_at', now, 'pending', '0')
    redis.call('PUBLISH', ARGV[6], ARGV[7])
    return {1, 0}
end
redis.call('HSET', KEYS[1], 'pending', '1')
return {3, announced_at + interval - now}
`)
	// flushEndpointsScript announces a pending change of the exact
	// generation once its interval ended: {1, 0} announced, {2, 0} nothing
	// pending or another generation, {3, retry_after_ms} not yet.
	flushEndpointsScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] or
    redis.call('HGET', KEYS[1], 'pending') ~= '1' then
    return {2, 0}
end
local interval = tonumber(ARGV[4])
if interval == nil or interval <= 0 then
    return {-1, 0}
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local announced_at = tonumber(redis.call('HGET', KEYS[1], 'announced_at'))
if announced_at ~= nil and now >= announced_at and now < announced_at + interval then
    return {3, announced_at + interval - now}
end
redis.call('HSET', KEYS[1], 'announced_at', now, 'pending', '0')
redis.call('PUBLISH', ARGV[2], ARGV[3])
return {1, 0}
`)
	loadEndpointsScript = redisclient.NewScript(`
local current_generation = redis.call('HGET', KEYS[1], 'generation')
if current_generation == ARGV[1] then
    return redis.call('HGET', KEYS[1], 'payload')
end
return false
`)
	loadConnectivityScript = redisclient.NewScript(`
local result = {}
for index = 1, #ARGV do
    local endpoint_key = KEYS[index * 2 - 1]
    local presence_key = KEYS[index * 2]
    local generation = ARGV[index]
    local endpoint_generation = redis.call('HGET', endpoint_key, 'generation')
    local endpoint_payload = redis.call('HGET', endpoint_key, 'payload')
    if (endpoint_generation == false) ~= (endpoint_payload == false) then
        return redis.error_reply('malformed endpoint state')
    end
    local preferred_relay_present = redis.call('HGET', endpoint_key, 'preferred_relay_present')
    local preferred_relay = redis.call('HGET', endpoint_key, 'preferred_relay')
    if (preferred_relay_present == false) ~= (preferred_relay == false) then
        return redis.error_reply('malformed preferred relay state')
    end
    if endpoint_generation == false and preferred_relay_present ~= false then
        return redis.error_reply('orphaned preferred relay state')
    end
    if endpoint_generation == generation then
        result[#result + 1] = endpoint_payload
        result[#result + 1] = preferred_relay_present
        result[#result + 1] = preferred_relay
    else
        result[#result + 1] = false
        result[#result + 1] = false
        result[#result + 1] = false
    end
    local presence_generation = redis.call('HGET', presence_key, 'generation')
    local presence_replica = redis.call('HGET', presence_key, 'replica')
    if (presence_generation == false) ~= (presence_replica == false) then
        return redis.error_reply('malformed presence state')
    end
    if presence_generation == generation then
        result[#result + 1] = 1
    else
        result[#result + 1] = 0
    end
end
return result
`)
)

// endpointObservation is one call of observeEndpointsScript.
type endpointObservation struct {
	endpointKey, presenceKey string
	generation               int64
	payload                  []byte
	preferredRelayPresent    int64
	preferredRelay           int
	ttl                      time.Duration
	channel                  string
	wakeup                   []byte
	interval                 time.Duration
	discoveryKey             string
	discoSpacing             time.Duration
}

// observeEndpointsFunc and flushEndpointsFunc answer the scripts' status
// and retry_after_ms.
type observeEndpointsFunc func(context.Context, endpointObservation) (int64, int64, error)
type flushEndpointsFunc func(ctx context.Context, endpointKey string, generation int64, channel string,
	wakeup []byte, interval time.Duration) (int64, int64, error)

// discoAnnounceSpacing lets a Device announce a new disco key at once
// three times a minute: its own map waits for that key (mtcp-v1 §8.1), so
// a reconnect is never held back by an interval, and a session cannot use
// new disco keys to bypass it.
const discoAnnounceSpacing = 20 * time.Second

// Script statuses (observeEndpointsScript, flushEndpointsScript).
const (
	endpointsStale     = 0
	endpointsAnnounced = 1
	endpointsUnchanged = 2
	endpointsPending   = 3
)

type loadEndpointsFunc func(context.Context, string, int64) ([]byte, error)
type loadConnectivityFunc func(context.Context, []string, []int64) ([]any, error)

const maximumConnectivityLoadBatch = 128

// ObserveEndpoints stores a bounded non-authoritative connectivity report
// and announces it to the Device's peers at once or, when it announced
// another within interval, later through FlushEndpoints. A false result is
// a successful rejection by a newer Node generation.
func (client *Client) ObserveEndpoints(
	ctx context.Context,
	scope network.Scope,
	observation node.EndpointObservation,
	interval time.Duration,
) (bool, mapsession.EndpointAnnouncement, error) {
	if ctx == nil || client == nil || client.observeEndpoints == nil ||
		!scope.IsValid() || !observation.IsValid() || interval <= 0 || interval >= observation.TTL() {
		return false, mapsession.EndpointAnnouncement{}, ErrInvalidOptions
	}
	payload, err := encodeEndpointSet(observation.Set())
	if err != nil {
		return false, mapsession.EndpointAnnouncement{}, err
	}
	defer clear(payload)
	wakeup, err := encodeConnectivityWakeup(
		scope,
		observation.NodeID(),
		observation.Generation(),
		mapsession.ConnectivityChangeEndpoints,
	)
	if err != nil {
		return false, mapsession.EndpointAnnouncement{}, err
	}
	defer clear(wakeup)
	preferredRelay, preferredRelayPresent := observation.PreferredRelay()
	preferredRelayPresence := int64(0)
	if preferredRelayPresent {
		preferredRelayPresence = 1
	}
	discoveryKey := observation.Set().DiscoveryKey().Bytes()
	startedAt := time.Now()
	status, retryAfter, err := client.observeEndpoints(ctx, endpointObservation{
		endpointKey:           endpointKey(observation.NodeID()),
		presenceKey:           presenceKeyForNode(observation.NodeID()),
		generation:            observation.Generation(),
		payload:               payload,
		preferredRelayPresent: preferredRelayPresence,
		preferredRelay:        preferredRelay,
		ttl:                   observation.TTL(),
		channel:               connectivityChangedChannel,
		wakeup:                wakeup,
		interval:              interval,
		discoveryKey:          hex.EncodeToString(discoveryKey[:]),
		discoSpacing:          discoAnnounceSpacing,
	})
	if err != nil {
		client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, err)
		return false, mapsession.EndpointAnnouncement{}, errors.Join(ErrObserveEndpoints, err)
	}
	announcement, outcome, valid := endpointAnnouncement(status, retryAfter, interval)
	if !valid {
		client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, ErrObserveEndpoints)
		return false, mapsession.EndpointAnnouncement{}, ErrObserveEndpoints
	}
	client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, nil)
	if status == endpointsStale {
		return false, mapsession.EndpointAnnouncement{}, nil
	}
	client.metrics.endpointAnnouncement(outcome)
	return true, announcement, nil
}

var _ mapsession.EndpointObserver = (*Client)(nil)

// FlushEndpoints announces the pending endpoint change of the exact Node
// generation once its interval ended; it answers Deferred while it has not.
// Nothing pending, or another generation, is a successful no-op.
func (client *Client) FlushEndpoints(
	ctx context.Context,
	scope network.Scope,
	nodeID node.ID,
	generation int64,
	interval time.Duration,
) (mapsession.EndpointAnnouncement, error) {
	if ctx == nil || client == nil || client.flushEndpoints == nil || !scope.IsValid() ||
		!nodeID.IsValid() || generation <= 0 || interval <= 0 {
		return mapsession.EndpointAnnouncement{}, ErrInvalidOptions
	}
	wakeup, err := encodeConnectivityWakeup(scope, nodeID, generation, mapsession.ConnectivityChangeEndpoints)
	if err != nil {
		return mapsession.EndpointAnnouncement{}, err
	}
	defer clear(wakeup)
	startedAt := time.Now()
	status, retryAfter, err := client.flushEndpoints(ctx, endpointKey(nodeID), generation,
		connectivityChangedChannel, wakeup, interval)
	if err != nil {
		client.metrics.observeCommand(redisCommandFlushEndpoints, startedAt, err)
		return mapsession.EndpointAnnouncement{}, errors.Join(ErrObserveEndpoints, err)
	}
	announcement, _, valid := endpointAnnouncement(status, retryAfter, interval)
	if !valid || status == endpointsStale {
		client.metrics.observeCommand(redisCommandFlushEndpoints, startedAt, ErrObserveEndpoints)
		return mapsession.EndpointAnnouncement{}, ErrObserveEndpoints
	}
	client.metrics.observeCommand(redisCommandFlushEndpoints, startedAt, nil)
	// Only a change announced now counts: a flush that is still early was
	// already counted as deferred when it was stored.
	if status == endpointsAnnounced {
		client.metrics.endpointAnnouncement("flushed")
	}
	return announcement, nil
}

// endpointAnnouncement maps a script answer; a pending change must name a
// retry within the interval.
func endpointAnnouncement(status, retryAfterMS int64, interval time.Duration) (
	mapsession.EndpointAnnouncement, string, bool) {
	switch status {
	case endpointsStale:
		return mapsession.EndpointAnnouncement{}, "", retryAfterMS == 0
	case endpointsAnnounced:
		return mapsession.EndpointAnnouncement{}, "announced", retryAfterMS == 0
	case endpointsUnchanged:
		return mapsession.EndpointAnnouncement{}, "unchanged", retryAfterMS == 0
	case endpointsPending:
		retryAfter := time.Duration(retryAfterMS) * time.Millisecond
		if retryAfterMS <= 0 || retryAfter > interval {
			return mapsession.EndpointAnnouncement{}, "", false
		}
		return mapsession.EndpointAnnouncement{Deferred: true, RetryAfter: retryAfter}, "deferred", true
	default:
		return mapsession.EndpointAnnouncement{}, "", false
	}
}

// LoadConnectivity returns one exact-generation transient projection per key,
// preserving input order. Missing state is represented as offline without an
// endpoint set. Reads are chunked to bound one Redis script invocation.
func (client *Client) LoadConnectivity(
	ctx context.Context,
	keys []mapsession.ConnectivityKey,
) ([]mapsession.Connectivity, error) {
	if ctx == nil || client == nil || client.loadConnectivity == nil || len(keys) == 0 ||
		len(keys) > mapsession.MaximumPeerCandidates+1 {
		return nil, ErrInvalidOptions
	}
	seen := make(map[node.ID]struct{}, len(keys))
	for _, key := range keys {
		if !key.IsValid() {
			return nil, ErrInvalidOptions
		}
		if _, exists := seen[key.NodeID()]; exists {
			return nil, ErrInvalidOptions
		}
		seen[key.NodeID()] = struct{}{}
	}

	startedAt := time.Now()
	values := make([]mapsession.Connectivity, 0, len(keys))
	for offset := 0; offset < len(keys); offset += maximumConnectivityLoadBatch {
		limit := min(offset+maximumConnectivityLoadBatch, len(keys))
		batch, err := client.loadConnectivityBatch(ctx, keys[offset:limit])
		if err != nil {
			client.metrics.observeCommand(redisCommandLoadConnectivity, startedAt, err)
			return nil, errors.Join(ErrLoadConnectivity, err)
		}
		values = append(values, batch...)
	}
	client.metrics.observeCommand(redisCommandLoadConnectivity, startedAt, nil)
	return values, nil
}

func (client *Client) loadConnectivityBatch(
	ctx context.Context,
	keys []mapsession.ConnectivityKey,
) ([]mapsession.Connectivity, error) {
	redisKeys := make([]string, 0, len(keys)*2)
	generations := make([]int64, 0, len(keys))
	for _, key := range keys {
		redisKeys = append(
			redisKeys,
			endpointKey(key.NodeID()),
			presenceKeyForNode(key.NodeID()),
		)
		generations = append(generations, key.Generation())
	}
	raw, err := client.loadConnectivity(ctx, redisKeys, generations)
	if err != nil || len(raw) != len(keys)*4 {
		return nil, ErrLoadConnectivity
	}
	values := make([]mapsession.Connectivity, len(keys))
	for index, key := range keys {
		payload, present, err := connectivityPayload(raw[index*4])
		if err != nil {
			return nil, err
		}
		var set node.EndpointSet
		if present {
			set, err = decodeEndpointSet(payload)
			clear(payload)
			if err != nil {
				return nil, err
			}
		}
		preferredRelay, preferredRelayPresent, err := connectivityPreferredRelay(
			raw[index*4+1],
			raw[index*4+2],
		)
		if err != nil {
			return nil, err
		}
		online, ok := raw[index*4+3].(int64)
		if !ok || online < 0 || online > 1 {
			return nil, ErrLoadConnectivity
		}
		values[index], err = mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key:                   key,
			EndpointSet:           set,
			EndpointSetPresent:    present,
			PreferredRelay:        preferredRelay,
			PreferredRelayPresent: preferredRelayPresent,
			Online:                online == 1,
		})
		if err != nil {
			return nil, ErrLoadConnectivity
		}
	}
	return values, nil
}

func connectivityPreferredRelay(
	presentValue any,
	regionValue any,
) (int, bool, error) {
	if presentValue == nil && regionValue == nil {
		return 0, false, nil
	}
	present, err := connectivityInteger(presentValue)
	if err != nil || present < 0 || present > 1 {
		return 0, false, ErrLoadConnectivity
	}
	regionID, err := connectivityInteger(regionValue)
	if err != nil || regionID < 0 || regionID > node.MaximumRelayRegionID ||
		present == 0 && regionID != 0 {
		return 0, false, ErrLoadConnectivity
	}
	return regionID, present == 1, nil
}

func connectivityInteger(value any) (int, error) {
	var encoded string
	switch typed := value.(type) {
	case string:
		encoded = typed
	case []byte:
		encoded = string(typed)
	default:
		return 0, ErrLoadConnectivity
	}
	if encoded == "" || len(encoded) > 5 {
		return 0, ErrLoadConnectivity
	}
	parsed, err := strconv.Atoi(encoded)
	if err != nil {
		return 0, ErrLoadConnectivity
	}
	return parsed, nil
}

func connectivityPayload(value any) ([]byte, bool, error) {
	switch typed := value.(type) {
	case nil:
		return nil, false, nil
	case string:
		if typed == "" || len(typed) > maxEndpointPayloadBytes {
			return nil, false, ErrLoadConnectivity
		}
		return []byte(typed), true, nil
	case []byte:
		if len(typed) == 0 || len(typed) > maxEndpointPayloadBytes {
			return nil, false, ErrLoadConnectivity
		}
		return bytes.Clone(typed), true, nil
	default:
		return nil, false, ErrLoadConnectivity
	}
}

// LoadEndpoints returns only the endpoint set matching the requested session
// generation. Missing, expired, older, or newer state is a clean cache miss.
func (client *Client) LoadEndpoints(
	ctx context.Context,
	nodeID node.ID,
	generation int64,
) (node.EndpointSet, bool, error) {
	if ctx == nil || client == nil || client.loadEndpoints == nil ||
		!nodeID.IsValid() || generation <= 0 {
		return node.EndpointSet{}, false, ErrInvalidOptions
	}
	startedAt := time.Now()
	payload, err := client.loadEndpoints(ctx, endpointKey(nodeID), generation)
	if err != nil {
		client.metrics.observeCommand(redisCommandLoadEndpoints, startedAt, err)
		return node.EndpointSet{}, false, errors.Join(ErrLoadEndpoints, err)
	}
	if len(payload) == 0 {
		client.metrics.observeCommand(redisCommandLoadEndpoints, startedAt, nil)
		return node.EndpointSet{}, false, nil
	}
	defer clear(payload)
	set, err := decodeEndpointSet(payload)
	client.metrics.observeCommand(redisCommandLoadEndpoints, startedAt, err)
	if err != nil {
		return node.EndpointSet{}, false, errors.Join(ErrLoadEndpoints, err)
	}
	return set, true, nil
}

type endpointSetPayload struct {
	Version      int                    `json:"version"`
	DiscoveryKey string                 `json:"discovery_key"`
	Endpoints    []endpointValuePayload `json:"endpoints"`
}

type endpointValuePayload struct {
	Address string              `json:"address"`
	Source  node.EndpointSource `json:"source"`
}

func encodeEndpointSet(set node.EndpointSet) ([]byte, error) {
	if !set.IsValid() {
		return nil, ErrObserveEndpoints
	}
	key := set.DiscoveryKey().Bytes()
	endpoints := set.Endpoints()
	values := make([]endpointValuePayload, len(endpoints))
	for index, endpoint := range endpoints {
		values[index] = endpointValuePayload{
			Address: endpoint.Address().String(),
			Source:  endpoint.Source(),
		}
	}
	payload, err := json.Marshal(endpointSetPayload{
		Version:      endpointPayloadVersion,
		DiscoveryKey: hex.EncodeToString(key[:]),
		Endpoints:    values,
	})
	if err != nil || len(payload) == 0 || len(payload) > maxEndpointPayloadBytes {
		clear(payload)
		return nil, ErrObserveEndpoints
	}
	return payload, nil
}

func decodeEndpointSet(payload []byte) (node.EndpointSet, error) {
	if len(payload) == 0 || len(payload) > maxEndpointPayloadBytes {
		return node.EndpointSet{}, ErrLoadEndpoints
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire endpointSetPayload
	if err := decoder.Decode(&wire); err != nil {
		return node.EndpointSet{}, ErrLoadEndpoints
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		wire.Version != endpointPayloadVersion || len(wire.DiscoveryKey) != 64 {
		return node.EndpointSet{}, ErrLoadEndpoints
	}
	var rawKey [32]byte
	if _, err := hex.Decode(rawKey[:], []byte(wire.DiscoveryKey)); err != nil {
		return node.EndpointSet{}, ErrLoadEndpoints
	}
	discoveryKey, err := node.NewDiscoveryKey(rawKey)
	if err != nil {
		return node.EndpointSet{}, ErrLoadEndpoints
	}
	endpoints := make([]node.Endpoint, 0, len(wire.Endpoints))
	for _, value := range wire.Endpoints {
		address, err := netip.ParseAddrPort(value.Address)
		if err != nil {
			return node.EndpointSet{}, ErrLoadEndpoints
		}
		endpoint, err := node.NewEndpoint(address, value.Source)
		if errors.Is(err, node.ErrUndistributableEndpoint) {
			// Stored before peers stopped being sent such addresses, or by
			// an older replica: dropped, the rest of the report still holds.
			continue
		}
		if err != nil {
			return node.EndpointSet{}, ErrLoadEndpoints
		}
		endpoints = append(endpoints, endpoint)
	}
	set, err := node.NewEndpointSet(discoveryKey, endpoints)
	if err != nil {
		return node.EndpointSet{}, ErrLoadEndpoints
	}
	return set, nil
}

func endpointKey(nodeID node.ID) string { return endpointKeyPrefix + nodeID.String() }

// runEndpointScript runs an endpoint script answering {status, retry_after_ms}.
func runEndpointScript(ctx context.Context, script *redisclient.Script, client redisclient.Scripter,
	keys []string, args ...any) (int64, int64, error) {
	values, err := script.Run(ctx, client, keys, args...).Int64Slice()
	if err != nil {
		return 0, 0, err
	}
	if len(values) != 2 {
		return 0, 0, ErrObserveEndpoints
	}
	return values[0], values[1], nil
}
