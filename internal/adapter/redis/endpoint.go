package redis

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
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
	ErrLoadConnectivity    = errors.New("redis: load connectivity")
	observeEndpointsScript = redisclient.NewScript(`
local current_endpoint_generation = redis.call('HGET', KEYS[1], 'generation')
local current_payload = redis.call('HGET', KEYS[1], 'payload')
if (current_endpoint_generation == false) ~= (current_payload == false) then
    return -1
end
if current_endpoint_generation ~= false then
    local stored_generation = tonumber(current_endpoint_generation)
    local requested_generation = tonumber(ARGV[1])
    if stored_generation == nil or requested_generation == nil then
        return -1
    end
    if requested_generation < stored_generation then
        return 0
    end
end

local current_presence_generation = redis.call('HGET', KEYS[2], 'generation')
if current_presence_generation ~= false then
    local presence_generation = tonumber(current_presence_generation)
    local requested_generation = tonumber(ARGV[1])
    if presence_generation == nil or requested_generation == nil then
        return -1
    end
    if requested_generation < presence_generation then
        return 0
    end
end

redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'payload', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
if current_endpoint_generation == ARGV[1] and current_payload == ARGV[2] then
    return 2
end
redis.call('PUBLISH', ARGV[4], ARGV[5])
return 1
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
    if endpoint_generation == generation then
        result[#result + 1] = endpoint_payload
    else
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

type observeEndpointsFunc func(
	context.Context,
	string,
	string,
	int64,
	[]byte,
	time.Duration,
	string,
	[]byte,
) (int64, error)
type loadEndpointsFunc func(context.Context, string, int64) ([]byte, error)
type loadConnectivityFunc func(context.Context, []string, []int64) ([]any, error)

const maximumConnectivityLoadBatch = 128

// ObserveEndpoints stores a bounded non-authoritative connectivity report. A
// false result is a successful rejection by a newer Node generation.
func (client *Client) ObserveEndpoints(
	ctx context.Context,
	scope network.Scope,
	observation node.EndpointObservation,
) (bool, error) {
	if ctx == nil || client == nil || client.observeEndpoints == nil ||
		!scope.IsValid() || !observation.IsValid() {
		return false, ErrInvalidOptions
	}
	payload, err := encodeEndpointSet(observation.Set())
	if err != nil {
		return false, err
	}
	defer clear(payload)
	wakeup, err := encodeConnectivityWakeup(
		scope,
		observation.NodeID(),
		observation.Generation(),
		mapsession.ConnectivityChangeEndpoints,
	)
	if err != nil {
		return false, err
	}
	defer clear(wakeup)
	startedAt := time.Now()
	result, err := client.observeEndpoints(
		ctx,
		endpointKey(observation.NodeID()),
		presenceKeyForNode(observation.NodeID()),
		observation.Generation(),
		payload,
		observation.TTL(),
		connectivityChangedChannel,
		wakeup,
	)
	if err != nil {
		client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, err)
		return false, errors.Join(ErrObserveEndpoints, err)
	}
	if result < 0 || result > 2 {
		client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, ErrObserveEndpoints)
		return false, ErrObserveEndpoints
	}
	client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, nil)
	return result > 0, nil
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
	if err != nil || len(raw) != len(keys)*2 {
		return nil, ErrLoadConnectivity
	}
	values := make([]mapsession.Connectivity, len(keys))
	for index, key := range keys {
		payload, present, err := connectivityPayload(raw[index*2])
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
		online, ok := raw[index*2+1].(int64)
		if !ok || online < 0 || online > 1 {
			return nil, ErrLoadConnectivity
		}
		values[index], err = mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key:                key,
			EndpointSet:        set,
			EndpointSetPresent: present,
			Online:             online == 1,
		})
		if err != nil {
			return nil, ErrLoadConnectivity
		}
	}
	return values, nil
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
	endpoints := make([]node.Endpoint, len(wire.Endpoints))
	for index, value := range wire.Endpoints {
		address, err := netip.ParseAddrPort(value.Address)
		if err != nil {
			return node.EndpointSet{}, ErrLoadEndpoints
		}
		endpoints[index], err = node.NewEndpoint(address, value.Source)
		if err != nil {
			return node.EndpointSet{}, ErrLoadEndpoints
		}
	}
	set, err := node.NewEndpointSet(discoveryKey, endpoints)
	if err != nil {
		return node.EndpointSet{}, ErrLoadEndpoints
	}
	return set, nil
}

func endpointKey(nodeID node.ID) string { return endpointKeyPrefix + nodeID.String() }
