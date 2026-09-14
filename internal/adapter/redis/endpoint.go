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
	ErrLoadEndpoints       = errors.New("redis: load endpoints")
	observeEndpointsScript = redisclient.NewScript(`
local current_endpoint_generation = redis.call('HGET', KEYS[1], 'generation')
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
return 1
`)
	loadEndpointsScript = redisclient.NewScript(`
local current_generation = redis.call('HGET', KEYS[1], 'generation')
if current_generation == ARGV[1] then
    return redis.call('HGET', KEYS[1], 'payload')
end
return false
`)
)

type observeEndpointsFunc func(
	context.Context,
	string,
	string,
	int64,
	[]byte,
	time.Duration,
) (int64, error)
type loadEndpointsFunc func(context.Context, string, int64) ([]byte, error)

// ObserveEndpoints stores a bounded non-authoritative connectivity report. A
// false result is a successful rejection by a newer Node generation.
func (client *Client) ObserveEndpoints(
	ctx context.Context,
	observation node.EndpointObservation,
) (bool, error) {
	if ctx == nil || client == nil || client.observeEndpoints == nil || !observation.IsValid() {
		return false, ErrInvalidOptions
	}
	payload, err := encodeEndpointSet(observation.Set())
	if err != nil {
		return false, err
	}
	defer clear(payload)
	startedAt := time.Now()
	result, err := client.observeEndpoints(
		ctx,
		endpointKey(observation.NodeID()),
		presenceKeyForNode(observation.NodeID()),
		observation.Generation(),
		payload,
		observation.TTL(),
	)
	if err != nil {
		client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, err)
		return false, errors.Join(ErrObserveEndpoints, err)
	}
	if result != 0 && result != 1 {
		client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, ErrObserveEndpoints)
		return false, ErrObserveEndpoints
	}
	client.metrics.observeCommand(redisCommandObserveEndpoints, startedAt, nil)
	return result == 1, nil
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
