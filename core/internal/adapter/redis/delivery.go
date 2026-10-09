package redis

import (
	"context"
	"errors"
	"strconv"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/node/distribution"
)

const (
	deliveryKeyPrefix = "meshtransit:v1:delivery:node:"
	// deliveryTTL keeps the last delivery of an offline Device long enough to
	// answer "what does it still run"; every record or touch renews it.
	deliveryTTL = 30 * 24 * time.Hour
	// maximumDeliveryLoad bounds one read to one distribution page.
	maximumDeliveryLoad = distribution.MaximumPageSize
	deliveryFieldCount  = 6
)

var (
	// ErrRecordDelivery classifies a failed or malformed delivery record.
	ErrRecordDelivery = errors.New("redis: record delivery")
	// ErrLoadDeliveries classifies unavailable or corrupt delivery records.
	ErrLoadDeliveries = errors.New("redis: load deliveries")

	// A record never moves a Device backwards: an older session generation, or
	// a lower Network revision in the same generation, is ignored.
	recordDeliveryScript = redisclient.NewScript(`
local stored_generation = redis.call('HGET', KEYS[1], 'generation')
local requested_generation = tonumber(ARGV[1])
local requested_revision = tonumber(ARGV[2])
if requested_generation == nil or requested_revision == nil then
    return -1
end
if stored_generation ~= false then
    local generation = tonumber(stored_generation)
    if generation == nil then
        return -1
    end
    if requested_generation < generation then
        return 0
    end
    if requested_generation == generation then
        local revision = tonumber(redis.call('HGET', KEYS[1], 'network_revision'))
        if revision ~= nil and requested_revision < revision then
            return 0
        end
    end
end
redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'network_revision', ARGV[2],
    'policy_revision', ARGV[3], 'delivered_at', ARGV[4], 'seen_at', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return 1
`)
	// A touch only refreshes the record of the same session generation.
	touchDeliveryScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then
    return 0
end
redis.call('HSET', KEYS[1], 'seen_at', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
`)
	// KEYS alternate delivery and presence keys; each pair yields five fields
	// (empty when absent) and whether a presence lease exists.
	loadDeliveriesScript = redisclient.NewScript(`
local result = {}
for index = 1, #KEYS, 2 do
    local fields = redis.call('HMGET', KEYS[index], 'generation', 'network_revision',
        'policy_revision', 'delivered_at', 'seen_at')
    for field = 1, 5 do
        result[#result + 1] = fields[field] or ''
    end
    result[#result + 1] = tostring(redis.call('EXISTS', KEYS[index + 1]))
end
return result
`)
)

type recordDeliveryFunc func(context.Context, string, int64, int64, int64, int64, time.Duration) (int64, error)

type touchDeliveryFunc func(context.Context, string, int64, int64, time.Duration) (int64, error)

type loadDeliveriesFunc func(context.Context, []string) ([]any, error)

var (
	_ mapsession.DeliveryRecorder    = (*Client)(nil)
	_ distribution.ObservationLoader = (*Client)(nil)
)

// RecordDelivery stores the last frame a Device received. It never moves a
// Device to an older revision.
func (client *Client) RecordDelivery(ctx context.Context, delivery mapsession.Delivery) error {
	if ctx == nil || client == nil || client.recordDelivery == nil || !delivery.IsValid() {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.recordDelivery(ctx, deliveryKeyForNode(delivery.NodeID), delivery.SessionGeneration,
		delivery.NetworkRevision, delivery.PolicyRevision, delivery.DeliveredAt.UnixMilli(), deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected delivery record result")
	}
	client.metrics.observeCommand(redisCommandRecordDelivery, startedAt, err)
	if err != nil {
		return errors.Join(ErrRecordDelivery, err)
	}
	return nil
}

// TouchDelivery refreshes when a Device was last seen on its current session.
func (client *Client) TouchDelivery(ctx context.Context, nodeID node.ID, sessionGeneration int64,
	seenAt time.Time) error {
	if ctx == nil || client == nil || client.touchDelivery == nil || !nodeID.IsValid() ||
		sessionGeneration < 1 || seenAt.IsZero() {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.touchDelivery(ctx, deliveryKeyForNode(nodeID), sessionGeneration, seenAt.UnixMilli(),
		deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected delivery touch result")
	}
	client.metrics.observeCommand(redisCommandTouchDelivery, startedAt, err)
	if err != nil {
		return errors.Join(ErrRecordDelivery, err)
	}
	return nil
}

// LoadObservations returns one observation per Device, in order, together
// with whether a presence lease is live.
func (client *Client) LoadObservations(ctx context.Context, ids []node.ID) ([]distribution.Observation, error) {
	if ctx == nil || client == nil || client.loadDeliveries == nil || len(ids) == 0 ||
		len(ids) > maximumDeliveryLoad {
		return nil, ErrInvalidOptions
	}
	keys := make([]string, 0, len(ids)*2)
	for _, id := range ids {
		if !id.IsValid() {
			return nil, ErrInvalidOptions
		}
		keys = append(keys, deliveryKeyForNode(id), presenceKeyForNode(id))
	}
	startedAt := time.Now()
	raw, err := client.loadDeliveries(ctx, keys)
	if err == nil {
		var observations []distribution.Observation
		observations, err = decodeObservations(raw, len(ids))
		if err == nil {
			client.metrics.observeCommand(redisCommandLoadDeliveries, startedAt, nil)
			return observations, nil
		}
	}
	client.metrics.observeCommand(redisCommandLoadDeliveries, startedAt, err)
	return nil, errors.Join(ErrLoadDeliveries, err)
}

func decodeObservations(raw []any, count int) ([]distribution.Observation, error) {
	if len(raw) != count*deliveryFieldCount {
		return nil, errors.New("unexpected delivery load length")
	}
	observations := make([]distribution.Observation, count)
	for index := range observations {
		fields := make([]string, deliveryFieldCount)
		for field := range fields {
			value, ok := raw[index*deliveryFieldCount+field].(string)
			if !ok {
				return nil, errors.New("unexpected delivery field type")
			}
			fields[field] = value
		}
		observation, err := decodeObservation(fields)
		if err != nil {
			return nil, err
		}
		observations[index] = observation
	}
	return observations, nil
}

func decodeObservation(fields []string) (distribution.Observation, error) {
	online := fields[5] == "1"
	if fields[5] != "0" && fields[5] != "1" {
		return distribution.Observation{}, errors.New("unexpected presence flag")
	}
	if fields[0] == "" {
		for _, field := range fields[1:5] {
			if field != "" {
				return distribution.Observation{}, errors.New("partial delivery record")
			}
		}
		return distribution.Observation{Online: online}, nil
	}
	numbers := make([]int64, 5)
	for index, field := range fields[:5] {
		value, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			return distribution.Observation{}, errors.New("malformed delivery record")
		}
		numbers[index] = value
	}
	observation := distribution.Observation{
		Known:             true,
		SessionGeneration: numbers[0],
		NetworkRevision:   numbers[1],
		PolicyRevision:    numbers[2],
		DeliveredAt:       time.UnixMilli(numbers[3]).UTC(),
		SeenAt:            time.UnixMilli(numbers[4]).UTC(),
		Online:            online,
	}
	if !observation.IsValid() {
		return distribution.Observation{}, errors.New("inconsistent delivery record")
	}
	return observation, nil
}

func deliveryKeyForNode(nodeID node.ID) string { return deliveryKeyPrefix + nodeID.String() }
