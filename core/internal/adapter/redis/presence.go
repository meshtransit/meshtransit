package redis

import (
	"context"
	"errors"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const presenceKeyPrefix = "meshtransit:v1:presence:node:"

var (
	// ErrAcquirePresence classifies an unavailable or malformed Redis acquisition.
	ErrAcquirePresence = errors.New("redis: acquire presence lease")
	// ErrRenewPresence classifies an unavailable or malformed Redis renewal.
	ErrRenewPresence = errors.New("redis: renew presence lease")
	// ErrReleasePresence classifies an unavailable or malformed Redis release.
	ErrReleasePresence    = errors.New("redis: release presence lease")
	acquirePresenceScript = redisclient.NewScript(`
local current_generation = redis.call('HGET', KEYS[1], 'generation')
local current_replica = redis.call('HGET', KEYS[1], 'replica')
if (current_generation == false) ~= (current_replica == false) then
    return -1
end

local requested_generation = tonumber(ARGV[1])
if requested_generation == nil then
    return -1
end
local changed = current_generation == false
if current_generation ~= false then
    local stored_generation = tonumber(current_generation)
    if stored_generation == nil then
        return -1
    end
    if requested_generation < stored_generation then
        return 0
    end
    changed = requested_generation > stored_generation
end

redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'replica', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
local endpoint_generation = redis.call('HGET', KEYS[2], 'generation')
if endpoint_generation == ARGV[1] then
    redis.call('PEXPIRE', KEYS[2], ARGV[3])
elseif changed and endpoint_generation ~= false then
    redis.call('DEL', KEYS[2])
end
if changed then
    redis.call('PUBLISH', ARGV[4], ARGV[5])
end
return 1
`)
	renewPresenceScript = redisclient.NewScript(`
local current_generation = redis.call('HGET', KEYS[1], 'generation')
local current_replica = redis.call('HGET', KEYS[1], 'replica')
if (current_generation == false) ~= (current_replica == false) then
    return -1
end
if current_generation == false then
    return 0
end

local requested_generation = tonumber(ARGV[1])
local stored_generation = tonumber(current_generation)
if requested_generation == nil or stored_generation == nil then
    return -1
end
if requested_generation ~= stored_generation or current_replica ~= ARGV[2] then
    return 0
end

redis.call('PEXPIRE', KEYS[1], ARGV[3])
if redis.call('HGET', KEYS[2], 'generation') == ARGV[1] then
    redis.call('PEXPIRE', KEYS[2], ARGV[3])
end
return 1
`)
	releasePresenceScript = redisclient.NewScript(`
local current_generation = redis.call('HGET', KEYS[1], 'generation')
local current_replica = redis.call('HGET', KEYS[1], 'replica')
if current_generation == ARGV[1] and current_replica == ARGV[2] then
    local deleted = redis.call('DEL', KEYS[1])
    if redis.call('HGET', KEYS[2], 'generation') == ARGV[1] then
        redis.call('DEL', KEYS[2])
    end
    redis.call('PUBLISH', ARGV[3], ARGV[4])
    return deleted
end
return 0
`)
)

type presenceAcquireFunc func(
	context.Context,
	string,
	string,
	int64,
	string,
	time.Duration,
	string,
	[]byte,
) (int64, error)
type presenceRenewFunc func(
	context.Context,
	string,
	string,
	int64,
	string,
	time.Duration,
) (int64, error)
type presenceReleaseFunc func(
	context.Context,
	string,
	string,
	int64,
	string,
	string,
	[]byte,
) (int64, error)

// AcquirePresence creates or generation-fences an ephemeral Node lease. A
// same-generation acquisition atomically transfers ownership between replicas
// without publishing an offline/online transition or deleting endpoints.
func (client *Client) AcquirePresence(
	ctx context.Context,
	scope network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	if ctx == nil || client == nil || client.acquirePresence == nil ||
		!scope.IsValid() || !lease.IsValid() {
		return false, ErrInvalidOptions
	}
	wakeup, err := encodeConnectivityWakeup(
		scope,
		lease.NodeID(),
		lease.Generation(),
		mapsession.ConnectivityChangePresence,
	)
	if err != nil {
		return false, err
	}
	defer clear(wakeup)
	startedAt := time.Now()
	result, err := client.acquirePresence(
		ctx,
		presenceKey(lease),
		endpointKey(lease.NodeID()),
		lease.Generation(),
		lease.ReplicaID(),
		lease.TTL(),
		connectivityChangedChannel,
		wakeup,
	)
	if err != nil {
		client.metrics.observeCommand(redisCommandAcquire, startedAt, err)
		return false, errors.Join(ErrAcquirePresence, err)
	}
	if result != 0 && result != 1 {
		client.metrics.observeCommand(redisCommandAcquire, startedAt, ErrAcquirePresence)
		return false, ErrAcquirePresence
	}
	client.metrics.observeCommand(redisCommandAcquire, startedAt, nil)
	return result == 1, nil
}

// RenewPresence extends only an exact generation-and-replica-owned lease. A
// false result means the lease expired or another stream took ownership.
func (client *Client) RenewPresence(
	ctx context.Context,
	lease node.PresenceLease,
) (bool, error) {
	if ctx == nil || client == nil || client.renewPresence == nil || !lease.IsValid() {
		return false, ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.renewPresence(
		ctx,
		presenceKey(lease),
		endpointKey(lease.NodeID()),
		lease.Generation(),
		lease.ReplicaID(),
		lease.TTL(),
	)
	if err != nil {
		client.metrics.observeCommand(redisCommandRenew, startedAt, err)
		return false, errors.Join(ErrRenewPresence, err)
	}
	if result != 0 && result != 1 {
		client.metrics.observeCommand(redisCommandRenew, startedAt, ErrRenewPresence)
		return false, ErrRenewPresence
	}
	client.metrics.observeCommand(redisCommandRenew, startedAt, nil)
	return result == 1, nil
}

// ReleasePresence deletes only the exact generation and replica-owned lease.
// Map streams normally leave leases to expire; this operation is reserved for
// callers that explicitly require an immediate offline transition.
func (client *Client) ReleasePresence(
	ctx context.Context,
	scope network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	if ctx == nil || client == nil || client.releasePresence == nil ||
		!scope.IsValid() || !lease.IsValid() {
		return false, ErrInvalidOptions
	}
	wakeup, err := encodeConnectivityWakeup(
		scope,
		lease.NodeID(),
		lease.Generation(),
		mapsession.ConnectivityChangePresence,
	)
	if err != nil {
		return false, err
	}
	defer clear(wakeup)
	startedAt := time.Now()
	result, err := client.releasePresence(
		ctx,
		presenceKey(lease),
		endpointKey(lease.NodeID()),
		lease.Generation(),
		lease.ReplicaID(),
		connectivityChangedChannel,
		wakeup,
	)
	if err != nil {
		client.metrics.observeCommand(redisCommandRelease, startedAt, err)
		return false, errors.Join(ErrReleasePresence, err)
	}
	if result != 0 && result != 1 {
		client.metrics.observeCommand(redisCommandRelease, startedAt, ErrReleasePresence)
		return false, ErrReleasePresence
	}
	client.metrics.observeCommand(redisCommandRelease, startedAt, nil)
	return result == 1, nil
}

func presenceKey(lease node.PresenceLease) string {
	return presenceKeyForNode(lease.NodeID())
}

func presenceKeyForNode(nodeID node.ID) string { return presenceKeyPrefix + nodeID.String() }
