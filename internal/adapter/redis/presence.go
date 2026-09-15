package redis

import (
	"context"
	"errors"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
)

const presenceKeyPrefix = "meshtransit:v1:presence:node:"

var (
	// ErrClaimPresence classifies an unavailable or malformed Redis claim.
	ErrClaimPresence = errors.New("redis: claim presence lease")
	// ErrReleasePresence classifies an unavailable or malformed Redis release.
	ErrReleasePresence  = errors.New("redis: release presence lease")
	claimPresenceScript = redisclient.NewScript(`
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
    if requested_generation == stored_generation and current_replica ~= ARGV[2] then
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

type presenceClaimFunc func(
	context.Context,
	string,
	string,
	int64,
	string,
	time.Duration,
	string,
	[]byte,
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

// ClaimPresence creates, renews, or generation-fences an ephemeral Node lease.
// A false result is a successful rejection of a stale or foreign owner.
func (client *Client) ClaimPresence(
	ctx context.Context,
	scope network.Scope,
	lease node.PresenceLease,
) (bool, error) {
	if ctx == nil || client == nil || client.claimPresence == nil ||
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
	result, err := client.claimPresence(
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
		client.metrics.observeCommand(redisCommandClaim, startedAt, err)
		return false, errors.Join(ErrClaimPresence, err)
	}
	if result != 0 && result != 1 {
		client.metrics.observeCommand(redisCommandClaim, startedAt, ErrClaimPresence)
		return false, ErrClaimPresence
	}
	client.metrics.observeCommand(redisCommandClaim, startedAt, nil)
	return result == 1, nil
}

// ReleasePresence deletes only the exact generation and replica-owned lease.
// A false result means the lease expired or ownership has already advanced.
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
