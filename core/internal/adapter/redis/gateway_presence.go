package redis

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const (
	// gatewayContestKeyPrefix holds, per Kubernetes gateway machine key,
	// until when its rotation is refused and how often live holders took
	// its presence (K1a1 plan §16.12). It sits under the presence prefix,
	// which Core's Redis user already has.
	gatewayContestKeyPrefix = presenceKeyPrefix + "gateway-contest:"
	// gatewayTakesWindow and gatewayTakesFight: the third take of a live
	// holder's presence within five minutes is a fight.
	gatewayTakesWindow = 5 * time.Minute
	gatewayTakesFight  = 3
)

var (
	// ErrGatewayPresence classifies an unavailable or malformed gateway
	// presence script.
	ErrGatewayPresence = errors.New("redis: gateway presence")

	// acquireGatewayPresenceScript is acquirePresenceScript for a gateway,
	// whose lease also names its holder. It answers {status, retry_ms,
	// fight}. A lease of another holder that still exists (it expires with
	// its holder's renewals) is taken, whatever its replica or generation:
	// the take marks the machine key contested until now + ARGV[9] in
	// KEYS[3], and counts towards a fight unless Core handed the lease off.
	acquireGatewayPresenceScript = redisclient.NewScript(`
local current_generation = redis.call('HGET', KEYS[1], 'generation')
local current_replica = redis.call('HGET', KEYS[1], 'replica')
if (current_generation == false) ~= (current_replica == false) then
    return {-1, 0, 0}
end

local requested_generation = tonumber(ARGV[1])
local transfer_limit = tonumber(ARGV[6])
local transfer_window = tonumber(ARGV[7])
local contest_window = tonumber(ARGV[9])
local takes_window = tonumber(ARGV[10])
local takes_fight = tonumber(ARGV[11])
if requested_generation == nil or transfer_limit == nil or transfer_window == nil or
    transfer_limit <= 0 or transfer_window <= 0 or contest_window == nil or contest_window <= 0 or
    takes_window == nil or takes_window <= 0 or takes_fight == nil or takes_fight <= 0 or
    ARGV[8] == '' then
    return {-1, 0, 0}
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local taken = current_generation ~= false and redis.call('HGET', KEYS[1], 'holder') ~= ARGV[8]
local changed = current_generation == false
if current_generation ~= false then
    local stored_generation = tonumber(current_generation)
    if stored_generation == nil then
        return {-1, 0, 0}
    end
    if requested_generation < stored_generation then
        return {0, 0, 0}
    end
    changed = requested_generation > stored_generation
    if not changed and current_replica ~= ARGV[2] then
        local until_ms = tonumber(redis.call('HGET', KEYS[1], 'moves_until'))
        local moves = 1
        if until_ms ~= nil and now < until_ms and until_ms - now <= transfer_window then
            moves = (tonumber(redis.call('HGET', KEYS[1], 'moves')) or 0) + 1
            redis.call('HSET', KEYS[1], 'moves', moves)
        else
            until_ms = now + transfer_window
            redis.call('HSET', KEYS[1], 'moves', 1, 'moves_until', until_ms)
        end
        if moves > transfer_limit then
            return {2, until_ms - now, 0}
        end
    end
end
if changed then
    redis.call('HDEL', KEYS[1], 'moves', 'moves_until')
end

local fight = 0
if taken then
    local contest_until = now + contest_window
    redis.call('HSET', KEYS[3], 'until', contest_until)
    local keep = contest_until
    local takes_until = tonumber(redis.call('HGET', KEYS[3], 'takes_until'))
    if takes_until ~= nil and (takes_until <= now or takes_until - now > takes_window) then
        takes_until = nil
    end
    if redis.call('HGET', KEYS[1], 'handoff') ~= '1' then
        local takes = 1
        if takes_until ~= nil then
            takes = (tonumber(redis.call('HGET', KEYS[3], 'takes')) or 0) + 1
            redis.call('HSET', KEYS[3], 'takes', takes)
        else
            takes_until = now + takes_window
            redis.call('HSET', KEYS[3], 'takes', 1, 'takes_until', takes_until)
        end
        if takes == takes_fight then
            fight = 1
        end
    end
    if takes_until ~= nil and takes_until > keep then
        keep = takes_until
    end
    redis.call('PEXPIRE', KEYS[3], keep - now)
end

redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'replica', ARGV[2], 'holder', ARGV[8])
redis.call('HDEL', KEYS[1], 'handoff')
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
return {1, 0, fight}
`)
	// renewGatewayPresenceScript extends only the lease of exactly this
	// generation, replica and holder.
	renewGatewayPresenceScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'replica') ~= ARGV[2] or
    redis.call('HGET', KEYS[1], 'holder') ~= ARGV[4] or ARGV[4] == '' then
    return {0}
end
redis.call('PEXPIRE', KEYS[1], ARGV[3])
if redis.call('HGET', KEYS[2], 'generation') == ARGV[1] then
    redis.call('PEXPIRE', KEYS[2], ARGV[3])
end
return {1}
`)
	// releaseGatewayPresenceScript deletes only the lease of exactly this
	// generation, replica and holder, as releasePresenceScript does.
	releaseGatewayPresenceScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'replica') ~= ARGV[2] or
    redis.call('HGET', KEYS[1], 'holder') ~= ARGV[3] or ARGV[3] == '' then
    return {0}
end
redis.call('DEL', KEYS[1])
if redis.call('HGET', KEYS[2], 'generation') == ARGV[1] then
    redis.call('DEL', KEYS[2])
end
redis.call('PUBLISH', ARGV[4], ARGV[5])
return {1}
`)
	// handOffGatewayPresenceScript marks the lease of exactly this
	// generation, replica and holder as handed off by Core.
	handOffGatewayPresenceScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'replica') ~= ARGV[2] or
    redis.call('HGET', KEYS[1], 'holder') ~= ARGV[3] or ARGV[3] == '' then
    return {0}
end
redis.call('HSET', KEYS[1], 'handoff', '1')
return {1}
`)
	// checkGatewayRotationScript answers {1} when the lease is exactly this
	// generation, replica and holder's and the machine key is not
	// contested, {2} when it is contested, {3} when the lease is not held.
	checkGatewayRotationScript = redisclient.NewScript(`
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local contest_until = redis.call('HGET', KEYS[2], 'until')
if contest_until ~= false then
    local until_ms = tonumber(contest_until)
    if until_ms == nil or until_ms > now then
        return {2}
    end
end
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'replica') ~= ARGV[2] or
    redis.call('HGET', KEYS[1], 'holder') ~= ARGV[3] or ARGV[3] == '' then
    return {3}
end
return {1}
`)
)

type gatewayScriptFunc func(ctx context.Context, script *redisclient.Script, keys []string,
	args ...any) ([]int64, error)

func runGatewayScript(client redisclient.Scripter) gatewayScriptFunc {
	return func(ctx context.Context, script *redisclient.Script, keys []string, args ...any) ([]int64, error) {
		return script.Run(ctx, client, keys, args...).Int64Slice()
	}
}

// AcquireGatewayPresence claims a Kubernetes gateway stream's presence
// (K1a1 plan §16.12). A churned lease answers a
// *mapsession.PresenceChurnError, as AcquirePresence does.
func (client *Client) AcquireGatewayPresence(ctx context.Context, scope network.Scope, lease node.PresenceLease,
	window time.Duration) (mapsession.GatewayClaim, error) {
	if ctx == nil || client == nil || client.gatewayScript == nil || !scope.IsValid() || !lease.IsValid() ||
		!lease.Gateway() || window < time.Second {
		return mapsession.GatewayClaim{}, ErrInvalidOptions
	}
	wakeup, err := encodeConnectivityWakeup(scope, lease.NodeID(), lease.Generation(),
		mapsession.ConnectivityChangePresence)
	if err != nil {
		return mapsession.GatewayClaim{}, err
	}
	defer clear(wakeup)
	startedAt := time.Now()
	values, err := client.gatewayScript(ctx, acquireGatewayPresenceScript,
		[]string{presenceKey(lease), endpointKey(lease.NodeID()), gatewayContestKey(lease)},
		lease.Generation(), lease.ReplicaID(), lease.TTL().Milliseconds(), connectivityChangedChannel, wakeup,
		presenceTransferLimit, presenceTransferWindow.Milliseconds(), lease.Holder().String(),
		window.Milliseconds(), gatewayTakesWindow.Milliseconds(), gatewayTakesFight)
	if err != nil {
		client.metrics.observeCommand(redisCommandGatewayAcquire, startedAt, err)
		return mapsession.GatewayClaim{}, errors.Join(ErrGatewayPresence, err)
	}
	if len(values) != 3 || values[2] < 0 || values[2] > 1 {
		client.metrics.observeCommand(redisCommandGatewayAcquire, startedAt, ErrGatewayPresence)
		return mapsession.GatewayClaim{}, ErrGatewayPresence
	}
	switch status, retryMS := values[0], values[1]; {
	case status == 2 && retryMS > 0 && retryMS <= presenceTransferWindow.Milliseconds():
		client.metrics.observeCommand(redisCommandGatewayAcquire, startedAt, nil)
		return mapsession.GatewayClaim{}, &mapsession.PresenceChurnError{
			RetryAfter: time.Duration(retryMS) * time.Millisecond}
	case status == 1:
		client.metrics.observeCommand(redisCommandGatewayAcquire, startedAt, nil)
		return mapsession.GatewayClaim{Claimed: true, Fight: values[2] == 1}, nil
	case status == 0 && values[2] == 0:
		client.metrics.observeCommand(redisCommandGatewayAcquire, startedAt, nil)
		return mapsession.GatewayClaim{}, nil
	default:
		client.metrics.observeCommand(redisCommandGatewayAcquire, startedAt, ErrGatewayPresence)
		return mapsession.GatewayClaim{}, ErrGatewayPresence
	}
}

// RenewGatewayPresence extends only the lease of exactly lease's holder.
func (client *Client) RenewGatewayPresence(ctx context.Context, lease node.PresenceLease) (bool, error) {
	if ctx == nil || client == nil || client.gatewayScript == nil || !lease.IsValid() || !lease.Gateway() {
		return false, ErrInvalidOptions
	}
	return client.gatewayFlag(ctx, redisCommandGatewayRenew, renewGatewayPresenceScript,
		[]string{presenceKey(lease), endpointKey(lease.NodeID())},
		lease.Generation(), lease.ReplicaID(), lease.TTL().Milliseconds(), lease.Holder().String())
}

// ReleaseGatewayPresence deletes only the lease of exactly lease's holder,
// and announces the gateway offline as ReleasePresence does.
func (client *Client) ReleaseGatewayPresence(ctx context.Context, scope network.Scope,
	lease node.PresenceLease) (bool, error) {
	if ctx == nil || client == nil || client.gatewayScript == nil || !scope.IsValid() || !lease.IsValid() ||
		!lease.Gateway() {
		return false, ErrInvalidOptions
	}
	wakeup, err := encodeConnectivityWakeup(scope, lease.NodeID(), lease.Generation(),
		mapsession.ConnectivityChangePresence)
	if err != nil {
		return false, err
	}
	defer clear(wakeup)
	return client.gatewayFlag(ctx, redisCommandGatewayRelease, releaseGatewayPresenceScript,
		[]string{presenceKey(lease), endpointKey(lease.NodeID())},
		lease.Generation(), lease.ReplicaID(), lease.Holder().String(), connectivityChangedChannel, wakeup)
}

// HandOffGatewayPresence marks the lease of exactly lease's holder as
// handed off by Core.
func (client *Client) HandOffGatewayPresence(ctx context.Context, lease node.PresenceLease) (bool, error) {
	if ctx == nil || client == nil || client.gatewayScript == nil || !lease.IsValid() || !lease.Gateway() {
		return false, ErrInvalidOptions
	}
	return client.gatewayFlag(ctx, redisCommandGatewayHandOff, handOffGatewayPresenceScript,
		[]string{presenceKey(lease)}, lease.Generation(), lease.ReplicaID(), lease.Holder().String())
}

// CheckGatewayRotation says whether the stream holding lease may rotate
// its keys.
func (client *Client) CheckGatewayRotation(ctx context.Context,
	lease node.PresenceLease) (mapsession.GatewayRotationState, error) {
	if ctx == nil || client == nil || client.gatewayScript == nil || !lease.IsValid() || !lease.Gateway() {
		return 0, ErrInvalidOptions
	}
	startedAt := time.Now()
	values, err := client.gatewayScript(ctx, checkGatewayRotationScript,
		[]string{presenceKey(lease), gatewayContestKey(lease)},
		lease.Generation(), lease.ReplicaID(), lease.Holder().String())
	if err != nil {
		client.metrics.observeCommand(redisCommandGatewayCheck, startedAt, err)
		return 0, errors.Join(ErrGatewayPresence, err)
	}
	if len(values) != 1 || values[0] < 1 || values[0] > 3 {
		client.metrics.observeCommand(redisCommandGatewayCheck, startedAt, ErrGatewayPresence)
		return 0, ErrGatewayPresence
	}
	client.metrics.observeCommand(redisCommandGatewayCheck, startedAt, nil)
	return [...]mapsession.GatewayRotationState{mapsession.GatewayRotationHeld,
		mapsession.GatewayRotationContested, mapsession.GatewayRotationNotHeld}[values[0]-1], nil
}

// gatewayFlag runs a script answering {0} or {1}.
func (client *Client) gatewayFlag(ctx context.Context, command redisCommand, script *redisclient.Script,
	keys []string, args ...any) (bool, error) {
	startedAt := time.Now()
	values, err := client.gatewayScript(ctx, script, keys, args...)
	if err != nil {
		client.metrics.observeCommand(command, startedAt, err)
		return false, errors.Join(ErrGatewayPresence, err)
	}
	if len(values) != 1 || values[0] < 0 || values[0] > 1 {
		client.metrics.observeCommand(command, startedAt, ErrGatewayPresence)
		return false, ErrGatewayPresence
	}
	client.metrics.observeCommand(command, startedAt, nil)
	return values[0] == 1, nil
}

func gatewayContestKey(lease node.PresenceLease) string {
	machine := lease.MachineFingerprint()
	return gatewayContestKeyPrefix + hex.EncodeToString(machine[:])
}
