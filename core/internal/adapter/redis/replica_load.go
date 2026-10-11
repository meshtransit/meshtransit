package redis

import (
	"context"
	"errors"
	"strconv"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/rebalance"
)

const (
	// replicaLoadKey holds one field per control replica:
	// "<sessions>:<expiry in Redis milliseconds>".
	replicaLoadKey = "meshtransit:v1:control:replicas"
	// maximumReplicaLoads bounds what one read returns.
	maximumReplicaLoads   = 1024
	maximumReplicaIDBytes = 64
)

var (
	// ErrReplicaLoad reports an unsafe or failed control load read or write.
	ErrReplicaLoad = errors.New("redis: replica load")

	// replicaLoadScript publishes ARGV[1] (unless empty) with ARGV[2]
	// sessions for ARGV[3] milliseconds, drops expired replicas and returns
	// the live ones as a flat id, sessions list. Redis time decides expiry,
	// so replica clocks never disagree about it.
	replicaLoadScript = redisclient.NewScript(`
local now = redis.call('TIME')
local nowMs = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local ttl = tonumber(ARGV[3])
if ARGV[1] ~= '' then
  redis.call('HSET', KEYS[1], ARGV[1], ARGV[2] .. ':' .. (nowMs + ttl))
  redis.call('PEXPIRE', KEYS[1], ttl)
end
local all = redis.call('HGETALL', KEYS[1])
local live = {}
for i = 1, #all, 2 do
  local value = all[i + 1]
  local separator = string.find(value, ':', 1, true)
  local expires = separator and tonumber(string.sub(value, separator + 1)) or nil
  if expires and expires > nowMs then
    live[#live + 1] = all[i]
    live[#live + 1] = string.sub(value, 1, separator - 1)
  else
    redis.call('HDEL', KEYS[1], all[i])
  end
end
return live
`)
)

type replicaLoadFunc func(ctx context.Context, key, replicaID string, sessions int, ttl time.Duration) ([]any, error)

func runReplicaLoadScript(client *redisclient.Client) replicaLoadFunc {
	return func(ctx context.Context, key, replicaID string, sessions int, ttl time.Duration) ([]any, error) {
		return replicaLoadScript.Run(ctx, client, []string{key}, replicaID, sessions, ttl.Milliseconds()).Slice()
	}
}

// PublishLoad implements rebalance.Registry.
func (client *Client) PublishLoad(ctx context.Context, replicaID string, sessions int,
	ttl time.Duration) ([]rebalance.ReplicaLoad, error) {
	if replicaID == "" || len(replicaID) > maximumReplicaIDBytes || sessions < 0 || ttl < time.Second {
		return nil, ErrReplicaLoad
	}
	return client.replicaLoads(ctx, replicaID, sessions, ttl)
}

// Loads implements rebalance.LoadReader.
func (client *Client) Loads(ctx context.Context) ([]rebalance.ReplicaLoad, error) {
	return client.replicaLoads(ctx, "", 0, time.Second)
}

// WithdrawLoad implements rebalance.Registry.
func (client *Client) WithdrawLoad(ctx context.Context, replicaID string) error {
	if ctx == nil || client == nil || client.withdrawReplicaLoad == nil || replicaID == "" {
		return ErrReplicaLoad
	}
	if err := client.withdrawReplicaLoad(ctx, replicaLoadKey, replicaID); err != nil {
		return errors.Join(ErrReplicaLoad, err)
	}
	return nil
}

func (client *Client) replicaLoads(ctx context.Context, replicaID string, sessions int,
	ttl time.Duration) ([]rebalance.ReplicaLoad, error) {
	if ctx == nil || client == nil || client.replicaLoad == nil {
		return nil, ErrReplicaLoad
	}
	startedAt := time.Now()
	raw, err := client.replicaLoad(ctx, replicaLoadKey, replicaID, sessions, ttl)
	client.metrics.observeCommand(redisCommandReplicaLoad, startedAt, err)
	if err != nil {
		return nil, errors.Join(ErrReplicaLoad, err)
	}
	if len(raw)%2 != 0 || len(raw) > 2*maximumReplicaLoads {
		return nil, ErrReplicaLoad
	}
	loads := make([]rebalance.ReplicaLoad, 0, len(raw)/2)
	for index := 0; index < len(raw); index += 2 {
		id, idOK := raw[index].(string)
		count, countOK := raw[index+1].(string)
		sessions, parseErr := strconv.Atoi(count)
		if !idOK || !countOK || parseErr != nil || id == "" || sessions < 0 {
			return nil, ErrReplicaLoad
		}
		loads = append(loads, rebalance.ReplicaLoad{ReplicaID: id, Sessions: sessions})
	}
	return loads, nil
}
