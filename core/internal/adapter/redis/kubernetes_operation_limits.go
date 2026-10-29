package redis

import (
	"context"
	"errors"
	"math"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/domain/kubeaudit"
)

// kubernetesOperationLimitPrefix holds the Workspace's and its gateways'
// operation buckets under the Workspace's hash tag, so one script takes
// from both (K1b0 §6).
const kubernetesOperationLimitPrefix = "meshtransit:v1:ratelimit:kubeops:"

var (
	// ErrKubernetesOperationLimits reports a failed or malformed take.
	ErrKubernetesOperationLimits = errors.New("redis: kubernetes operation limits")

	// kubernetesOperationLimitsScript takes ARGV[1] tokens from two GCRA
	// buckets on Redis time, or from neither: KEYS[1] the Workspace's
	// (ARGV[2] µs a token, ARGV[3] burst), KEYS[2] the gateway's (ARGV[4],
	// ARGV[5]). It returns {1, 0}, or {0, µs until both hold the tokens}.
	kubernetesOperationLimitsScript = redisclient.NewScript(`
local n = tonumber(ARGV[1])
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000000 + tonumber(time[2])
local tats, wait = {}, 0
for index = 1, 2 do
  local interval = tonumber(ARGV[2 * index])
  local burst = tonumber(ARGV[2 * index + 1])
  local tat = tonumber(redis.call('GET', KEYS[index]) or now)
  if tat == nil or tat < now then tat = now end
  local proposed = tat + n * interval
  local over = proposed - now - burst * interval
  if over > wait then wait = over end
  tats[index] = proposed
end
if wait > 0 then return {0, math.ceil(wait)} end
for index = 1, 2 do
  redis.call('SET', KEYS[index], string.format('%.0f', tats[index]), 'PX', math.ceil((tats[index] - now) / 1000) + 1)
end
return {1, 0}
`)
)

type kubernetesOperationLimitsFunc func(ctx context.Context, keys []string, args ...any) ([]int64, error)

func runKubernetesOperationLimitsScript(client *redisclient.Client) kubernetesOperationLimitsFunc {
	return func(ctx context.Context, keys []string, args ...any) ([]int64, error) {
		return kubernetesOperationLimitsScript.Run(ctx, client, keys, args...).Int64Slice()
	}
}

// TakeKubernetesOperations takes n operations from a Workspace's and a
// gateway's shared buckets, or from neither (kubeaudit.SharedBuckets);
// false returns how long until both hold n.
func (client *Client) TakeKubernetesOperations(ctx context.Context, workspace, gateway string, n int,
	limits kubeaudit.Limits,
) (time.Duration, bool, error) {
	if ctx == nil || client == nil || client.kubernetesOperationLimits == nil || workspace == "" || gateway == "" ||
		n < 1 {
		return 0, false, ErrKubernetesOperationLimits
	}
	workspaceInterval, gatewayInterval := microsecondsPerToken(limits.Workspace), microsecondsPerToken(limits.Gateway)
	if workspaceInterval < 1 || gatewayInterval < 1 {
		return 0, false, ErrKubernetesOperationLimits
	}
	tag := kubernetesOperationLimitPrefix + "{" + workspace + "}:"
	startedAt := time.Now()
	result, err := client.kubernetesOperationLimits(ctx, []string{tag + "workspace", tag + "gateway:" + gateway}, n,
		workspaceInterval, int64(limits.Workspace.Burst), gatewayInterval, int64(limits.Gateway.Burst))
	client.metrics.observeCommand(redisCommandKubernetesOperationLimits, startedAt, err)
	if err != nil {
		return 0, false, errors.Join(ErrKubernetesOperationLimits, err)
	}
	if len(result) != 2 || (result[0] != 0 && result[0] != 1) || result[1] < 0 {
		return 0, false, ErrKubernetesOperationLimits
	}
	return time.Duration(result[1]) * time.Microsecond, result[0] == 1, nil
}

// microsecondsPerToken is a rate's refill interval; 0 for one that cannot
// be one.
func microsecondsPerToken(rate kubeaudit.Rate) int64 {
	if rate.PerSecond <= 0 || rate.Burst < 1 || math.IsInf(rate.PerSecond, 0) {
		return 0
	}
	return int64(math.Round(1e6 / rate.PerSecond))
}
