package redis

import (
	"context"
	"errors"
	"strconv"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/platform/ratelimit"
	"meshtransit.net/core/internal/platform/servertiming"
)

const managementRateLimitKeyPrefix = "meshtransit:v1:ratelimit:management:"

var (
	// ErrRateLimit classifies unavailable or malformed distributed limiter results.
	ErrRateLimit    = errors.New("redis: apply rate limit")
	rateLimitScript = redisclient.NewScript(`
local capacity = tonumber(ARGV[1])
local interval_ms = tonumber(ARGV[2])
if capacity == nil or capacity < 1 or interval_ms == nil or interval_ms < 1 then
    return {-1, -1, -1}
end

local redis_time = redis.call('TIME')
local now_ms = (tonumber(redis_time[1]) * 1000) + math.floor(tonumber(redis_time[2]) / 1000)
local stored_tat = redis.call('GET', KEYS[1])
if ARGV[3] == 'refund' then
    -- Give back one spent token: move the theoretical arrival time back one
    -- interval, never below now, so a budget never exceeds its capacity.
    if stored_tat == false then
        return {1, capacity, 0}
    end
    local spent_tat = tonumber(stored_tat)
    if spent_tat == nil then
        return {-1, -1, -1}
    end
    spent_tat = spent_tat - interval_ms
    if spent_tat <= now_ms then
        redis.call('DEL', KEYS[1])
        return {1, capacity, 0}
    end
    redis.call('SET', KEYS[1], spent_tat, 'PX', spent_tat - now_ms)
    return {1, math.floor((now_ms + (capacity * interval_ms) - spent_tat) / interval_ms), 0}
end
local tat = now_ms
if stored_tat ~= false then
    tat = tonumber(stored_tat)
    if tat == nil then
        return {-1, -1, -1}
    end
    if tat < now_ms then
        tat = now_ms
    end
end

local proposed_tat = tat + interval_ms
local burst_deadline = now_ms + (capacity * interval_ms)
if proposed_tat > burst_deadline then
    return {0, 0, proposed_tat - burst_deadline}
end

local ttl_ms = proposed_tat - now_ms
if ttl_ms < interval_ms then
    ttl_ms = interval_ms
end
redis.call('SET', KEYS[1], proposed_tat, 'PX', ttl_ms)
local remaining = math.floor((burst_deadline - proposed_tat) / interval_ms)
return {1, remaining, 0}
`)
)

// rateLimitFunc runs the limiter script in one mode: spend one token, or
// refund one spent token.
type rateLimitFunc func(ctx context.Context, key string, capacity int64, refill time.Duration, mode string) ([]int64, error)

const (
	rateLimitModeSpend  = "spend"
	rateLimitModeRefund = "refund"
)

// ValidateRateLimiter checks structural construction without issuing a command.
// It proves neither connectivity nor readiness, and never grants authority.
func (client *Client) ValidateRateLimiter() error {
	if client == nil || client.applyRateLimit == nil {
		return ErrInvalidOptions
	}
	return nil
}

// Allow atomically consumes one distributed token using Redis server time.
func (client *Client) Allow(
	ctx context.Context,
	subject ratelimit.Subject,
	policy ratelimit.Policy,
) (ratelimit.Decision, error) {
	return client.decide(ctx, subject, policy, rateLimitModeSpend)
}

// Refund gives back one token a request spent, never raising the budget
// above its capacity (TD-CORE-138: a source token spent before
// authentication is returned once the session is valid).
func (client *Client) Refund(
	ctx context.Context,
	subject ratelimit.Subject,
	policy ratelimit.Policy,
) error {
	_, err := client.decide(ctx, subject, policy, rateLimitModeRefund)
	return err
}

func (client *Client) decide(
	ctx context.Context,
	subject ratelimit.Subject,
	policy ratelimit.Policy,
	mode string,
) (ratelimit.Decision, error) {
	if ctx == nil || client == nil || client.applyRateLimit == nil ||
		!subject.IsValid() || !policy.IsValid() {
		return ratelimit.Decision{}, ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.applyRateLimit(
		ctx,
		rateLimitKey(subject),
		policy.Capacity(),
		policy.RefillInterval(),
		mode,
	)
	servertiming.AddRedis(ctx, time.Since(startedAt))
	if err != nil {
		client.metrics.observeCommand(redisCommandRateLimit, startedAt, err)
		return ratelimit.Decision{}, errors.Join(ErrRateLimit, err)
	}
	if len(result) != 3 || (result[0] != 0 && result[0] != 1) {
		client.metrics.observeCommand(redisCommandRateLimit, startedAt, ErrRateLimit)
		return ratelimit.Decision{}, ErrRateLimit
	}
	decision, err := ratelimit.NewDecision(
		result[0] == 1,
		policy.Capacity(),
		result[1],
		time.Duration(result[2])*time.Millisecond,
	)
	client.metrics.observeCommand(redisCommandRateLimit, startedAt, err)
	if err != nil {
		return ratelimit.Decision{}, errors.Join(ErrRateLimit, err)
	}
	return decision, nil
}

func rateLimitKey(subject ratelimit.Subject) string {
	return managementRateLimitKeyPrefix + string(subject.Kind()) + ":" +
		subject.DigestKeyID() + ":" + subject.DigestString()
}

func runRateLimitScript(
	ctx context.Context,
	client *redisclient.Client,
	key string,
	capacity int64,
	refillInterval time.Duration,
	mode string,
) ([]int64, error) {
	return rateLimitScript.Run(
		ctx,
		client,
		[]string{key},
		strconv.FormatInt(capacity, 10),
		strconv.FormatInt(refillInterval.Milliseconds(), 10),
		mode,
	).Int64Slice()
}
