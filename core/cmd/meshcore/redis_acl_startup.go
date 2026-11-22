package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
)

// redisACLChecker is the Redis client's start-up check.
type redisACLChecker interface {
	CheckACL(ctx context.Context, role string) error
}

// redisACLRetryInterval spaces tries while Redis is not ready.
const redisACLRetryInterval = time.Second

// checkRedisACL runs the role's Redis ACL self-check after Redis answers,
// trying again while the server or network is not ready, until deadline.
// It returns the error code that stops the process, or "" to go on. A
// server that refuses MULTI (a user made before the check, a proxy without
// transactions) only gets a warning.
func checkRedisACL(ctx context.Context, logger *slog.Logger, checker redisACLChecker, role string,
	deadline time.Time, now func() time.Time, sleep func(context.Context, time.Duration) error,
) string {
	for {
		tryCtx, cancel := context.WithDeadline(ctx, deadline)
		err := checker.CheckACL(tryCtx, role)
		cancel()
		if ctx.Err() != nil {
			logger.InfoContext(ctx, "startup stopped while checking the redis acl", "role", role)
			return "canceled"
		}
		var missing *redisadapter.ACLMissingError
		switch {
		case err == nil:
			return ""
		case errors.Is(err, redisadapter.ErrACLCheckUnavailable):
			logger.WarnContext(ctx, "redis acl not checked: the server refuses MULTI for this user", "role", role,
				"cause", redisadapter.ErrorClass(err))
			return ""
		case errors.As(err, &missing):
			logger.ErrorContext(ctx, "startup failed", "error_code", "redis_acl_missing", "missing", missing.Missing)
			return "redis_acl_missing"
		case errors.Is(err, redisadapter.ErrACLCheckTransient) && now().Add(redisACLRetryInterval).Before(deadline):
			if sleep(ctx, redisACLRetryInterval) == nil {
				continue
			}
		}
		logger.ErrorContext(ctx, "startup failed", "error_code", "redis_acl_check_failure",
			"cause", redisadapter.ErrorClass(err), "error", err)
		return "redis_acl_check_failure"
	}
}

func sleepContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
