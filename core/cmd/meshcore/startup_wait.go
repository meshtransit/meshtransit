package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/platform/app"
)

// dependencyStartupRetry spaces the tries while a dependency is awaited.
const dependencyStartupRetry = time.Second

// waitForDependency tries checker until it answers or deadline passes
// (TD-CORE-139): during a rolling update PostgreSQL may refuse a new pod's
// connections (its login's CONNECTION LIMIT) until old pods finish shutting
// down. Each try gets tryTimeout. It logs once when it starts waiting. Past
// the deadline it returns the last error.
func waitForDependency(ctx context.Context, logger *slog.Logger, checker app.DependencyChecker,
	tryTimeout time.Duration, deadline time.Time,
) error {
	for logged := false; ; {
		tryDeadline := time.Now().Add(tryTimeout)
		if deadline.Before(tryDeadline) {
			tryDeadline = deadline
		}
		checkCtx, cancel := context.WithDeadline(ctx, tryDeadline)
		err := checker.Check(checkCtx)
		cancel()
		if err == nil {
			if logged {
				logger.InfoContext(ctx, "dependency available", "dependency", checker.Component().String())
			}
			return nil
		}
		if !time.Now().Add(dependencyStartupRetry).Before(deadline) {
			return err
		}
		if !logged {
			logged = true
			logger.WarnContext(ctx, "dependency unavailable at start-up; waiting",
				"dependency", checker.Component().String(), "until", deadline.UTC())
		}
		timer := time.NewTimer(dependencyStartupRetry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(err, ctx.Err())
		case <-timer.C:
		}
	}
}
