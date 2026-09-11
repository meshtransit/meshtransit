package netwatch

import (
	"context"
	"errors"
	"time"
)

type pollingSource struct {
	interval time.Duration
}

func newPollingSource(interval time.Duration) *pollingSource {
	return &pollingSource{interval: interval}
}

func (s *pollingSource) Wait(ctx context.Context) error {
	if s == nil || s.interval <= 0 {
		return errors.New("netwatch: polling interval is invalid")
	}

	return waitFor(ctx, s.interval)
}

func (s *pollingSource) Close() error {
	return nil
}
