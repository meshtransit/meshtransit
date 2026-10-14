package controlplane

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("stream: %w", WithRetryAfter(ErrNetmapAuthorityPaused, 3*time.Second))
	if !errors.Is(err, ErrNetmapAuthorityPaused) || RetryAfterOf(err) != 3*time.Second {
		t.Fatalf("RetryAfterOf = %s, is paused %t", RetryAfterOf(err), errors.Is(err, ErrNetmapAuthorityPaused))
	}
	if RetryAfterOf(WithRetryAfter(ErrRegistrationTemporary, 24*time.Hour)) != MaxRetryAfter {
		t.Fatal("a wait past MaxRetryAfter was not bounded")
	}
	var retry *RetryAfterError
	if unchanged := WithRetryAfter(ErrRegistrationTemporary, 0); errors.As(unchanged, &retry) ||
		!errors.Is(unchanged, ErrRegistrationTemporary) || RetryAfterOf(ErrRegistration) != 0 {
		t.Fatal("no wait was attached or read")
	}
}
