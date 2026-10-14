package mtcpclient

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

func TestRefusalCarriesRetryAfter(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]time.Duration{
		"5":                             5 * time.Second,
		" 30 ":                          30 * time.Second,
		"86400":                         controlplane.MaxRetryAfter,
		"0":                             0,
		"-3":                            0,
		"soon":                          0,
		"Wed, 21 Oct 2026 07:28:00 GMT": 0,
		"":                              0,
	} {
		header := http.Header{}
		if value != "" {
			header.Set("Retry-After", value)
		}
		for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
			err := refusal(status, header)
			if !errors.Is(err, controlplane.ErrRegistrationTemporary) || controlplane.RetryAfterOf(err) != want {
				t.Errorf("refusal(%d, Retry-After %q) = %v, wait %s; want %s", status, value, err,
					controlplane.RetryAfterOf(err), want)
			}
		}
	}
}
