package k8sstate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"
)

// ensureAttempts bounds the reads and writes EnsureKey makes: replicas that
// start together each add their own key, so a few conflicts are expected.
const ensureAttempts = 8

// ErrKeyInvalid reports a key the Secret holds that valid refuses: the
// replica stops rather than replace a key another writer set.
var ErrKeyInvalid = errors.New("k8sstate: the Secret holds an unusable value for the key")

// EnsureKey returns the value of key in the Secret cfg names. When the
// Secret lacks it, EnsureKey adds the value generate makes with an update
// over the Secret's resourceVersion (V1-12 design §3.7: the chart renders
// the Secret empty; each replica adds its own key), reading again after a
// conflict and never replacing a key someone else added meanwhile. added
// reports whether this call wrote it; the caller uses the value it got, as
// a mount of the Secret may show it only a minute later.
func EnsureKey(ctx context.Context, cfg Config, key string, generate func() ([]byte, error),
	valid func([]byte) bool) (value []byte, added bool, err error) {
	if key == "" || generate == nil || valid == nil {
		return nil, false, errors.New("k8sstate: EnsureKey needs a key, a generator and a check")
	}
	api, err := newAPIClient(cfg)
	if err != nil {
		return nil, false, err
	}
	defer api.close()
	for attempt := range ensureAttempts {
		current, err := timed(ctx, cfg.Timeout, api.get)
		if err != nil {
			if wait, ok := tooMany(err); ok {
				if sleepErr := sleep(ctx, max(wait, defaultRetryAfter)); sleepErr != nil {
					return nil, false, sleepErr
				}
				continue
			}
			return nil, false, fmt.Errorf("k8sstate: reading Secret %s: %w", cfg.SecretName, err)
		}
		if existing, ok := current.data[key]; ok {
			if !valid(existing) {
				return nil, false, fmt.Errorf("%w %s in Secret %s", ErrKeyInvalid, key, cfg.SecretName)
			}
			return existing, false, nil
		}
		fresh, err := generate()
		if err != nil {
			return nil, false, fmt.Errorf("k8sstate: making the key %s: %w", key, err)
		}
		if !valid(fresh) {
			return nil, false, fmt.Errorf("k8sstate: the key made for %s is not usable", key)
		}
		data := maps.Clone(current.data)
		data[key] = fresh
		_, err = timed(ctx, cfg.Timeout, func(ctx context.Context) (secret, error) { return api.put(ctx, current, data) })
		var status *statusError
		switch {
		case err == nil:
			return fresh, true, nil
		case errors.As(err, &status) && status.code == http.StatusConflict:
			// Another replica wrote first: read again, keep what it wrote.
			if sleepErr := sleep(ctx, time.Duration(attempt+1)*50*time.Millisecond); sleepErr != nil {
				return nil, false, sleepErr
			}
		case errors.As(err, &status) && status.code == http.StatusTooManyRequests:
			if sleepErr := sleep(ctx, max(status.retryAfter, defaultRetryAfter)); sleepErr != nil {
				return nil, false, sleepErr
			}
		default:
			// An answer lost on the way back may have written the key: the next
			// read finds it, or this fails.
			if notRun(err) {
				return nil, false, fmt.Errorf("k8sstate: adding %s to Secret %s: %w", key, cfg.SecretName, err)
			}
		}
	}
	return nil, false, fmt.Errorf("k8sstate: adding %s to Secret %s: still conflicting after %d attempts", key,
		cfg.SecretName, ensureAttempts)
}

// timed runs one request within the per-request timeout.
func timed(ctx context.Context, timeout time.Duration, run func(context.Context) (secret, error)) (secret, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	request, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return run(request)
}
