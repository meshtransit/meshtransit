package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
)

type scriptedACL struct {
	results []error
	calls   int
}

func (checker *scriptedACL) CheckACL(context.Context, string) error {
	err := checker.results[min(checker.calls, len(checker.results)-1)]
	checker.calls++
	return err
}

func TestCheckRedisACL(t *testing.T) {
	t.Parallel()
	noSleep := func(context.Context, time.Duration) error { return nil }
	start := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return start }
	later := start.Add(time.Hour)
	cases := []struct {
		name     string
		results  []error
		deadline time.Time
		code     string
		calls    int
		log      string
	}{
		{"passes", []error{nil}, later, "", 1, ""},
		{"not ready, then passes", []error{redisadapter.ErrACLCheckTransient, redisadapter.ErrACLCheckTransient, nil},
			later, "", 3, ""},
		{"not ready past the deadline", []error{redisadapter.ErrACLCheckTransient}, start,
			"redis_acl_check_failure", 1, "redis_acl_check_failure"},
		{"MULTI refused", []error{redisadapter.ErrACLCheckUnavailable}, later, "", 1, "redis acl not checked"},
		{"missing rights", []error{&redisadapter.ACLMissingError{Missing: []string{"HDEL meshtransit:v1:x: (NOPERM)"}}},
			later, "redis_acl_missing", 1, "HDEL meshtransit:v1:x:"},
		{"other failure", []error{errors.New("boom")}, later, "redis_acl_check_failure", 1, "redis_acl_check_failure"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			checker := &scriptedACL{results: test.results}
			code := checkRedisACL(context.Background(), logger, checker, "api", test.deadline, clock, noSleep)
			if code != test.code || checker.calls != test.calls || !strings.Contains(output.String(), test.log) {
				t.Errorf("code %q after %d calls, log %s; want %q after %d calls, log with %q",
					code, checker.calls, output.String(), test.code, test.calls, test.log)
			}
		})
	}
}
