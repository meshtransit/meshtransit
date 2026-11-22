package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/crypto/acme"
)

type statusTest struct{}

func (statusTest) Error() string     { return "status 503" }
func (statusTest) ErrorCode() string { return "bad_status" }
func (statusTest) StatusCode() int   { return 503 }

func TestErrorCodeIsClosedAndNonSensitive(t *testing.T) {
	t.Parallel()
	for want, err := range map[string]error{
		"none":               nil,
		"state_rejected":     Code("state_rejected", errors.New("secret detail")),
		"canceled":           fmt.Errorf("fetch: %w", context.Canceled),
		"timeout":            context.DeadlineExceeded,
		"dns":                &net.DNSError{Err: "no such host", Name: "core.example"},
		"connection_refused": &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		"too_many_files":     &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)},
		"eof":                io.ErrUnexpectedEOF,
		"acme_rateLimited":   &acme.Error{ProblemType: "urn:ietf:params:acme:error:rateLimited", Detail: "host x"},
		"acme_unknown":       &acme.Error{ProblemType: "urn:x:1234"},
		"other":              errors.New("https://core.example/x?token=1"),
	} {
		if got := ErrorCode(err); got != want {
			t.Errorf("ErrorCode(%v) = %q, want %q", err, got, want)
		}
	}
	attrs := ErrorAttrs(fmt.Errorf("poll: %w", statusTest{}))
	if len(attrs) != 6 || attrs[3] != "bad_status" || attrs[5] != 503 {
		t.Errorf("ErrorAttrs = %v", attrs)
	}
}
