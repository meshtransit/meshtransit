package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestTransientConnectError(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"connection refused", refused, true},
		{"refused, wrapped", fmt.Errorf("failed to connect: %w", refused), true},
		{"dial timeout", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}, true},
		{"no route", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, true},
		{"DNS timeout", &net.DNSError{Err: "i/o timeout", Name: "db", IsTimeout: true}, true},
		{"DNS not found", &net.DNSError{Err: "no such host", Name: "db", IsNotFound: true}, true},
		{"too many connections", &pgconn.PgError{Code: "53300"}, true},
		{"server starting", &pgconn.PgError{Code: "57P03"}, true},
		{"wrong password", &pgconn.PgError{Code: "28P01"}, false},
		{"no pg_hba entry", &pgconn.PgError{Code: "28000"}, false},
		{"unknown database", &pgconn.PgError{Code: "3D000"}, false},
		{"untrusted certificate", x509.UnknownAuthorityError{}, false},
		{"wrong host name", x509.HostnameError{Host: "db"}, false},
		{"server refused the handshake", &net.OpError{Op: "remote error", Err: tls.AlertError(42)}, false},
		{"TLS alert", tls.AlertError(40), false},
		{"server closed the connection", fmt.Errorf("receive message: %w", io.ErrUnexpectedEOF), true},
		// One attempt's connect timeout; the loop stops when the caller's context ends.
		{"attempt timeout", fmt.Errorf("connect: %w", context.DeadlineExceeded), true},
		{"canceled", context.Canceled, false},
		{"other", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, test := range cases {
		if got := transientConnectError(test.err); got != test.want {
			t.Errorf("%s: transient = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestConnectRetryingRetriesTransientErrors(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	attempts, slept := 0, time.Duration(0)
	connection := &pgx.Conn{}
	got, err := connectRetrying(context.Background(), connectRetryPolicy{
		window: 10 * time.Second, first: 100 * time.Millisecond, longest: time.Second,
		sleep: func(_ context.Context, wait time.Duration) error { slept += wait; return nil },
		now:   func() time.Time { return time.Unix(0, 0).Add(slept) },
	}, func(context.Context) (*pgx.Conn, error) {
		attempts++
		if attempts < 4 {
			return nil, refused
		}
		return connection, nil
	})
	if err != nil || got != connection {
		t.Fatalf("connectRetrying = %v, %v; want the connection", got, err)
	}
	if attempts != 4 || slept != 700*time.Millisecond {
		t.Fatalf("attempts %d, slept %s; want 4 attempts after 100+200+400ms", attempts, slept)
	}
}

func TestConnectRetryingStopsOnPermanentErrors(t *testing.T) {
	attempts := 0
	wrong := &pgconn.PgError{Code: "28P01"}
	_, err := connectRetrying(context.Background(), connectRetryPolicy{
		window: 10 * time.Second, first: time.Millisecond, longest: time.Millisecond,
		sleep: func(context.Context, time.Duration) error { return nil },
		now:   time.Now,
	}, func(context.Context) (*pgx.Conn, error) {
		attempts++
		return nil, wrong
	})
	if attempts != 1 || !errors.Is(err, wrong) {
		t.Fatalf("attempts %d, err %v; want one attempt and the password error", attempts, err)
	}
}

func TestConnectRetryingGivesUpAfterTheWindow(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	attempts, elapsed := 0, time.Duration(0)
	_, err := connectRetrying(context.Background(), connectRetryPolicy{
		window: 5 * time.Second, first: time.Second, longest: 2 * time.Second,
		sleep: func(_ context.Context, wait time.Duration) error { elapsed += wait; return nil },
		now:   func() time.Time { return time.Unix(0, 0).Add(elapsed) },
	}, func(context.Context) (*pgx.Conn, error) {
		attempts++
		return nil, refused
	})
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err %v; want the last connect error", err)
	}
	// Attempts at 0s, 1s, 3s, 5s: never a wait past the window.
	if attempts != 4 || elapsed > 5*time.Second {
		t.Fatalf("attempts %d after %s; want 4 within the 5s window", attempts, elapsed)
	}
}

func TestConnectRetryingStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	attempts := 0
	_, err := connectRetrying(ctx, connectRetryPolicy{
		window: time.Minute, first: time.Millisecond, longest: time.Millisecond,
		sleep: func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() },
		now:   time.Now,
	}, func(context.Context) (*pgx.Conn, error) {
		attempts++
		return nil, refused
	})
	if attempts != 1 || !errors.Is(err, syscall.ECONNREFUSED) || !errors.Is(err, context.Canceled) {
		t.Fatalf("attempts %d, err %v; want one attempt, the connect error and the cancel", attempts, err)
	}
}

func TestConnectRetryingCapsTheLastWaitAtTheWindow(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	var waits []time.Duration
	elapsed := time.Duration(0)
	_, _ = connectRetrying(context.Background(), connectRetryPolicy{
		window: 2500 * time.Millisecond, first: time.Second, longest: 4 * time.Second,
		sleep: func(_ context.Context, wait time.Duration) error {
			waits = append(waits, wait)
			elapsed += wait
			return nil
		},
		now: func() time.Time { return time.Unix(0, 0).Add(elapsed) },
	}, func(context.Context) (*pgx.Conn, error) { return nil, refused })
	if fmt.Sprint(waits) != "[1s 1.5s]" {
		t.Fatalf("waits %v; want [1s 1.5s] (the second cut to what is left of the window)", waits)
	}
}

func TestConnectRetryingSharesTheBudget(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	budget := newRetryBudget(3 * time.Second)
	elapsed := time.Duration(0)
	policy := connectRetryPolicy{
		window: time.Minute, budget: budget, first: time.Second, longest: time.Second,
		sleep: func(_ context.Context, wait time.Duration) error { elapsed += wait; return nil },
		now:   func() time.Time { return time.Unix(0, 0).Add(elapsed) },
	}
	attempts := 0
	connect := func(context.Context) (*pgx.Conn, error) { attempts++; return nil, refused }
	_, _ = connectRetrying(context.Background(), policy, connect)
	first := attempts
	_, _ = connectRetrying(context.Background(), policy, connect)
	// The first call spends the whole budget (3 waits); the second gets none.
	if first != 4 || attempts != 5 || elapsed != 3*time.Second {
		t.Fatalf("attempts %d then %d, waited %s; want 4, then 1 more, 3s in all", first, attempts, elapsed)
	}
}

func TestConnectRetryingStopsAtTheCallersDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	started := time.Now()
	_, err := connectRetrying(ctx, connectRetryPolicy{
		window: time.Minute, first: 40 * time.Millisecond, longest: 40 * time.Millisecond,
		sleep: sleepContext, now: time.Now,
	}, func(context.Context) (*pgx.Conn, error) { return nil, refused })
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatalf("err %v after %s; want the caller's deadline soon after 150ms", err, time.Since(started))
	}
}
