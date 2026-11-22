package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// connectRetryPolicy bounds how long a one-shot connection (a Job's or a
// setup command's) keeps trying. A Kubernetes Job's pod can start before the
// NetworkPolicy that lets it reach the database is in force (policies are
// applied asynchronously; a hook policy is recreated just before its Job),
// and a database can be restarting or at its connection limit for a moment.
//
// Each attempt still has the connection's own connect timeout, and a name
// lookup is bounded only by the caller's context, so one call can last
// longer than its window by one attempt.
type connectRetryPolicy struct {
	// window bounds the waits of one call; budget, when set, those of every
	// call sharing it (a command that connects many times in a row).
	window  time.Duration
	budget  *retryBudget
	first   time.Duration
	longest time.Duration
	sleep   func(context.Context, time.Duration) error
	now     func() time.Time
}

// retryBudget is the waiting time left to the calls sharing it.
type retryBudget struct {
	mutex sync.Mutex
	left  time.Duration
}

func newRetryBudget(total time.Duration) *retryBudget { return &retryBudget{left: total} }

// take returns up to want of the budget, and removes it.
func (budget *retryBudget) take(want time.Duration) time.Duration {
	budget.mutex.Lock()
	defer budget.mutex.Unlock()
	granted := max(min(want, budget.left), 0)
	budget.left -= granted
	return granted
}

// processConnectBudget is shared by every direct connection of the process:
// the install bootstrap connects a dozen times, and a database at its
// connection limit must not cost each of them a full window before the Job's
// deadline. It is never refilled: every caller is a one-shot command or Job;
// a long-running process would stop retrying once it is spent.
var processConnectBudget = newRetryBudget(60 * time.Second)

func defaultConnectRetry() connectRetryPolicy {
	return connectRetryPolicy{
		window:  30 * time.Second,
		budget:  processConnectBudget,
		first:   250 * time.Millisecond,
		longest: 4 * time.Second,
		sleep:   sleepContext,
		now:     time.Now,
	}
}

// connectDirect opens one direct connection, retrying transient failures
// within the default window. Credentials, database and certificate errors
// are returned at once.
func connectDirect(ctx context.Context, config *pgx.ConnConfig) (*pgx.Conn, error) {
	return connectRetrying(ctx, defaultConnectRetry(), func(ctx context.Context) (*pgx.Conn, error) {
		return pgx.ConnectConfig(ctx, config)
	})
}

func connectRetrying(
	ctx context.Context,
	policy connectRetryPolicy,
	connect func(context.Context) (*pgx.Conn, error),
) (*pgx.Conn, error) {
	deadline := policy.now().Add(policy.window)
	wait := policy.first
	for {
		connection, err := connect(ctx)
		if err == nil {
			return connection, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			return nil, errors.Join(err, ctxErr)
		}
		if ctx.Err() != nil || !transientConnectError(err) {
			return nil, err
		}
		pause := min(wait, deadline.Sub(policy.now()))
		if policy.budget != nil && pause > 0 {
			pause = policy.budget.take(pause)
		}
		if pause <= 0 {
			return nil, err
		}
		if sleepErr := policy.sleep(ctx, pause); sleepErr != nil {
			return nil, errors.Join(err, sleepErr)
		}
		wait = min(2*wait, policy.longest)
	}
}

// transientConnectError reports a failure another attempt may not meet: the
// network (refused, unreachable, timed out, name lookup), a server that
// closed the connection, is starting or is at its connection limit. Never a
// credential, database or certificate error, a TLS handshake the server
// refused, nor a cancelled caller.
func transientConnectError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var (
		unknownAuthority x509.UnknownAuthorityError
		hostname         x509.HostnameError
		invalid          x509.CertificateInvalidError
		verification     *tls.CertificateVerificationError
		alert            tls.AlertError // QUIC; over TCP an alert is a "remote error" OpError
		server           *pgconn.PgError
		operation        *net.OpError
		lookup           *net.DNSError
	)
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) ||
		errors.As(err, &verification) || errors.As(err, &alert) {
		return false
	}
	if errors.As(err, &server) {
		// too_many_connections, cannot_connect_now
		return server.Code == "53300" || server.Code == "57P03"
	}
	if errors.As(err, &operation) {
		// The server refused the TLS handshake (a client certificate, no
		// shared version or cipher): a setting, not the network.
		return operation.Op != "remote error"
	}
	return errors.As(err, &lookup) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
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
