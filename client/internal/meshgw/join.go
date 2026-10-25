package meshgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
)

// A K1 gateway replica joins its cluster with the join key in its Secret
// and an administrator's approval of the code it prints (mtcp-v1 §6.6),
// then, at every start, settles and rotates its keys before it serves
// (§6.8).

const (
	// joinWait is how long one join request waits for the approval on its
	// session; the replica prints its code again after each.
	joinWait = 55 * time.Second
	// joinAttemptTimeout bounds one join call: the wait and the handshake.
	joinAttemptTimeout = joinWait + 30*time.Second
	// contestedRetry: another holder of the keys pushed the replica out,
	// which reconnects within 2 seconds (mtcp-v1 §6.8).
	contestedRetry = time.Second
)

// joiner is the gateway daemon as the join loop sees it.
type joiner interface {
	controller
	JoinCluster(ctx context.Context, joinKey string, reported map[string]string, wait time.Duration) (
		daemon.ClusterJoin, error)
	PrepareGatewayKeys(ctx context.Context) error
}

// ErrJoinRefused means Core refused the join for good; the message says
// what an administrator must do.
var ErrJoinRefused = errors.New("meshgw: the cluster join was refused")

// joinUntilDone joins the cluster, printing the code while it waits; two
// asks start at least wait apart, should Core answer pending at once
// (sessions cut short by a proxy or a rolling Core). Failures that may
// pass are retried from wait, at most a minute apart.
func joinUntilDone(ctx context.Context, service joiner, cfg Config, wait time.Duration, logger *slog.Logger) error {
	backoff := wait
	expiredOnce := false
	for {
		started := time.Now()
		state, err := joinOnce(ctx, service, cfg)
		switch {
		case err == nil && state.State == daemon.ClusterJoinJoined:
			return nil
		case err == nil:
			logger.Info("enroll code: "+state.Code, "request", state.RequestID, "expires_at", state.ExpiresAt,
				"hint", "an administrator approves this replica with this code")
			backoff = wait
			if err := sleepUntil(ctx, wait-time.Since(started)); err != nil {
				return err
			}
			continue
		}
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		var rejected *controlplane.RejectedError
		if errors.As(err, &rejected) && rejected.Code == "expired" && !expiredOnce {
			// The approval came too late: one new request may get a new code.
			expiredOnce = true
			continue
		}
		if refused := joinRefusal(err); refused != nil {
			return refused
		}
		if permanent(err) {
			return err
		}
		delay := max(backoff, controlplane.RetryAfterOf(err))
		if errors.Is(err, controlplane.ErrGatewayContested) || errors.Is(err, controlplane.ErrGatewayClock) {
			delay = contestedRetry
		} else {
			backoff = min(2*backoff, enrollRetryLongest)
		}
		logger.Warn("joining the cluster failed; trying again", "error", err, "retry_in", delay)
		if err := sleepUntil(ctx, delay); err != nil {
			return err
		}
	}
}

// joinOnce asks once: the join key is read for this request only, and a
// replica that already joined needs none.
func joinOnce(ctx context.Context, service joiner, cfg Config) (daemon.ClusterJoin, error) {
	attempt, cancel := context.WithTimeout(ctx, joinAttemptTimeout)
	defer cancel()
	status, err := prepareProfile(attempt, service, cfg)
	if err != nil {
		return daemon.ClusterJoin{}, err
	}
	if status.Registration == daemon.RegistrationRegistered {
		return daemon.ClusterJoin{State: daemon.ClusterJoinJoined}, nil
	}
	key, err := readJoinKey(cfg.JoinKeyFile)
	if err != nil {
		return daemon.ClusterJoin{}, err
	}
	return service.JoinCluster(attempt, key, reported(cfg), joinWait)
}

// joinRefusal turns Core's final refusals into what an administrator must
// do, or returns nil.
func joinRefusal(err error) error {
	var rejected *controlplane.RejectedError
	if !errors.As(err, &rejected) {
		return nil
	}
	switch rejected.Code {
	case "credential_invalid", "credential_exhausted":
		return fmt.Errorf("%w: the join key is unknown, revoked, expired or used up (%s); issue a new join key",
			ErrJoinRefused, rejected.Code)
	case "expired":
		return fmt.Errorf("%w: the approval expired twice; approve the replica within the time shown", ErrJoinRefused)
	default:
		return fmt.Errorf("%w: %s (%s); remove this replica's state Secret to ask again", ErrJoinRefused,
			rejected.Code, rejected.Message)
	}
}

// prepareKeysUntilDone settles and rotates the gateway's keys at its start,
// retrying failures that may pass; it must end before the map stream.
func prepareKeysUntilDone(ctx context.Context, service joiner, wait time.Duration, logger *slog.Logger) error {
	backoff := wait
	for {
		err := service.PrepareGatewayKeys(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if permanent(err) {
			return err
		}
		delay := max(backoff, controlplane.RetryAfterOf(err))
		if errors.Is(err, controlplane.ErrGatewayContested) || errors.Is(err, controlplane.ErrGatewayClock) {
			delay = contestedRetry
		} else {
			backoff = min(2*backoff, enrollRetryLongest)
		}
		logger.Warn("preparing the gateway's keys failed; trying again", "error", err, "retry_in", delay)
		if err := sleepUntil(ctx, delay); err != nil {
			return err
		}
	}
}

// reported is what the replica says about itself while it waits.
func reported(cfg Config) map[string]string {
	fields := map[string]string{}
	for name, value := range map[string]string{
		"pod": cfg.PodName, "namespace": cfg.Namespace,
		"node": cfg.NodeName,
	} {
		if value != "" && len(value) <= 256 {
			fields[name] = value
		}
	}
	return fields
}

// readJoinKey reads the replica's join key, only when it must join.
func readJoinKey(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the mounted join key Secret
	if err != nil {
		return "", fmt.Errorf("%w: the replica must join, but %s is unreadable: %w", ErrEnrollmentKey, path, err)
	}
	joinKey := strings.TrimSpace(string(raw))
	clear(raw)
	if joinKey == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrEnrollmentKey, path)
	}
	return joinKey, nil
}

func sleepUntil(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}
