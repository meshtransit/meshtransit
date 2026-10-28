package kubecert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

// unsupportedCeiling bounds the wait while Core issues no certificates
// (§10 M4): it may be mid-upgrade.
const unsupportedCeiling = time.Hour

// ask sends the waiting request and settles Core's answer.
func (manager *Manager) ask(ctx context.Context, now time.Time) {
	request, err := manager.request()
	if err != nil {
		manager.options.Logger.WarnContext(ctx, "kubernetes gateway certificate request not made", "error_code",
			"kubernetes_certificate_token_unreadable")
		manager.retry(now, 0)
		return
	}
	manager.mu.Lock()
	if manager.since.IsZero() {
		manager.since = manager.pending.firstAt
	}
	manager.mu.Unlock()
	result, err := manager.options.Request(ctx, request)
	if ctx.Err() != nil {
		return
	}
	now = manager.options.Now()
	if err != nil {
		manager.failed(now, err)
		return
	}
	if result.Outcome == controlplane.KubeCertIssued {
		manager.issued(ctx, now, result)
		return
	}
	manager.count(result)
	manager.refused(ctx, now, result)
}

// failed settles a request that got no answer: the same request goes again.
func (manager *Manager) failed(now time.Time, err error) {
	switch {
	case errors.Is(err, controlplane.ErrKubeCertUnsupported):
		manager.countKey(outcomeKey{"error", "unsupported"})
		manager.unsupported++
		manager.nextAt = now.Add(min(unsupportedCeiling, jitter(time.Minute<<min(manager.unsupported-1, 6))))
	case errors.Is(err, controlplane.ErrKubeCertBusy):
		manager.countKey(outcomeKey{"error", "busy"})
		manager.nextAt = now.Add(jitter(2 * time.Second))
	case errors.Is(err, controlplane.ErrKubeCertTimeout):
		manager.countKey(outcomeKey{"error", "timeout"})
		manager.retry(now, 0)
	default:
		manager.countKey(outcomeKey{"error", "session"})
		manager.retry(now, 0)
	}
}

// retry sends the same request again after max(after, backoff).
func (manager *Manager) retry(now time.Time, after time.Duration) {
	manager.attempts++
	remaining := time.Hour
	if current, valid := manager.validCurrent(now); valid {
		remaining = current.NotAfter.Sub(now)
	}
	manager.nextAt = now.Add(max(after, backoff(manager.attempts, remaining)))
}

// issued takes a certificate that checks, or waits and asks with a new key.
func (manager *Manager) issued(ctx context.Context, now time.Time, result controlplane.KubeCertResult) {
	cert, err := verify(result, manager.pending.key, manager.mapCA, now)
	if err != nil {
		// Never taken; the current one stays (§10 H1).
		manager.countKey(outcomeKey{"verify_failed", ""})
		manager.options.Logger.ErrorContext(ctx, "kubernetes gateway certificate refused by the gateway",
			"error_code", "kubernetes_certificate_verify_failed", "error", err)
		manager.newKeyLater(now)
		return
	}
	manager.countKey(outcomeKey{"issued", ""})
	manager.mu.Lock()
	manager.current, manager.since = &cert, time.Time{}
	manager.mu.Unlock()
	manager.pending, manager.attempts, manager.failures, manager.unsupported, manager.refusals = nil, 0, 0, 0, 0
	manager.forceToken, manager.early = false, nil
	manager.planEarly(now)
	manager.nextAt = manager.dueAt(&cert, now)
	manager.options.Logger.InfoContext(ctx, "kubernetes gateway certificate issued",
		"serial", hex.EncodeToString(cert.Serial[:]), "not_after", cert.NotAfter.UTC(),
		"issuer", hex.EncodeToString(cert.Issuer[:4]))
}

// refused acts on a refusal or a retry (spec §6.9, design §10).
func (manager *Manager) refused(ctx context.Context, now time.Time, result controlplane.KubeCertResult) {
	action := actionFor(result)
	if action == ActionRetry {
		manager.retry(now, result.RetryAfter)
		return
	}
	manager.options.Logger.WarnContext(ctx, "kubernetes gateway certificate refused", "reason", result.Reason)
	manager.pending = nil
	manager.refusals++
	manager.mu.Lock()
	manager.since = time.Time{}
	manager.mu.Unlock()
	// Every refusal waits longer than the last until a certificate is
	// issued: a fleet refused together spreads out (a4b1 review H-A, H-B).
	wait := max(result.RetryAfter, failureBackoff(manager.refusals))
	switch action {
	case ActionToken:
		manager.forceToken = true
		// The first switch to the token is quick; one Core keeps refusing
		// waits longer each time (a4b2 review L1).
		manager.nextAt = now.Add(max(result.RetryAfter, backoff(manager.refusals, time.Hour)))
	case ActionWaitToken:
		manager.forceToken = true
		wait := &tokenWait{until: now.Add(tokenWaitLimit)}
		if token, err := manager.options.Token(); err == nil {
			wait.digest, wait.read = sha256.Sum256([]byte(token)), true
		}
		manager.waitToken = wait
		manager.nextAt = now.Add(max(result.RetryAfter, minimumTokenWait))
	case ActionWaitMap:
		manager.waitMapTill = now.Add(mapWait)
		if ca := manager.mapCA; ca != nil {
			manager.waitMapSigning = bytes.Clone(ca.Signing)
		}
		manager.nextAt = now.Add(max(wait, jitter(2*recheck)))
	case ActionNew:
		manager.nextAt = now.Add(wait)
	case ActionNewKey:
		manager.options.Logger.ErrorContext(ctx, "kubernetes gateway certificate request was malformed",
			"error_code", "kubernetes_certificate_request_malformed", "reason", result.Reason)
		manager.newKeyLater(now)
	case ActionStop:
		manager.nextAt = now.Add(max(wait, stopWait/2+random(stopWait)))
	}
}

// newKeyLater drops the request and asks with a new key after a growing
// wait (§10 H1).
func (manager *Manager) newKeyLater(now time.Time) {
	manager.pending = nil
	manager.failures++
	manager.mu.Lock()
	manager.since = time.Time{}
	manager.mu.Unlock()
	manager.nextAt = now.Add(failureBackoff(manager.failures))
}

// planEarly plans, once per pair of CAs the map names, an early renewal
// when they differ from the certificate's; a map that matches it again
// cancels it (§3.3, §10 L2).
func (manager *Manager) planEarly(now time.Time) {
	current, valid := manager.validCurrent(now)
	if !valid {
		return
	}
	spread, differs, root := earlyRenewal(*current, manager.mapCA, now)
	manager.mu.Lock()
	manager.mismatch = differs
	manager.mu.Unlock()
	if !differs {
		manager.early = nil
		return
	}
	var pair [64]byte
	copy(pair[:32], manager.mapCA.Root)
	copy(pair[32:], manager.mapCA.Signing)
	if manager.planned[pair] {
		return
	}
	manager.planned[pair] = true
	manager.early = &earlyPlan{at: now.Add(random(spread)), root: root}
	if manager.pending == nil && manager.early.at.Before(manager.nextAt) {
		manager.nextAt = manager.dueAt(current, now)
	}
}
