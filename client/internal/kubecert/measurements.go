package kubecert

import (
	"maps"
	"slices"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

// knownReasons are the reasons counted by name (spec §6.9); any other is
// "other".
var knownReasons = []string{
	"unavailable", "busy", "limited", "overloaded", "timeout", "presence", "internal", "contested", "csr",
	"conflict", "invalid", "not_gateway", "not_proven", "no_ca", "misnamed", "trust_missing", "token",
	"token_expired", "token_used", "proof", "renewal_expired", "renewal_unknown", "revoked", "cluster",
	"attempts", "superseded",
}

// Measurements are identifier-free counts and times for metrics and the
// gateway's local status.
type Measurements struct {
	// HasCertificate: one valid now, with its NotAfter and RenewAt (Core's
	// clock), serial and the SHA-256 of its issuer and root.
	HasCertificate    bool
	NotAfter, RenewAt time.Time
	Serial            [16]byte
	Issuer, Root      [32]byte
	// MapMismatch: the map names CAs other than the certificate's.
	MapMismatch bool
	// WaitingSince is when the request waiting for an answer was made;
	// zero: none waits. WaitingFor is how long, on the same clock.
	WaitingSince time.Time
	WaitingFor   time.Duration
	// Requests counts answers by outcome (issued, refused, retry,
	// verify_failed, error) and reason, and the stored certificate's fate
	// (restored, restore_refused, restored_renew): not answers.
	Requests map[[2]string]uint64
}

// Snapshot returns the manager's measurements, all read at once (a4b2
// review L3).
func (manager *Manager) Snapshot() Measurements {
	now := manager.options.Now()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	measurements := Measurements{
		MapMismatch: manager.mismatch, WaitingSince: manager.since,
		Requests: make(map[[2]string]uint64, len(manager.counts)),
	}
	if !manager.since.IsZero() {
		measurements.WaitingFor = max(0, now.Sub(manager.since))
	}
	if current := manager.current; current != nil && current.NotAfter.After(now) {
		measurements.HasCertificate, measurements.NotAfter, measurements.RenewAt = true, current.NotAfter,
			current.RenewAt
		measurements.Serial, measurements.Issuer, measurements.Root = current.Serial, current.Issuer, current.Root
	}
	for _, key := range slices.Collect(maps.Keys(manager.counts)) {
		measurements.Requests[[2]string{key.outcome, key.reason}] = manager.counts[key]
	}
	return measurements
}

// count counts a refusal or a retry by its reason.
func (manager *Manager) count(result controlplane.KubeCertResult) {
	outcome := "retry"
	if result.Outcome == controlplane.KubeCertRefused {
		outcome = "refused"
	}
	reason := result.Reason
	if !slices.Contains(knownReasons, reason) {
		reason = "other"
	}
	manager.countKey(outcomeKey{outcome, reason})
}

func (manager *Manager) countKey(key outcomeKey) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.counts[key]++
}
