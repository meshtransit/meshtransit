package mapsession

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/policydigest"
)

// maximumAppliedSkew is how far in the future a client clock may place the
// time it applied a filter.
const maximumAppliedSkew = time.Minute

var (
	// ErrInvalidEnforcementReport reports malformed enforcement evidence.
	ErrInvalidEnforcementReport = errors.New("map session: invalid enforcement report")
	// ErrNoEnforcementStream reports evidence from a node whose current map
	// session is unknown; the client retries on its next report.
	ErrNoEnforcementStream = errors.New("map session: no current session for enforcement report")
	// ErrEnforcementUnavailable reports evidence that could not be stored.
	ErrEnforcementUnavailable = errors.New("map session: enforcement report unavailable")
)

// FilterDigest is the policy digest of one packet filter and how many grants
// it covers.
type FilterDigest struct {
	digest policydigest.Digest
	grants int
}

// NewFilterDigest validates a computed digest.
func NewFilterDigest(digest policydigest.Digest, grants int) (FilterDigest, error) {
	if digest.IsZero() || grants < 0 || grants > policydigest.MaximumGrants {
		return FilterDigest{}, ErrInvalidEnforcementReport
	}
	return FilterDigest{digest: digest, grants: grants}, nil
}

// Digest returns the digest value.
func (filter FilterDigest) Digest() policydigest.Digest { return filter.digest }

// Grants returns how many distinct grants the filter covers.
func (filter FilterDigest) Grants() int { return filter.grants }

// IsValid reports a computed digest.
func (filter FilterDigest) IsValid() bool { return !filter.digest.IsZero() }

// FilterDigester computes the digest of the packet filter a snapshot sends.
// The protocol adapter provides it, since the filter is its encoding.
type FilterDigester func(Snapshot) (FilterDigest, error)

// ClientEnforcement is what a node reports it enforces: the digest of the
// rules installed in its packet filter and when it installed them.
type ClientEnforcement struct {
	NodeKey   node.Key
	Filter    FilterDigest
	AppliedAt time.Time
}

// Enforcement is one enforcement report, bound to the authenticated node
// that sent it. The recorder ties it to that node's current map session.
type Enforcement struct {
	NodeKey            node.Key
	MachineFingerprint [32]byte
	Filter             FilterDigest
	AppliedAt          time.Time
	ReportedAt         time.Time
}

// IsValid reports a complete enforcement report.
func (enforcement Enforcement) IsValid() bool {
	return enforcement.NodeKey.IsValid() && enforcement.MachineFingerprint != [32]byte{} &&
		enforcement.Filter.IsValid() && !enforcement.AppliedAt.IsZero() && !enforcement.ReportedAt.IsZero() &&
		!enforcement.AppliedAt.After(enforcement.ReportedAt)
}

// EnforcementRecorder stores the latest enforcement report against the
// current map session of the reporting node, wherever that session is
// served. It reports false when the node has no current session or the
// session belongs to another machine.
type EnforcementRecorder interface {
	RecordEnforcement(context.Context, Enforcement) (bool, error)
}

// WithEnforcementRecorder returns a service that also accepts enforcement
// reports. Call it once while composing, before any stream is served.
func (service *StreamService) WithEnforcementRecorder(recorder EnforcementRecorder) (*StreamService, error) {
	if service == nil || isNilDependency(recorder) {
		return nil, ErrInvalidStreamService
	}
	recorded, err := NewStreamService(service.snapshots, service.presence, service.revisions,
		service.connectivity, service.options)
	if err != nil {
		return nil, err
	}
	recorded.delivery = service.delivery
	recorded.enforcement = recorder
	return recorded, nil
}

// ReportEnforcement stores what a node enforces. The node key must belong to
// the authenticated machine's current map session; any control replica can
// accept the report, since sessions are found through the recorder.
func (service *StreamService) ReportEnforcement(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	report ClientEnforcement,
) error {
	if ctx == nil || service == nil || !machine.IsValid() {
		return ErrInvalidStreamService
	}
	if service.enforcement == nil {
		return ErrEnforcementUnavailable
	}
	identity, err := machine.BindNodeKey(report.NodeKey)
	if err != nil || !report.Filter.IsValid() || report.AppliedAt.IsZero() {
		return ErrInvalidEnforcementReport
	}
	now := time.Now().UTC()
	if report.AppliedAt.After(now.Add(maximumAppliedSkew)) {
		return ErrInvalidEnforcementReport
	}
	appliedAt := report.AppliedAt.UTC()
	if appliedAt.After(now) {
		appliedAt = now
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	stored, err := service.enforcement.RecordEnforcement(operationCtx, Enforcement{
		NodeKey: identity.NodeKey(), MachineFingerprint: identity.MachineFingerprint(),
		Filter: report.Filter, AppliedAt: appliedAt, ReportedAt: now,
	})
	if err != nil {
		return errors.Join(ErrEnforcementUnavailable, err)
	}
	if !stored {
		return ErrNoEnforcementStream
	}
	return nil
}
