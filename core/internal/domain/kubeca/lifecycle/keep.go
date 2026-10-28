package lifecycle

import (
	"time"

	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

// entry is a CA as the decision leaves it. ca is nil for a CA this decision
// creates.
type entry struct {
	ca         *kubeca.StoredCA
	issuer     publicid.ID
	createdAt  time.Time
	retiringAt time.Time
	notAfter   time.Time
}

func storedEntry(ca *kubeca.StoredCA) *entry {
	return &entry{ca: ca, issuer: ca.IssuerID, createdAt: ca.CreatedAt, retiringAt: ca.RetiringAt, notAfter: ca.NotAfter}
}

// keeper decides one active cluster's CAs. Moves come before the change
// that needs their place: a CA leaves a state before another takes it, and
// an intermediate steps down before its root does.
type keeper struct {
	decision *Decision
	cluster  publicid.ID
	name     string
	now      time.Time
	policy   Policy
	fresh    bool

	// rename lets a root under another name be replaced: only an
	// operator's explicit request sets it (§17.1 C2).
	rename bool

	activeRoot, nextRoot, retiringRoot *entry
	activeIntermediate                 *entry
	retiringIntermediates              []*entry
	newRoot                            bool
}

func newKeeper(decision *Decision, cluster kubeca.Cluster, name string, now time.Time, policy Policy,
	rename bool,
) *keeper {
	keeper := &keeper{
		decision: decision, cluster: cluster.ID, name: name, now: now, policy: policy, rename: rename,
		fresh: len(cluster.CAs) == 0,
	}
	for index := range cluster.CAs {
		ca := &cluster.CAs[index]
		current := storedEntry(ca)
		switch {
		case ca.Kind == kubeca.KindRoot && ca.State == kubeca.StateActive:
			keeper.activeRoot = current
		case ca.Kind == kubeca.KindRoot && ca.State == kubeca.StateNext:
			keeper.nextRoot = current
		case ca.Kind == kubeca.KindRoot && ca.State == kubeca.StateRetiring:
			keeper.retiringRoot = current
		case ca.Kind == kubeca.KindIntermediate && ca.State == kubeca.StateActive:
			keeper.activeIntermediate = current
		case ca.Kind == kubeca.KindIntermediate && ca.State == kubeca.StateRetiring:
			keeper.retiringIntermediates = append(keeper.retiringIntermediates, current)
		}
	}
	return keeper
}

func (keeper *keeper) keep() {
	if !keeper.rename && keeper.misnamed() {
		// A name that differs from the roots' is never acted on alone: a
		// changed naming rule or a wrong suffix must not replace every root.
		keeper.decision.Misnamed = append(keeper.decision.Misnamed, keeper.cluster)
		keeper.decision.Schedules = append(keeper.decision.Schedules, kubeca.Schedule{
			Cluster: keeper.cluster, At: keeper.now.Add(keeper.policy.RetryAfter), Failed: true,
		})
		return
	}
	keeper.dropUnusableNext()
	keeper.retireDue()
	changed, reason := keeper.keepRoot()
	keeper.keepIntermediate(changed, reason)
	keeper.decision.Schedules = append(keeper.decision.Schedules,
		kubeca.Schedule{Cluster: keeper.cluster, At: keeper.nextLook()})
}

func (keeper *keeper) move(current *entry, to kubeca.State, reason kubeca.Reason) {
	keeper.decision.move(keeper.cluster, *current.ca, to, reason)
}

func (keeper *keeper) create(kind kubeca.Kind, state kubeca.State, reason kubeca.Reason) *entry {
	create := &Create{Kind: kind, State: state, Reason: reason, ClusterDNSName: keeper.name}
	notAfter := keeper.now.Add(keeper.policy.RootLifetime)
	if kind == kubeca.KindIntermediate {
		// An intermediate ends no later than its root.
		notAfter = keeper.now.Add(keeper.policy.IntermediateLifetime)
		if keeper.activeRoot.notAfter.Before(notAfter) {
			notAfter = keeper.activeRoot.notAfter
		}
		if keeper.newRoot {
			create.IssuerNew = true
		} else {
			create.Issuer = keeper.activeRoot.ca.ID
		}
	}
	keeper.decision.Actions = append(keeper.decision.Actions, Action{Cluster: keeper.cluster, Create: create})
	return &entry{createdAt: keeper.now, notAfter: notAfter}
}

// misnamed reports a root that signs for another name than the cluster's.
func (keeper *keeper) misnamed() bool {
	for _, root := range []*entry{keeper.activeRoot, keeper.nextRoot} {
		if root != nil && root.ca.ClusterDNSName != keeper.name {
			return true
		}
	}
	return false
}

// unusable reports a CA too close to its end to sign.
func (keeper *keeper) unusable(current *entry) bool {
	return !current.notAfter.After(keeper.now.Add(kubeca.MinimumSigningLife))
}

// dropUnusableNext retires a successor root that cannot serve.
func (keeper *keeper) dropUnusableNext() {
	switch {
	case keeper.nextRoot == nil:
	case keeper.nextRoot.ca.ClusterDNSName != keeper.name:
		keeper.move(keeper.nextRoot, kubeca.StateRetired, kubeca.ReasonNameChanged)
		keeper.nextRoot = nil
	case keeper.unusable(keeper.nextRoot):
		keeper.move(keeper.nextRoot, kubeca.StateRetired, kubeca.ReasonExpired)
		keeper.nextRoot = nil
	}
}

// retireDue retires what handed over longer ago than RetireAfter: an old
// root together with whatever intermediates of it are still retiring.
func (keeper *keeper) retireDue() {
	due := func(current *entry) bool {
		return !keeper.now.Before(current.retiringAt.Add(keeper.policy.RetireAfter))
	}
	kept := keeper.retiringIntermediates[:0]
	for _, current := range keeper.retiringIntermediates {
		if due(current) {
			keeper.move(current, kubeca.StateRetired, kubeca.ReasonScheduled)
			continue
		}
		kept = append(kept, current)
	}
	keeper.retiringIntermediates = kept
	if keeper.retiringRoot != nil && due(keeper.retiringRoot) {
		keeper.retireRetiringRoot(kubeca.ReasonScheduled)
	}
}

// retireRetiringRoot retires the retiring root and its intermediates.
func (keeper *keeper) retireRetiringRoot(reason kubeca.Reason) {
	keeper.retireIntermediatesOf(keeper.retiringRoot.ca.ID, reason)
	keeper.move(keeper.retiringRoot, kubeca.StateRetired, reason)
	keeper.retiringRoot = nil
}

// retireIntermediatesOf retires the retiring intermediates of a root: the
// database retires a root only once all of them have.
func (keeper *keeper) retireIntermediatesOf(root publicid.ID, reason kubeca.Reason) {
	kept := keeper.retiringIntermediates[:0]
	for _, current := range keeper.retiringIntermediates {
		if current.issuer == root {
			keeper.move(current, kubeca.StateRetired, reason)
			continue
		}
		kept = append(kept, current)
	}
	keeper.retiringIntermediates = kept
}

// stepDownIntermediate takes the active intermediate out of signing: it
// retires outright if it cannot sign, else keeps being trusted while its
// certificates live.
func (keeper *keeper) stepDownIntermediate(reason kubeca.Reason) {
	current := keeper.activeIntermediate
	if current == nil {
		return
	}
	keeper.activeIntermediate = nil
	if keeper.unusable(current) {
		keeper.move(current, kubeca.StateRetired, kubeca.ReasonExpired)
		return
	}
	keeper.move(current, kubeca.StateRetiring, reason)
	current.retiringAt = keeper.now
	keeper.retiringIntermediates = append(keeper.retiringIntermediates, current)
}

// stepDownRoot moves the active root to retiring, retiring the root that
// was retiring before it.
func (keeper *keeper) stepDownRoot(reason kubeca.Reason) {
	if keeper.retiringRoot != nil {
		keeper.retireRetiringRoot(reason)
	}
	keeper.move(keeper.activeRoot, kubeca.StateRetiring, reason)
	keeper.activeRoot.retiringAt = keeper.now
	keeper.retiringRoot, keeper.activeRoot = keeper.activeRoot, nil
}

// keepRoot decides the root and reports whether the signing root changed,
// and why.
func (keeper *keeper) keepRoot() (bool, kubeca.Reason) {
	root := keeper.activeRoot
	switch {
	case root != nil && root.ca.ClusterDNSName != keeper.name:
		// Only an operator's rename request reaches here (§17.1 C2).
		keeper.stepDownIntermediate(kubeca.ReasonNameChanged)
		keeper.stepDownRoot(kubeca.ReasonNameChanged)
		keeper.activeRoot, keeper.newRoot = keeper.create(kubeca.KindRoot, kubeca.StateActive,
			kubeca.ReasonNameChanged), true
		return true, kubeca.ReasonNameChanged
	case root != nil && keeper.unusable(root):
		keeper.stepDownIntermediate(kubeca.ReasonExpired)
		keeper.retireIntermediatesOf(root.ca.ID, kubeca.ReasonExpired)
		keeper.move(root, kubeca.StateRetired, kubeca.ReasonExpired)
		keeper.activeRoot = nil
		return keeper.takeOver(kubeca.ReasonScheduled), kubeca.ReasonScheduled
	case root == nil:
		reason := kubeca.ReasonScheduled
		if keeper.fresh {
			reason = kubeca.ReasonInitial
		}
		return keeper.takeOver(reason), reason
	case keeper.nextRoot == nil && !keeper.now.Before(root.notAfter.Add(-keeper.policy.RootRotateBefore)):
		keeper.nextRoot = keeper.create(kubeca.KindRoot, kubeca.StateNext, kubeca.ReasonScheduled)
	case keeper.nextRoot != nil && !keeper.now.Before(keeper.nextRoot.createdAt.Add(keeper.policy.RootPublishFor)):
		keeper.stepDownIntermediate(kubeca.ReasonScheduled)
		keeper.stepDownRoot(kubeca.ReasonScheduled)
		keeper.move(keeper.nextRoot, kubeca.StateActive, kubeca.ReasonScheduled)
		keeper.activeRoot, keeper.nextRoot = keeper.nextRoot, nil
		return true, kubeca.ReasonScheduled
	}
	return false, ""
}

// takeOver makes the published successor root active, or creates an
// active root when there is none.
func (keeper *keeper) takeOver(reason kubeca.Reason) bool {
	if keeper.nextRoot != nil {
		keeper.move(keeper.nextRoot, kubeca.StateActive, kubeca.ReasonScheduled)
		keeper.activeRoot, keeper.nextRoot = keeper.nextRoot, nil
		return true
	}
	keeper.activeRoot, keeper.newRoot = keeper.create(kubeca.KindRoot, kubeca.StateActive, reason), true
	return true
}

// keepIntermediate keeps one active intermediate under the active root,
// handing over before it ends or when the root changed.
func (keeper *keeper) keepIntermediate(rootChanged bool, reason kubeca.Reason) {
	current := keeper.activeIntermediate
	switch {
	case current == nil:
	case rootChanged:
		keeper.stepDownIntermediate(reason)
	case current.issuer != keeper.activeRoot.ca.ID:
		keeper.stepDownIntermediate(kubeca.ReasonScheduled)
	case !keeper.now.Before(current.notAfter.Add(-keeper.policy.IntermediateRotateBefore)):
		keeper.stepDownIntermediate(kubeca.ReasonScheduled)
	}
	if keeper.activeIntermediate != nil {
		return
	}
	switch {
	case rootChanged:
	case keeper.fresh:
		reason = kubeca.ReasonInitial
	default:
		reason = kubeca.ReasonScheduled
	}
	keeper.activeIntermediate = keeper.create(kubeca.KindIntermediate, kubeca.StateActive, reason)
}

// nextLook is the earliest moment the CAs as decided need another look,
// no later than policy.Recheck and no sooner than a minute.
func (keeper *keeper) nextLook() time.Time {
	policy := keeper.policy
	at := keeper.now.Add(policy.Recheck)
	earlier := func(candidate time.Time) {
		if candidate.Before(at) {
			at = candidate
		}
	}
	for _, current := range keeper.retiringIntermediates {
		earlier(current.retiringAt.Add(policy.RetireAfter))
	}
	if keeper.retiringRoot != nil {
		earlier(keeper.retiringRoot.retiringAt.Add(policy.RetireAfter))
	}
	if keeper.nextRoot != nil {
		earlier(keeper.nextRoot.createdAt.Add(policy.RootPublishFor))
	} else if keeper.activeRoot != nil {
		earlier(keeper.activeRoot.notAfter.Add(-policy.RootRotateBefore))
	}
	if keeper.activeIntermediate != nil {
		earlier(keeper.activeIntermediate.notAfter.Add(-policy.IntermediateRotateBefore))
	}
	if minimum := keeper.now.Add(time.Minute); at.Before(minimum) {
		return minimum
	}
	return at
}
