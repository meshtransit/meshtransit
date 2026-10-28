// Package lifecycle keeps the CAs of Kubernetes clusters through their life
// (K1a4 §17.2, §17.6): each cluster has a long-lived root that clients
// trust and a short-lived intermediate that signs replicas. Decide says
// what a Network's CAs need; the worker turns that into stored changes.
package lifecycle

import (
	"time"

	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

// Policy is how long each tier lives and how it hands over. It is the same
// for the whole deployment (K1a4 Q14).
type Policy struct {
	// RootLifetime is the life of a new root.
	RootLifetime time.Duration
	// RootRotateBefore is how long before its end a root publishes its
	// successor; RootPublishFor how long the successor is trusted before it
	// takes over, so every client learns it first.
	RootRotateBefore, RootPublishFor time.Duration
	// IntermediateLifetime is the life of a new intermediate, give or take
	// IntermediateJitter so clusters do not all hand over the same day.
	IntermediateLifetime, IntermediateJitter time.Duration
	// IntermediateRotateBefore is how long before its end an intermediate
	// hands over: gateways renew under the new one at once.
	IntermediateRotateBefore time.Duration
	// RetireAfter is how long a CA that handed over stays trusted: longer
	// than any certificate it signed may still be in use.
	RetireAfter time.Duration
	// Recheck bounds how long a cluster waits for its next look; RetryAfter
	// is the wait after a look that could not decide.
	Recheck, RetryAfter time.Duration
}

// DefaultPolicy is ten-year roots that publish their successor a year ahead
// for 90 days, and 30-day intermediates (± 3 days) that hand over 10 days
// before their end; a CA stays trusted a certificate's life and an hour
// after it hands over.
func DefaultPolicy() Policy {
	return Policy{
		RootLifetime: kubeca.DefaultRootLifetime, RootRotateBefore: 365 * 24 * time.Hour,
		RootPublishFor: 90 * 24 * time.Hour, IntermediateLifetime: kubeca.DefaultIntermediateLifetime,
		IntermediateJitter: 3 * 24 * time.Hour, IntermediateRotateBefore: 10 * 24 * time.Hour,
		RetireAfter: kubeca.ReplicaLifetime + time.Hour, Recheck: 24 * time.Hour, RetryAfter: time.Hour,
	}
}

// Valid reports whether the policy hands over each tier before it ends and
// keeps a CA trusted while its certificates live.
func (policy Policy) Valid() bool {
	shortest := policy.IntermediateLifetime - policy.IntermediateJitter
	longest := policy.IntermediateLifetime + policy.IntermediateJitter
	return policy.RootLifetime >= kubeca.MinimumRootLifetime && policy.RootLifetime <= kubeca.MaximumRootLifetime &&
		policy.RootPublishFor > 0 && policy.RootRotateBefore > policy.RootPublishFor+policy.RetireAfter &&
		policy.RootRotateBefore < policy.RootLifetime/2 && policy.IntermediateJitter >= 0 &&
		shortest >= kubeca.MinimumIntermediateLifetime && longest <= kubeca.MaximumIntermediateLifetime &&
		policy.IntermediateRotateBefore > kubeca.ReplicaLifetime+policy.Recheck &&
		policy.IntermediateRotateBefore < shortest/2 &&
		policy.RetireAfter > kubeca.ReplicaLifetime && policy.RetireAfter <= 7*24*time.Hour &&
		policy.Recheck >= time.Minute && policy.Recheck <= 24*time.Hour &&
		policy.RetryAfter >= time.Minute && policy.RetryAfter <= policy.Recheck
}

// Create asks for a new CA of a cluster, named ClusterDNSName. An
// intermediate is signed by the existing root Issuer, or, when IssuerNew,
// by the root created earlier in the same decision.
type Create struct {
	Kind           kubeca.Kind
	State          kubeca.State
	Reason         kubeca.Reason
	ClusterDNSName string
	Issuer         publicid.ID
	IssuerNew      bool
}

// Action is one change to one cluster's CAs: exactly one of Create and Move.
type Action struct {
	Cluster publicid.ID
	Create  *Create
	Move    *kubeca.Move
}

// Decision is what a Network's CAs need now, in the order to apply it, and
// when each cluster should next be looked at. Misnamed lists the clusters
// whose roots sign for another name: nothing is done to them but alerting
// (§17.1 C2).
type Decision struct {
	Actions   []Action
	Schedules []kubeca.Schedule
	Misnamed  []publicid.ID
}

// Decide says what the CAs of a Network's clusters need at read.Now. names
// holds the DNS name each active cluster must sign for. A cluster without a
// name, or whose roots sign for another one, is left alone and retried
// later. A deleted cluster retires all its CAs.
func Decide(read kubeca.Network, names map[publicid.ID]string, policy Policy) Decision {
	return decide(read, names, policy, publicid.ID{})
}

// DecideRename is Decide with an operator's request to rename one
// cluster: its roots under another name are replaced at once by a root for
// names[cluster] (§17.1 C2); clients must then trust the new root.
func DecideRename(read kubeca.Network, names map[publicid.ID]string, policy Policy, cluster publicid.ID) Decision {
	return decide(read, names, policy, cluster)
}

func decide(read kubeca.Network, names map[publicid.ID]string, policy Policy, rename publicid.ID) Decision {
	var decision Decision
	for _, cluster := range read.Clusters {
		if !cluster.Active {
			decision.retireAll(cluster)
			continue
		}
		name, ok := names[cluster.ID]
		if !ok || name == "" {
			decision.Schedules = append(decision.Schedules,
				kubeca.Schedule{Cluster: cluster.ID, At: read.Now.Add(policy.RetryAfter), Failed: true})
			continue
		}
		keeper := newKeeper(&decision, cluster, name, read.Now, policy, rename.IsValid() && cluster.ID == rename)
		keeper.keep()
	}
	return decision
}

func (decision *Decision) move(cluster publicid.ID, ca kubeca.StoredCA, to kubeca.State, reason kubeca.Reason) {
	decision.Actions = append(decision.Actions, Action{
		Cluster: cluster,
		Move:    &kubeca.Move{CA: ca.ID, Version: ca.Version, To: to, Reason: reason},
	})
}

// retireAll retires a deleted cluster's intermediates, then its roots.
func (decision *Decision) retireAll(cluster kubeca.Cluster) {
	for _, kind := range []kubeca.Kind{kubeca.KindIntermediate, kubeca.KindRoot} {
		for _, ca := range cluster.CAs {
			if ca.Kind == kind {
				decision.move(cluster.ID, ca, kubeca.StateRetired, kubeca.ReasonClusterDeleted)
			}
		}
	}
	decision.Schedules = append(decision.Schedules, kubeca.Schedule{Cluster: cluster.ID, Done: true})
}
