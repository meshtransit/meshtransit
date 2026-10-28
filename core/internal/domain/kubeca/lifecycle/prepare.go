package lifecycle

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

// ErrPlanChanged reports a Network that changed between the read the keys
// were prepared from and the read under its lock: nothing was applied, and
// the next pass prepares again.
var ErrPlanChanged = errors.New("kubernetes CA lifecycle: the Network changed while keys were prepared")

// Sealer seals and opens CA private keys: the installation's identity and
// the Network's data keys in the clear.
type Sealer struct {
	Installation string
	// DataKeyID and DataKey are the Network's active data key, which seals
	// every new CA.
	DataKeyID publicid.ID
	DataKey   kubeca.DataKey
	// OpenDataKey returns another data key of the Network in the clear, for
	// a root sealed under a data key since retired.
	OpenDataKey func(id publicid.ID) (kubeca.DataKey, error)
}

// Prepare turns a decision into stored changes, outside any transaction
// that holds a lock (§17.3): it generates and seals each CA the decision
// creates, an intermediate under the root created before it or under the
// cluster's stored active root. NotBefore is the database clock of the
// read; jitter spreads intermediate lifetimes.
func Prepare(read kubeca.Network, decision Decision, sealer Sealer, policy Policy,
	jitter func(time.Duration) time.Duration,
) ([]kubeca.Step, error) {
	clusters := make(map[publicid.ID]kubeca.Cluster, len(read.Clusters))
	for _, cluster := range read.Clusters {
		clusters[cluster.ID] = cluster
	}
	created := map[publicid.ID]createdRoot{}
	// Roots this plan makes active sign intermediates later in it, though
	// the read still shows them next (review a2 H-A).
	promoted := map[publicid.ID]bool{}
	steps := make([]kubeca.Step, 0, len(decision.Actions))
	for _, action := range decision.Actions {
		if action.Move != nil {
			move := *action.Move
			if move.To == kubeca.StateActive {
				promoted[move.CA] = true
			}
			steps = append(steps, kubeca.Step{Move: &move})
			continue
		}
		cluster, ok := clusters[action.Cluster]
		if !ok || action.Create == nil {
			return nil, kubeca.ErrInvalid
		}
		creation, root, err := prepareCreate(read.Now, cluster, *action.Create, created[cluster.ID], promoted, sealer,
			policy, jitter)
		if err != nil {
			return nil, err
		}
		if action.Create.Kind == kubeca.KindRoot && action.Create.State == kubeca.StateActive {
			created[cluster.ID] = createdRoot{id: creation.ID, ca: root}
		}
		steps = append(steps, kubeca.Step{Create: creation})
	}
	return steps, nil
}

type createdRoot struct {
	id publicid.ID
	ca kubeca.CA
}

func prepareCreate(now time.Time, cluster kubeca.Cluster, create Create, fresh createdRoot,
	promoted map[publicid.ID]bool, sealer Sealer, policy Policy, jitter func(time.Duration) time.Duration,
) (*kubeca.Creation, kubeca.CA, error) {
	id, err := publicid.New()
	if err != nil {
		return nil, kubeca.CA{}, err
	}
	label := subjectLabel(cluster.Name, id)
	var ca kubeca.CA
	var issuer publicid.ID
	switch create.Kind {
	case kubeca.KindRoot:
		ca, err = kubeca.NewRoot(kubeca.RootParams{
			ClusterDNSName: create.ClusterDNSName,
			Subject:        label + " root", NotBefore: now, Lifetime: policy.RootLifetime,
		})
	case kubeca.KindIntermediate:
		var root kubeca.CA
		root, issuer, err = issuerRoot(cluster, create, fresh, promoted, sealer)
		if err == nil {
			lifetime := policy.IntermediateLifetime + jitter(policy.IntermediateJitter)
			ca, err = root.NewIntermediate(kubeca.IntermediateParams{
				Subject: label, NotBefore: now,
				Lifetime: lifetime,
			})
		}
	default:
		err = kubeca.ErrInvalid
	}
	if err != nil {
		return nil, kubeca.CA{}, err
	}
	sealed, err := kubeca.SealCA(sealer.DataKey, ca, sealer.Installation, cluster.ID.String(), id.String())
	if err != nil {
		return nil, kubeca.CA{}, err
	}
	certificate := ca.Certificate()
	return &kubeca.Creation{
		Cluster: cluster.ID, ID: id, Kind: create.Kind, IssuerID: issuer, State: create.State, Reason: create.Reason,
		DataKeyID: sealer.DataKeyID, Certificate: certificate.Raw, ClusterDNSName: create.ClusterDNSName,
		NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter, SealedKey: sealed,
	}, ca, nil
}

// issuerRoot opens the root an intermediate is created under: the one this
// preparation created, or the stored one the decision names, active or
// promoted earlier in the plan.
func issuerRoot(cluster kubeca.Cluster, create Create, fresh createdRoot, promoted map[publicid.ID]bool,
	sealer Sealer,
) (kubeca.CA, publicid.ID, error) {
	if create.IssuerNew {
		if !fresh.id.IsValid() {
			return kubeca.CA{}, publicid.ID{}, kubeca.ErrInvalid
		}
		return fresh.ca, fresh.id, nil
	}
	for _, stored := range cluster.CAs {
		signing := stored.State == kubeca.StateActive || stored.State == kubeca.StateNext && promoted[stored.ID]
		if stored.ID != create.Issuer || stored.Kind != kubeca.KindRoot || !signing {
			continue
		}
		dataKey := sealer.DataKey
		if stored.DataKeyID != sealer.DataKeyID {
			var err error
			if sealer.OpenDataKey == nil {
				return kubeca.CA{}, publicid.ID{}, kubeca.ErrInvalid
			}
			if dataKey, err = sealer.OpenDataKey(stored.DataKeyID); err != nil {
				return kubeca.CA{}, publicid.ID{}, err
			}
		}
		root, err := kubeca.OpenRoot(dataKey, stored.Certificate, stored.SealedKey, sealer.Installation,
			cluster.ID.String(), stored.ID.String())
		if err != nil {
			return kubeca.CA{}, publicid.ID{}, err
		}
		if root.ClusterDNSName() != create.ClusterDNSName {
			return kubeca.CA{}, publicid.ID{}, kubeca.ErrInvalid
		}
		return root, stored.ID, nil
	}
	return kubeca.CA{}, publicid.ID{}, kubeca.ErrInvalid
}

// subjectLabel names a CA by its cluster and the start of its ID, so two
// CAs of one cluster never share a subject (§17.3).
func subjectLabel(cluster string, id publicid.ID) string {
	if len(cluster) > 40 {
		cluster = cluster[:40]
	}
	return cluster + " " + id.String()[:8]
}

// shape is a decision's actions without what preparing adds, to tell
// whether the Network still needs what was prepared.
func shape(decision Decision) string {
	var builder strings.Builder
	for _, action := range decision.Actions {
		switch {
		case action.Move != nil:
			fmt.Fprintf(&builder, "m %s %s %d %s %s;", action.Cluster, action.Move.CA, action.Move.Version,
				action.Move.To, action.Move.Reason)
		case action.Create != nil:
			create := action.Create
			fmt.Fprintf(&builder, "c %s %s %s %s %s %s %t;", action.Cluster, create.Kind, create.State, create.Reason,
				create.ClusterDNSName, create.Issuer, create.IssuerNew)
		}
	}
	return builder.String()
}

// Recheck returns the plan to apply under the Network's lock: the prepared
// steps, if decide still needs exactly what was prepared from the locked
// read, with the locked read's schedules; ErrPlanChanged otherwise.
func Recheck(prepared Decision, steps []kubeca.Step, locked kubeca.Network,
	decide func(kubeca.Network) Decision,
) (kubeca.Changes, error) {
	current := decide(locked)
	if shape(current) != shape(prepared) {
		return kubeca.Changes{}, ErrPlanChanged
	}
	return kubeca.Changes{Steps: steps, Schedules: current.Schedules}, nil
}
