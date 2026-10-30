package compilation

import (
	"context"
	"errors"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/shared/kubeprofile"
)

var (
	// ErrKubernetesAccessRequired reports a rule to a Kubernetes cluster
	// sent without its access where nothing may be kept: one that applied a
	// profile and now comes from another source or goes to another cluster,
	// or, once access is required, any new rule to a cluster.
	ErrKubernetesAccessRequired = errors.New("policy compilation: a rule to a Kubernetes cluster needs its access")
	// ErrKubernetesProfileUnknown reports a rule that applies a profile the
	// release does not hold.
	ErrKubernetesProfileUnknown = errors.New("policy compilation: unknown Kubernetes access profile")
	// ErrKubernetesProfileInUse reports a release that drops a profile a
	// rule keeps applying.
	ErrKubernetesProfileInUse = errors.New("policy compilation: a removed Kubernetes access profile is in use")
	// ErrKubernetesReportWindow reports a report deadline that is not in the
	// next MaximumKubernetesReport.
	ErrKubernetesReportWindow = errors.New("policy compilation: Kubernetes report deadline out of range")
	// ErrKubernetesAccessLimit reports rules to one cluster whose grants or
	// scope table would pass what a gateway takes.
	ErrKubernetesAccessLimit = publication.ErrKubernetesAccessLimit
)

// reportClockMargin is how much earlier than 14 days from now a report
// deadline must be.
const reportClockMargin = 5 * time.Minute

// KubernetesAccessIntent is how a rule to a cluster applies its Kubernetes
// groups: in full, or narrowed to a profile of the release in some
// namespaces, enforcing or reporting until a deadline.
type KubernetesAccessIntent struct {
	Full        bool
	ProfileID   publication.KubernetesProfileID
	Namespaces  []string
	ClusterPart bool
	Report      bool
	ReportUntil time.Time
}

// IsValid reports either full access and nothing else, or a profile with
// valid namespaces and a report deadline exactly when it reports.
func (access *KubernetesAccessIntent) IsValid() bool {
	if access == nil {
		return false
	}
	if access.Full {
		return !access.ProfileID.IsValid() && access.Namespaces == nil && !access.ClusterPart && !access.Report &&
			access.ReportUntil.IsZero()
	}
	if !access.ProfileID.IsValid() || access.Report == access.ReportUntil.IsZero() {
		return false
	}
	_, err := kubeprofile.ScopeHash([32]byte{}, access.Namespaces, access.ClusterPart)
	return err == nil
}

func (access *KubernetesAccessIntent) clone() *KubernetesAccessIntent {
	if access == nil {
		return nil
	}
	cloned := *access
	cloned.Namespaces = slices.Clone(access.Namespaces)
	return &cloned
}

// KubernetesAccess returns how the rule applies its groups, nil when it
// keeps what it has in the release the request replaces.
func (intent RuleIntent) KubernetesAccess() *KubernetesAccessIntent {
	return intent.kubernetesAccess.clone()
}

// WithKubernetesAccess returns the intent to a cluster with its access, for
// a reader of a release that holds it.
func (intent RuleIntent) WithKubernetesAccess(access *KubernetesAccessIntent) (RuleIntent, error) {
	named := intent
	named.destinationPrefixes = slices.Clone(intent.destinationPrefixes)
	named.destinationPortRanges = slices.Clone(intent.destinationPortRanges)
	named.kubernetesGroups = slices.Clone(intent.kubernetesGroups)
	named.kubernetesAccess = access.clone()
	if !named.IsValid() {
		return RuleIntent{}, ErrInvalidRequest
	}
	return named, nil
}

// cloneProfiles copies profiles, keeping nil apart from empty.
func cloneProfiles(profiles []publication.KubernetesProfile) []publication.KubernetesProfile {
	if profiles == nil {
		return nil
	}
	return append(make([]publication.KubernetesProfile, 0, len(profiles)), profiles...)
}

// validRequestProfiles reports nil, or at most MaximumKubernetesProfiles
// valid profiles with distinct IDs and names.
func validRequestProfiles(profiles []publication.KubernetesProfile) bool {
	if len(profiles) > publication.MaximumKubernetesProfiles {
		return false
	}
	ids := make(map[publication.KubernetesProfileID]struct{}, len(profiles))
	names := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		_, idTaken := ids[profile.ID()]
		_, nameTaken := names[profile.Name()]
		if !profile.IsValid() || idTaken || nameTaken {
			return false
		}
		ids[profile.ID()], names[profile.Name()] = struct{}{}, struct{}{}
	}
	return true
}

// ReleasedKubernetesAccess is what a release holds of Kubernetes access:
// its rules to clusters and its profiles.
type ReleasedKubernetesAccess struct {
	Rules    map[policy.RuleID]ReleasedClusterRule
	Profiles []publication.KubernetesProfile
}

// KubernetesAccessReader returns the rules to Kubernetes clusters and the
// access profiles of the scope's release at a policy revision (K1a3, K2).
type KubernetesAccessReader interface {
	ReadPolicyKubernetesAccess(context.Context, accountsession.Session, network.Scope,
		int64) (ReleasedKubernetesAccess, error)
}

// releasedAccess reads the release the request replaces once, when first
// needed. The first release (revision 2) replaces none.
type releasedAccess struct {
	read    func() (ReleasedKubernetesAccess, error)
	value   ReleasedKubernetesAccess
	err     error
	settled bool
}

func (released *releasedAccess) get() (ReleasedKubernetesAccess, error) {
	if !released.settled {
		released.value, released.err = released.read()
		released.settled = true
	}
	return released.value, released.err
}

func (service *Service) releasedAccess(ctx context.Context, session accountsession.Session,
	request Request) *releasedAccess {
	return &releasedAccess{read: func() (ReleasedKubernetesAccess, error) {
		replaced := request.revision - 1
		if service.access == nil || replaced <= 1 {
			return ReleasedKubernetesAccess{}, nil
		}
		return service.access.ReadPolicyKubernetesAccess(ctx, session, request.scope, replaced)
	}}
}

// requestProfiles returns the profiles of the release: the request's, else
// those of the release it replaces. A request that sends or applies a
// profile needs a compiler that knows profiles.
func (service *Service) requestProfiles(request Request,
	released *releasedAccess) ([]publication.KubernetesProfile, error) {
	applies := slices.ContainsFunc(request.rules, func(intent RuleIntent) bool {
		return intent.kubernetesAccess != nil && !intent.kubernetesAccess.Full
	})
	if service.access == nil {
		if len(request.kubernetesProfiles) > 0 || applies {
			return nil, ErrInvalidRequest
		}
		return request.kubernetesProfiles, nil
	}
	if request.kubernetesProfiles != nil {
		return cloneProfiles(request.kubernetesProfiles), nil
	}
	base, err := released.get()
	if err != nil {
		return nil, err
	}
	return cloneProfiles(base.Profiles), nil
}

// clusterRuleAccess returns the Kubernetes groups and access of a group
// rule. Groups: those named, else those of the replaced release (see
// keptKubernetesGroups). Access, independent of the groups sent: the one
// named; else the one the replaced release holds for the same rule from the
// same source to the same cluster, its profile at the content the new
// release holds; else full for a new rule unless access is required. A rule
// that applied a profile and moved is refused rather than widened.
func (service *Service) clusterRuleAccess(released *releasedAccess, profiles []publication.KubernetesProfile,
	intent RuleIntent, cluster kubecluster.ID) ([]string, publication.KubernetesAccess, error) {
	if !cluster.IsValid() {
		return intent.KubernetesGroups(), publication.KubernetesAccess{}, nil
	}
	var rule ReleasedClusterRule
	held, same := false, false
	if service.access != nil && (intent.kubernetesGroups == nil || intent.kubernetesAccess == nil) {
		base, err := released.get()
		if err != nil {
			return nil, publication.KubernetesAccess{}, err
		}
		rule, held = base.Rules[intent.id]
		kind, source := intent.sourceSide()
		same = held && rule.Cluster == cluster && rule.SourceKind == kind && rule.SourceID == source
	}
	groups, err := service.keptGroups(intent, rule, held, same)
	if err != nil {
		return nil, publication.KubernetesAccess{}, err
	}
	access, err := service.keptAccess(intent, profiles, rule, held, same)
	if err != nil {
		return nil, publication.KubernetesAccess{}, err
	}
	if !access.IsZero() && groups == nil {
		return nil, publication.KubernetesAccess{}, ErrKubernetesGroupsRequired
	}
	return groups, access, nil
}

// keptGroups returns the groups a rule names, else those of the same rule
// from the same source to the same cluster, else none for a rule released
// without any. A new or moved rule without groups is refused. Without a
// reader, only those it names.
func (service *Service) keptGroups(intent RuleIntent, rule ReleasedClusterRule, held, same bool) ([]string, error) {
	if intent.kubernetesGroups != nil || service.access == nil {
		return intent.KubernetesGroups(), nil
	}
	if !held {
		return nil, ErrKubernetesGroupsRequired
	}
	if rule.Groups == nil {
		return nil, nil // released before K1a3: it grants no group
	}
	if !same {
		return nil, ErrKubernetesGroupsRequired
	}
	return slices.Clone(rule.Groups), nil
}

func (service *Service) keptAccess(intent RuleIntent, profiles []publication.KubernetesProfile,
	rule ReleasedClusterRule, held, same bool) (publication.KubernetesAccess, error) {
	if named := intent.kubernetesAccess; named != nil {
		if named.Full {
			return publication.KubernetesAccess{}, nil
		}
		if named.Report {
			// The database bounds the deadline by the release's own time;
			// a margin keeps a Core clock a little ahead of it from passing
			// here what the database then refuses (review d2 L2).
			now := service.now()
			if !named.ReportUntil.After(now) ||
				named.ReportUntil.After(now.Add(publication.MaximumKubernetesReport-reportClockMargin)) {
				return publication.KubernetesAccess{}, ErrKubernetesReportWindow
			}
		}
		return profileAccess(profiles, named.ProfileID, named.Namespaces, named.ClusterPart, named.Report,
			named.ReportUntil, ErrKubernetesProfileUnknown)
	}
	switch {
	case service.access == nil:
		return publication.KubernetesAccess{}, nil
	case held && !rule.Access.IsZero():
		if !same {
			return publication.KubernetesAccess{}, ErrKubernetesAccessRequired
		}
		kept := rule.Access
		return profileAccess(profiles, kept.ProfileID(), kept.Namespaces(), kept.ClusterPart(), kept.Report(),
			kept.ReportUntil(), ErrKubernetesProfileInUse)
	case held && same, !service.accessRequired:
		return publication.KubernetesAccess{}, nil
	default:
		return publication.KubernetesAccess{}, ErrKubernetesAccessRequired
	}
}

// profileAccess applies the profile with id of the release; missing names
// what its absence means.
func profileAccess(profiles []publication.KubernetesProfile, id publication.KubernetesProfileID,
	namespaces []string, clusterPart, report bool, reportUntil time.Time,
	missing error) (publication.KubernetesAccess, error) {
	index := slices.IndexFunc(profiles, func(profile publication.KubernetesProfile) bool {
		return profile.ID() == id
	})
	if index < 0 {
		return publication.KubernetesAccess{}, missing
	}
	access, err := publication.NewKubernetesAccess(publication.KubernetesAccessParams{
		ProfileID: id, ProfileHash: profiles[index].ContentHash(), Namespaces: namespaces,
		ClusterPart: clusterPart, Report: report, ReportUntil: reportUntil,
	})
	if err != nil {
		return publication.KubernetesAccess{}, ErrInvalidRequest
	}
	return access, nil
}
