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
	// ErrKubernetesProfileClusterRequired reports a new permission set sent
	// without its cluster once sets belong to clusters (K2h Q261).
	ErrKubernetesProfileClusterRequired = errors.New("policy compilation: a new permission set names its cluster")
	// ErrKubernetesProfileClusterChange reports a set moved to another
	// cluster, or a set of one cluster made a set of every cluster: only a
	// set of every cluster may become one cluster's (K2h Q264).
	ErrKubernetesProfileClusterChange = errors.New("policy compilation: a permission set keeps its cluster")
	// ErrKubernetesProfileWrongCluster reports a rule that applies a set of
	// another cluster (K2h-I1).
	ErrKubernetesProfileWrongCluster = errors.New("policy compilation: a rule applies a set of another cluster")
	// ErrKubernetesProfileLegacy reports a rule newly applying a set of
	// every cluster once sets belong to clusters (K2h Q268).
	ErrKubernetesProfileLegacy = errors.New("policy compilation: a rule newly applies a set of every cluster")
	// ErrKubernetesProfileName reports two sets of one cluster, or a set of
	// every cluster and another set, of one name; or, until sets belong to
	// clusters, a new name shared by sets of different clusters (K2h H1).
	ErrKubernetesProfileName = errors.New("policy compilation: a permission set name is taken")
	// ErrKubernetesProfileLimit reports more permission sets than a release
	// may hold: 256 until sets belong to clusters, then 1024 (K2h Q267).
	ErrKubernetesProfileLimit = errors.New("policy compilation: too many permission sets")
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
// valid profiles with distinct IDs. Names are checked once each set's
// cluster is known (profileClusters).
func validRequestProfiles(profiles []publication.KubernetesProfile) bool {
	if len(profiles) > publication.MaximumKubernetesProfiles {
		return false
	}
	ids := make(map[publication.KubernetesProfileID]struct{}, len(profiles))
	for _, profile := range profiles {
		if _, idTaken := ids[profile.ID()]; !profile.IsValid() || idTaken {
			return false
		}
		ids[profile.ID()] = struct{}{}
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
	if request.kubernetesProfiles == nil {
		base, err := released.get()
		if err != nil {
			return nil, err
		}
		return cloneProfiles(base.Profiles), nil
	}
	base, err := released.get()
	if err != nil {
		return nil, err
	}
	return service.profileClusters(request, base.Profiles)
}

// profileClusters binds each set the request sends to its cluster (K2h
// Q261): the one named, else the one it has in the replaced release, else
// every cluster until sets belong to clusters. A set keeps its cluster but
// for every cluster becoming one; it keeps its copy origin unless sent one.
// Then the names and the count.
func (service *Service) profileClusters(request Request,
	base []publication.KubernetesProfile) ([]publication.KubernetesProfile, error) {
	held := make(map[publication.KubernetesProfileID]publication.KubernetesProfile, len(base))
	for _, profile := range base {
		held[profile.ID()] = profile
	}
	profiles := make([]publication.KubernetesProfile, 0, len(request.kubernetesProfiles))
	for _, profile := range request.kubernetesProfiles {
		before, kept := held[profile.ID()]
		choice, named := request.profileClusters[profile.ID()]
		var cluster kubecluster.ID
		switch {
		case !named && kept:
			cluster = before.Cluster()
		case !named || choice.Legacy:
			if kept && before.Cluster().IsValid() {
				return nil, ErrKubernetesProfileClusterChange
			}
			if !kept && service.clusteredProfiles {
				return nil, ErrKubernetesProfileClusterRequired
			}
		default:
			if kept && before.Cluster().IsValid() && before.Cluster() != choice.Cluster {
				return nil, ErrKubernetesProfileClusterChange
			}
			cluster = choice.Cluster
		}
		bound := profile.WithCluster(cluster)
		if !profile.CopiedFrom().IsValid() && kept {
			bound = bound.WithCopiedFrom(before.CopiedFrom())
		}
		profiles = append(profiles, bound)
	}
	if err := service.checkProfileNames(profiles, held); err != nil {
		return nil, err
	}
	return profiles, nil
}

// checkProfileNames refuses two sets of one cluster of one name, a set of
// every cluster named like another set, and more sets than a release may
// hold. Until sets belong to clusters, sets of different clusters share a
// name only as the replaced release already had them, and at most 256: a
// Core that does not know clusters still publishes them (K2h §32.12 M-2).
func (service *Service) checkProfileNames(profiles []publication.KubernetesProfile,
	held map[publication.KubernetesProfileID]publication.KubernetesProfile) error {
	limit := publication.MaximumKubernetesProfiles
	if !service.clusteredProfiles {
		limit = publication.MaximumSharedKubernetesProfiles
	}
	if len(profiles) > limit {
		return ErrKubernetesProfileLimit
	}
	byName := make(map[string][]publication.KubernetesProfile, len(profiles))
	for _, profile := range profiles {
		byName[profile.Name()] = append(byName[profile.Name()], profile)
	}
	for _, named := range byName {
		if len(named) < 2 {
			continue
		}
		clusters := make(map[kubecluster.ID]struct{}, len(named))
		for _, profile := range named {
			if _, taken := clusters[profile.Cluster()]; taken || !profile.Cluster().IsValid() {
				return ErrKubernetesProfileName
			}
			clusters[profile.Cluster()] = struct{}{}
			before, kept := held[profile.ID()]
			if !service.clusteredProfiles && (!kept || before.Name() != profile.Name()) {
				return ErrKubernetesProfileName
			}
		}
	}
	return nil
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
	// With clustered sets, a rule naming a set of every cluster keeps it only
	// if it applied it already: the replaced rule is read for that too.
	if service.access != nil && (intent.kubernetesGroups == nil || intent.kubernetesAccess == nil ||
		service.clusteredProfiles) {
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
	access, err := service.keptAccess(intent, profiles, cluster, rule, held, same)
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
	cluster kubecluster.ID, rule ReleasedClusterRule, held, same bool) (publication.KubernetesAccess, error) {
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
		// A set of every cluster stays only on a rule that applies it already
		// (K2h Q268): it is not offered to new rules once sets belong to
		// clusters.
		legacy := !service.clusteredProfiles || (same && rule.Access.ProfileID() == named.ProfileID)
		return profileAccess(profiles, cluster, named.ProfileID, named.Namespaces, named.ClusterPart,
			named.Report, named.ReportUntil, legacy, ErrKubernetesProfileUnknown)
	}
	switch {
	case service.access == nil:
		return publication.KubernetesAccess{}, nil
	case held && !rule.Access.IsZero():
		if !same {
			return publication.KubernetesAccess{}, ErrKubernetesAccessRequired
		}
		kept := rule.Access
		return profileAccess(profiles, cluster, kept.ProfileID(), kept.Namespaces(), kept.ClusterPart(),
			kept.Report(), kept.ReportUntil(), true, ErrKubernetesProfileInUse)
	case held && same, !service.accessRequired:
		return publication.KubernetesAccess{}, nil
	default:
		return publication.KubernetesAccess{}, ErrKubernetesAccessRequired
	}
}

// profileAccess applies the profile with id of the release to a rule to
// cluster: a set of that cluster, or of every cluster when legacy allows it;
// missing names what its absence means.
func profileAccess(profiles []publication.KubernetesProfile, cluster kubecluster.ID,
	id publication.KubernetesProfileID, namespaces []string, clusterPart, report bool, reportUntil time.Time,
	legacy bool, missing error) (publication.KubernetesAccess, error) {
	index := slices.IndexFunc(profiles, func(profile publication.KubernetesProfile) bool {
		return profile.ID() == id
	})
	if index < 0 {
		return publication.KubernetesAccess{}, missing
	}
	switch bound := profiles[index].Cluster(); {
	case bound.IsValid() && bound != cluster:
		return publication.KubernetesAccess{}, ErrKubernetesProfileWrongCluster
	case !bound.IsValid() && !legacy:
		return publication.KubernetesAccess{}, ErrKubernetesProfileLegacy
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
