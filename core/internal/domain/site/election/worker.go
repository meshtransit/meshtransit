package election

import (
	"context"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/primaryelection"
	"meshtransit.net/core/internal/domain/site"
)

// PageSize is how many Sites one read returns.
const PageSize = primaryelection.PageSize

var (
	// ErrInvalidWorker rejects unsafe dependencies or timing bounds.
	ErrInvalidWorker = primaryelection.ErrInvalidWorker
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = primaryelection.ErrWorkerStarted
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = primaryelection.ErrWorkerNotStarted
)

// RouterFacts is what the database holds about one router of a Site.
type RouterFacts struct {
	Device   node.ID
	Priority int
	Draining bool
	// Live, WorkspaceOwned and Covers decide whether the Device may serve
	// the Site at all: active and unexpired, owned by the Workspace, and
	// offering every prefix of the Site.
	Live, WorkspaceOwned, Covers bool
}

// SiteFacts is one active Site with routers.
type SiteFacts struct {
	Site     site.ID
	Failback bool
	// Primary is the elected primary (zero: none, or not elected yet) and
	// Generation its election's generation (0 before the first).
	Primary    node.ID
	Generation int64
	// Routers in priority order.
	Routers []RouterFacts
}

// Page is one page of Sites in Site order.
type Page struct {
	Sites []SiteFacts
	Done  bool
}

// Facts reads the Sites to elect for, page by page after a Site.
type Facts interface {
	List(ctx context.Context, installation deployment.ID, after site.ID, limit int) (Page, error)
}

// Decision is a primary to record, made on Generation.
type Decision struct {
	Site               site.ID
	ExpectedGeneration int64
	Primary            node.ID // zero: none
	Reason             string
}

// Recorder records a decision; false when it was made on an older state.
type Recorder interface {
	Record(ctx context.Context, installation deployment.ID, decision Decision) (bool, error)
}

// Clock is this host's time.
type Clock = primaryelection.Clock

// WakeupSubscription receives wakeup hints; Receive blocks until one comes.
type WakeupSubscription = primaryelection.WakeupSubscription

// Options binds one process to an installation and its pacing.
type Options struct {
	DeploymentID                   deployment.ID
	PollInterval, OperationTimeout time.Duration
	// Wakeups, when set, subscribes to hints that a router newly reports a
	// failed Site: a pass then runs at once instead of at the next poll.
	Wakeups func(context.Context) (WakeupSubscription, error)
}

// Measurements are identifier-free process counters and the health counts
// of the last complete sweep.
type Measurements struct {
	Running                                             bool
	Passes, ReadErrors, Elections, WriteErrors, Wakeups uint64
	// Tally is nil until a sweep has completed with health known.
	Tally *Tally
}

// Tally counts Sites by how well their routers can serve them and routers by
// status, over one sweep.
type Tally struct {
	// SitesServed have a router that can serve them now.
	SitesServed uint64
	// SitesDegraded have routers, none of which can serve now (failed,
	// recovering or draining).
	SitesDegraded uint64
	// SitesUnserved have no router the Site can use at all.
	SitesUnserved uint64
	// Routers counts router entries (one router of one Site) by status.
	Routers map[Status]uint64
}

// Worker elects the primary router of every Site every poll, with the
// election of package primaryelection. It owns one goroutine.
type Worker struct {
	*primaryelection.Worker
	options Options

	// tallyMu guards the last converted tally: the same sweep converts to
	// the same pointer, so snapshots can be compared.
	tallyMu   sync.Mutex
	tallyFrom *primaryelection.Tally
	tallyTo   *Tally
}

// New constructs a stopped worker without I/O.
func New(options Options, facts Facts, recorder Recorder, observations distribution.ObservationLoader,
	clock Clock, logger *slog.Logger,
) (*Worker, error) {
	if nilPort(facts) || nilPort(recorder) {
		return nil, ErrInvalidWorker
	}
	shared, err := primaryelection.New(primaryelection.Options{
		DeploymentID: options.DeploymentID, PollInterval: options.PollInterval,
		OperationTimeout: options.OperationTimeout, Wakeups: options.Wakeups, Health: siteHealth,
		Label: "Site", Key: "site", Code: "site_election",
	}, siteFacts{facts}, siteRecorder{recorder}, observations, clock, logger)
	if err != nil {
		return nil, err
	}
	return &Worker{Worker: shared, options: options}, nil
}

func nilPort(port any) bool {
	if port == nil {
		return true
	}
	value := reflect.ValueOf(port)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Snapshot returns race-safe measurements with Site and router counts. The
// same sweep's counts are the same Tally value, so snapshots can be compared.
func (worker *Worker) Snapshot() Measurements {
	if worker == nil || worker.Worker == nil {
		return Measurements{}
	}
	shared := worker.Worker.Snapshot()
	measurements := Measurements{Running: shared.Running, Passes: shared.Passes, ReadErrors: shared.ReadErrors,
		Elections: shared.Elections, WriteErrors: shared.WriteErrors, Wakeups: shared.Wakeups}
	if shared.Tally != nil {
		measurements.Tally = worker.siteTally(shared.Tally)
	}
	return measurements
}

// siteTally names a group tally as Sites and routers.
func (worker *Worker) siteTally(tally *primaryelection.Tally) *Tally {
	worker.tallyMu.Lock()
	defer worker.tallyMu.Unlock()
	if worker.tallyFrom != tally {
		worker.tallyFrom = tally
		worker.tallyTo = &Tally{SitesServed: tally.GroupsServed, SitesDegraded: tally.GroupsDegraded,
			SitesUnserved: tally.GroupsUnserved, Routers: tally.Members}
	}
	return worker.tallyTo
}

// siteHealth reads a router's report of a Site.
func siteHealth(observation distribution.Observation, group string, now time.Time) primaryelection.Report {
	report := primaryelection.Report{ReportedAt: observation.RouteHealthAt}
	reported, fresh := distribution.CurrentRouteHealth(observation, now)
	if fresh {
		for _, entry := range reported {
			if entry.Ref == group {
				report.State, report.Code = entry.State, entry.Code
			}
		}
	}
	return report
}

// siteFacts lists Sites as groups of routers.
type siteFacts struct{ facts Facts }

func (adapter siteFacts) List(ctx context.Context, installation deployment.ID, after string,
	limit int) (primaryelection.Page, error) {
	var afterSite site.ID
	if after != "" {
		parsed, err := site.ParseID(after)
		if err != nil {
			return primaryelection.Page{}, err
		}
		afterSite = parsed
	}
	page, err := adapter.facts.List(ctx, installation, afterSite, limit)
	if err != nil {
		return primaryelection.Page{}, err
	}
	groups := make([]primaryelection.GroupFacts, 0, len(page.Sites))
	for _, facts := range page.Sites {
		members := make([]primaryelection.MemberFacts, 0, len(facts.Routers))
		for _, router := range facts.Routers {
			members = append(members, primaryelection.MemberFacts{Device: router.Device, Priority: router.Priority,
				Draining: router.Draining, Eligible: router.Live && router.WorkspaceOwned && router.Covers})
		}
		groups = append(groups, primaryelection.GroupFacts{Group: facts.Site.String(), Failback: facts.Failback,
			Primary: facts.Primary, Generation: facts.Generation, Members: members})
	}
	return primaryelection.Page{Groups: groups, Done: page.Done}, nil
}

// siteRecorder records group decisions as Site decisions.
type siteRecorder struct{ recorder Recorder }

func (adapter siteRecorder) Record(ctx context.Context, installation deployment.ID,
	decision primaryelection.Decision) (bool, error) {
	siteID, err := site.ParseID(decision.Group)
	if err != nil {
		return false, err
	}
	return adapter.recorder.Record(ctx, installation, Decision{Site: siteID,
		ExpectedGeneration: decision.ExpectedGeneration, Primary: decision.Primary, Reason: decision.Reason})
}
