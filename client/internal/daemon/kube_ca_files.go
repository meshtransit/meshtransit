package daemon

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"meshtransit.net/client/internal/kubecafile"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/privatefile"
)

// kubeCAReconcileEvery is how often the CA files are reconciled without a
// map: expiry, repairs and retries happen on time (K1e design §3.3).
const kubeCAReconcileEvery = time.Minute

// kubeCAStrict is how many directories up from a profile's directory are
// checked strictly: the profile's and kube, and MeshTransit on Windows,
// which no user may write (K1e design §3.1, re-review H-b).
func kubeCAStrict() int {
	if runtime.GOOS == "windows" {
		return 3
	}
	return 2
}

// kubeCAFiles keeps the Kubernetes CA files of the profile meshd serves
// (K1e design §3): reconciled on every map and every minute, withheld when
// meshd stops serving the profile, resumed by a map taken since. The map
// and status paths only record and read state; every disk access happens
// in run's goroutine (review e1b M3).
type kubeCAFiles struct {
	base      string
	logger    *slog.Logger
	now       func() time.Time
	connected func(profileID string) bool
	signal    chan struct{}

	mu sync.Mutex
	// serving is the profile meshd serves now ("" none); clusters and the
	// flags are its last map's.
	serving       string
	clusters      []networkmap.KubernetesCluster
	authoritative bool
	negotiated    bool
	// withhold are the profiles to withhold, until done; withheld those
	// withheld since their last map; resume those to resume on the next
	// pass (a map taken since).
	withhold map[string]bool
	withheld map[string]bool
	resume   map[string]bool
	statuses map[string]kubecafile.Status
	failing  bool
	// withholdFailing: a withhold failed and was logged; stopped are
	// closed by the pass that finishes the withholds pending at the time.
	withholdFailing bool
	stopped         []chan struct{}

	// managers is run's goroutine's alone.
	managers map[string]*kubecafile.Manager
}

func newKubeCAFiles(base string, logger *slog.Logger, now func() time.Time,
	connected func(profileID string) bool,
) *kubeCAFiles {
	if base == "" {
		return nil
	}
	return &kubeCAFiles{
		base: filepath.Clean(base), logger: logger, now: now, connected: connected,
		signal: make(chan struct{}, 1), managers: map[string]*kubecafile.Manager{},
		withhold: map[string]bool{}, withheld: map[string]bool{}, resume: map[string]bool{},
	}
}

// profileDirectory is a profile's directory, checked on every open.
type profileDirectory struct {
	base, path string
}

func (dir profileDirectory) Path() string { return dir.path }

func (dir profileDirectory) Open() (*os.Root, error) {
	if err := privatefile.PreparePublicDir(dir.base, kubeCAStrict()-1); err != nil {
		return nil, err
	}
	if err := privatefile.PreparePublicDir(dir.path, kubeCAStrict()); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir.path)
}

// validProfileDir accepts the profile IDs meshd makes: lowercase hex.
func validProfileDir(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, character := range id {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// serve records the profile the session loop is about to serve: the one
// served before, if another, is withheld (review e1b H1).
func (files *kubeCAFiles) serve(profileID string) {
	if files == nil {
		return
	}
	files.mu.Lock()
	if files.serving != "" && files.serving != profileID {
		files.stopLocked()
	}
	files.mu.Unlock()
	files.wake()
}

// stop withholds the served profile: meshd stopped serving it (down, no
// Device, no profile). It waits up to kubeCAStopWait for the markers, so
// `meshctl down` returns with them on disk (re-review e1b L1).
func (files *kubeCAFiles) stop() {
	if files == nil {
		return
	}
	done := make(chan struct{})
	files.mu.Lock()
	files.stopLocked()
	files.stopped = append(files.stopped, done)
	files.mu.Unlock()
	files.wake()
	select {
	case <-done:
	case <-time.After(kubeCAStopWait):
	}
}

// kubeCAStopWait bounds how long a stop waits for its markers.
const kubeCAStopWait = 2 * time.Second

func (files *kubeCAFiles) stopLocked() {
	if files.serving == "" {
		return
	}
	files.withhold[files.serving] = true
	delete(files.resume, files.serving)
	files.serving, files.clusters, files.statuses = "", nil, nil
}

// observe takes a map of profileID: it serves that profile, resuming its
// files if they were withheld.
func (files *kubeCAFiles) observe(profileID string, snapshot networkmap.Snapshot) {
	if files == nil || snapshot.KubernetesClusters == nil {
		return
	}
	files.mu.Lock()
	if files.serving != "" && files.serving != profileID {
		files.stopLocked()
	}
	files.serving = profileID
	files.clusters = snapshot.KubernetesClusters
	files.authoritative = snapshot.KubernetesClustersAuthoritative
	files.negotiated = snapshot.KubernetesClustersNegotiated
	if files.withhold[profileID] || files.withheld[profileID] {
		delete(files.withhold, profileID)
		files.resume[profileID] = true
	}
	files.mu.Unlock()
	files.wake()
}

func (files *kubeCAFiles) wake() {
	select {
	case files.signal <- struct{}{}:
	default:
	}
}

// run reconciles on every change and every minute until ctx ends; then the
// served profile's files are withheld (a graceful stop, Q118).
func (files *kubeCAFiles) run(ctx context.Context) {
	if files == nil {
		return
	}
	ticker := time.NewTicker(kubeCAReconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// This goroutine does the passes: record the stop, then pass.
			files.mu.Lock()
			files.stopLocked()
			files.mu.Unlock()
			files.pass()
			return
		case <-files.signal:
		case <-ticker.C:
		}
		files.pass()
	}
}

// pass withholds what is to be withheld, retrying what failed (review e1b
// H2), then reconciles the served profile. Disk access holds no lock the
// map or status paths take.
func (files *kubeCAFiles) pass() {
	files.mu.Lock()
	withhold := make([]string, 0, len(files.withhold))
	for id := range files.withhold {
		withhold = append(withhold, id)
	}
	serving, clusters := files.serving, files.clusters
	pass := kubecafile.Pass{Authoritative: files.authoritative}
	negotiated, resume := files.negotiated, files.resume[serving]
	delete(files.resume, serving)
	stopped := files.stopped
	files.stopped = nil
	files.mu.Unlock()
	defer func() {
		for _, done := range stopped {
			close(done)
		}
	}()

	var withholdErr error
	for _, id := range withhold {
		err := files.withholdNow(id)
		files.mu.Lock()
		if err == nil && files.withhold[id] {
			delete(files.withhold, id)
			files.withheld[id] = true
		}
		files.mu.Unlock()
		withholdErr = errors.Join(withholdErr, err)
	}
	// Logged when it starts failing and when it recovers, not every pass.
	files.mu.Lock()
	failing := files.withholdFailing
	files.withholdFailing = withholdErr != nil
	files.mu.Unlock()
	switch {
	case withholdErr != nil && !failing:
		files.logger.Warn("kubernetes CA files not all withheld", "error_code", "kubernetes_ca_file_error",
			"error", withholdErr)
	case withholdErr == nil && failing:
		files.logger.Info("kubernetes CA files withheld again", "event", "kubernetes_ca_file_withheld")
	}
	if serving == "" {
		return
	}
	manager := files.manager(serving)
	if manager == nil {
		return
	}
	if resume {
		manager.Resume()
	}
	// Core confirms the list only on a live session that negotiated
	// kube.ca1 and does not hold it (review e1a H3): the live state.
	pass.Confirmed = pass.Authoritative && negotiated && files.connected(serving) && !holding(clusters)
	statuses, err := manager.Reconcile(clusters, pass)
	files.report(statuses, err)
	files.mu.Lock()
	if files.serving == serving {
		files.statuses = statuses
		if resume {
			delete(files.withheld, serving)
		}
	}
	files.mu.Unlock()
}

// withholdNow writes the markers of profileID; a profile with no directory
// has nothing to withhold (review e1b L3).
func (files *kubeCAFiles) withholdNow(profileID string) error {
	if _, err := os.Lstat(filepath.Join(files.base, profileID)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	manager := files.manager(profileID)
	if manager == nil {
		return nil
	}
	if err := manager.Withhold(kubecafile.ReasonDisconnected); err != nil {
		return err
	}
	files.logger.Info("kubernetes CA files withheld", "event", "kubernetes_ca_file_withheld")
	return nil
}

// manager returns profileID's manager; run's goroutine only.
func (files *kubeCAFiles) manager(profileID string) *kubecafile.Manager {
	if !validProfileDir(profileID) {
		return nil
	}
	manager, ok := files.managers[profileID]
	if !ok {
		manager = kubecafile.New(profileDirectory{base: files.base, path: filepath.Join(files.base, profileID)},
			files.now)
		_ = manager.Clean()
		files.managers[profileID] = manager
	}
	return manager
}

// report logs what changed since the last pass.
func (files *kubeCAFiles) report(statuses map[string]kubecafile.Status, err error) {
	files.mu.Lock()
	previous, failing := files.statuses, files.failing
	files.failing = err != nil
	files.mu.Unlock()
	switch {
	case err != nil && !failing:
		files.logger.Warn("kubernetes CA files not reconciled", "error_code", "kubernetes_ca_dir_refused",
			"error", err)
	case err == nil && failing:
		files.logger.Info("kubernetes CA files reconciled again", "event", "kubernetes_ca_file_current")
	}
	for id, status := range statuses {
		if before, ok := previous[id]; !ok || before.State != status.State || before.Reason != status.Reason {
			files.logger.Info("kubernetes CA file", "event", "kubernetes_ca_file_"+string(status.State),
				"cluster_id", id, "reason", string(status.Reason))
		}
	}
}

func holding(clusters []networkmap.KubernetesCluster) bool {
	for _, cluster := range clusters {
		if !cluster.HeldUntil.IsZero() {
			return true
		}
	}
	return false
}

// status is a cluster's file as last known for profileID: withheld once
// its markers are written, error while they are not (review e1b H2).
func (files *kubeCAFiles) status(profileID, clusterID string) (kubecafile.Status, bool) {
	if files == nil {
		return kubecafile.Status{}, false
	}
	files.mu.Lock()
	defer files.mu.Unlock()
	path := filepath.Join(files.base, profileID, clusterID+".pem")
	switch {
	case files.withhold[profileID]:
		return kubecafile.Status{Path: path, State: kubecafile.StateError, Reason: kubecafile.ReasonDisconnected}, true
	case files.withheld[profileID] && files.serving != profileID:
		return kubecafile.Status{Path: path, State: kubecafile.StateWithheld, Reason: kubecafile.ReasonDisconnected},
			true
	case profileID != files.serving:
		return kubecafile.Status{}, false
	}
	status, ok := files.statuses[clusterID]
	return status, ok
}

// controlLive reports a live, synchronized control session of profileID.
func (s *Service) controlLive(profileID string) bool {
	status := s.getSyncStatus()
	return status.profileID == profileID && status.state == ControlSessionSynchronized
}

// kubernetesClusterStatus is the clusters of status, as of now, each with
// its CA file.
func (s *Service) kubernetesClusterStatus(status syncStatus) []KubernetesClusterView {
	views := kubernetesClustersAt(status.kubernetesClusters, s.clock())
	for index := range views {
		if file, ok := s.kubeCA.status(status.profileID, views[index].ID); ok {
			views[index].CAFile, views[index].CAFileState = file.Path, string(file.State)
			views[index].CAFileReason = string(file.Reason)
		}
	}
	return views
}
