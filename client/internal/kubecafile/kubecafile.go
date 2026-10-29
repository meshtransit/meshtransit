// Package kubecafile keeps the CA files kubectl trusts for the Kubernetes
// clusters a node may reach (K1e design §3): one file per cluster in the
// profile's directory, holding the roots Core named in the node's map, or a
// marker that is not PEM when no root may be trusted. A file is never empty:
// client-go takes an empty certificate-authority file as no CA at all and
// falls back to the system roots (review v1 C1).
package kubecafile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/privatefile"
)

// Expiry is how long a file's roots stay trusted past the last time Core
// confirmed them, across a restart (K1e design §3.3): a gateway
// certificate's life plus an hour, as the map's own hold (K1a4d §5).
const Expiry = 25 * time.Hour

const (
	manifestName = ".manifest.json"
	markerPrefix = "# MeshTransit: CA withheld ("
	fileSuffix   = ".pem"
	tempInfix    = ".tmp-"
	maxFileSize  = 1 << 20
	maxManifest  = 4 << 20
	// clockSlack is how far ahead of the clock a recorded time may be.
	clockSlack    = 5 * time.Minute
	fileMode      = 0o644
	formatVersion = 1
)

// Reason says why a file holds a marker.
type Reason string

// Marker reasons.
const (
	ReasonDisconnected   Reason = "disconnected"
	ReasonPending        Reason = "pending"
	ReasonInvalid        Reason = "invalid"
	ReasonExpired        Reason = "expired"
	ReasonUnsupportedKey Reason = "unsupported_key"
)

// State is how a cluster's file stands.
type State string

// File states, as the local API reports them.
const (
	// StateCurrent: the file holds the roots the map names now.
	StateCurrent State = "current"
	// StateWithheld: the file holds a marker on purpose.
	StateWithheld State = "withheld"
	// StateStale: Core has not said since meshd started, or holds; the file
	// stays as it was until its roots expire.
	StateStale State = "stale"
	// StateExpired: the roots were not confirmed for Expiry.
	StateExpired State = "expired"
	// StateError: the file could not be checked or written.
	StateError State = "error"
	// StateMissing: no file yet, and Core has not said since meshd started.
	StateMissing State = "missing"
)

// Status is one cluster's file.
type Status struct {
	Path   string
	State  State
	Reason Reason
}

// ErrDirectory reports a directory the files may not live in.
var ErrDirectory = errors.New("kubecafile: directory refused")

// Directory opens the profile's directory after checking it and every
// directory above it (K1e design §3.1).
type Directory interface {
	Path() string
	Open() (*os.Root, error)
}

// Manager reconciles a profile's CA files with the node's map.
type Manager struct {
	dir Directory
	now func() time.Time
	// mu serializes the timer's, the map's and the user's passes (review
	// e1a M2); withheld is the reason of a Withhold not yet resumed.
	mu       sync.Mutex
	withheld Reason
}

// New returns a Manager over dir; now is the wall clock.
func New(dir Directory, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{dir: dir, now: now}
}

// manifest records, per cluster, the file's digest and when Core last
// confirmed its roots (zero for a marker).
type manifest struct {
	Format int                      `json:"format"`
	Files  map[string]manifestEntry `json:"files"`
}

type manifestEntry struct {
	SHA256     string    `json:"sha256"`
	VerifiedAt time.Time `json:"verified_at,omitzero"`
}

// Pass says what the node knows of its clusters when files are reconciled.
type Pass struct {
	// Authoritative: the list is complete, so a file of a cluster missing
	// from it goes (Snapshot.KubernetesClustersAuthoritative).
	Authoritative bool
	// Confirmed: Core confirms the list right now — the control session is
	// up, negotiated kube.ca1 and does not hold (review e1a H3). Only then
	// do the roots' confirmation times move.
	Confirmed bool
}

// Reconcile brings the files in line with clusters (K1e design §3.3). Each
// file is settled on its own: one that fails is reported in error and
// keeps its manifest entry, the others go on, and the manifest is always
// written (review e1a H2). While withheld (Withhold, until Resume) nothing
// is written.
func (manager *Manager) Reconcile(clusters []networkmap.KubernetesCluster, pass Pass) (map[string]Status, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.withheld != "" {
		// Withheld: never roots, but a marker the withhold failed to write
		// is written now (re-review e1a M-1).
		err := manager.withholdAll(manager.withheld)
		statuses := make(map[string]Status, len(clusters))
		for _, cluster := range clusters {
			if validID(cluster.ID) {
				statuses[cluster.ID] = Status{Path: manager.path(cluster.ID + fileSuffix), State: StateWithheld,
					Reason: manager.withheld}
			}
		}
		return statuses, err
	}
	root, err := manager.dir.Open()
	if err != nil {
		return manager.failed(clusters), err
	}
	defer func() { _ = root.Close() }()
	run := reconciliation{root: root, pass: pass, now: manager.now().Round(0),
		next: manifest{Format: formatVersion, Files: map[string]manifestEntry{}}}
	run.recorded = readManifest(root)
	statuses := make(map[string]Status, len(clusters))
	listed := map[string]bool{}
	for _, cluster := range clusters {
		if !validID(cluster.ID) {
			continue
		}
		listed[cluster.ID] = true
		status := run.listed(cluster)
		status.Path = manager.path(cluster.ID + fileSuffix)
		statuses[cluster.ID] = status
	}
	held, err := heldFiles(root)
	if err != nil {
		run.errs = append(run.errs, err)
	}
	for _, id := range held {
		if !listed[id] {
			run.unlisted(id)
		}
	}
	if err := writeManifest(root, run.recorded, run.next); err != nil {
		run.errs = append(run.errs, err)
	}
	return statuses, errors.Join(run.errs...)
}

// reconciliation is one pass over a profile's files.
type reconciliation struct {
	root     *os.Root
	pass     Pass
	now      time.Time
	recorded manifest
	next     manifest
	errs     []error
}

// file reads a cluster's file: nil when it does not exist.
func (run *reconciliation) file(name string) ([]byte, error) {
	content, err := readBounded(run.root, name, maxFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return content, err
}

// trusted reports whether content holds roots Core confirmed within Expiry,
// as the manifest records: a roots file without a matching entry (a crash
// before the manifest, a lost manifest) is not (review e1a H1).
func (run *reconciliation) trusted(id string, content []byte) bool {
	entry, ok := run.recorded.Files[id]
	// A time ahead of the clock (a clock set back) dates nothing (re-review
	// e1a L-2).
	return ok && entry.SHA256 == digest(content) && !entry.VerifiedAt.IsZero() &&
		!run.now.After(entry.VerifiedAt.Add(Expiry)) && !entry.VerifiedAt.After(run.now.Add(clockSlack))
}

// keep carries a file's entry over, or fails the file.
func (run *reconciliation) keep(id string) {
	if entry, ok := run.recorded.Files[id]; ok {
		run.next.Files[id] = entry
	}
}

// fail records a file that could not be settled: it keeps its entry.
func (run *reconciliation) fail(id string, err error) Status {
	run.errs = append(run.errs, err)
	run.keep(id)
	return Status{State: StateError}
}

// withhold writes a marker in a cluster's file.
func (run *reconciliation) withhold(id string, reason Reason) Status {
	content := marker(reason)
	if err := writeIfChanged(run.root, id+fileSuffix, content); err != nil {
		return run.fail(id, err)
	}
	run.next.Files[id] = manifestEntry{SHA256: digest(content)}
	if reason == ReasonExpired {
		return Status{State: StateExpired, Reason: reason}
	}
	return Status{State: StateWithheld, Reason: reason}
}

// listed settles the file of a cluster the list names (K1e §3.3).
func (run *reconciliation) listed(cluster networkmap.KubernetesCluster) Status {
	id := cluster.ID
	current, err := run.file(id + fileSuffix)
	if err != nil {
		return run.fail(id, err)
	}
	holding := !cluster.HeldUntil.IsZero()
	// An expired hold wins over every other reason (re-review H-a).
	if holding && run.now.After(cluster.HeldUntil) || cluster.State == networkmap.KubernetesClusterUnavailable {
		return run.withhold(id, ReasonExpired)
	}
	if !run.pass.Authoritative {
		switch {
		case current == nil:
			return Status{State: StateMissing}
		case IsMarker(current):
			run.keep(id)
			return Status{State: StateWithheld}
		case !run.trusted(id, current):
			return run.withhold(id, ReasonExpired)
		}
		run.keep(id)
		return Status{State: StateStale}
	}
	roots, reason := usableRoots(cluster)
	if reason != "" {
		return run.withhold(id, reason)
	}
	desired := encodeRoots(roots)
	entry := run.recorded.Files[id]
	unchanged := bytes.Equal(current, desired) && run.trusted(id, current)
	// Core does not confirm a list it holds, whatever the caller says
	// (re-review e1a L-1).
	switch confirmed := run.pass.Confirmed && run.pass.Authoritative && !holding; {
	case confirmed:
		// Refreshed at most hourly: expiry only comes earlier (review e1a L1).
		if !unchanged || run.now.Sub(entry.VerifiedAt) >= time.Hour {
			entry.VerifiedAt = run.now
		}
	case unchanged:
	case holding:
		// New roots during a hold count from the hold's start (review e1a M1).
		entry.VerifiedAt = cluster.HeldUntil.Add(-Expiry)
	default:
		// New roots while Core does not confirm (a session without kube.ca1):
		// nothing to date them by.
		return run.withhold(id, ReasonExpired)
	}
	if run.now.After(entry.VerifiedAt.Add(Expiry)) {
		return run.withhold(id, ReasonExpired)
	}
	if err := writeIfChanged(run.root, id+fileSuffix, desired); err != nil {
		return run.fail(id, err)
	}
	entry.SHA256 = digest(desired)
	run.next.Files[id] = entry
	return Status{State: StateCurrent}
}

// unlisted settles a file the list does not name: removed when the list is
// authoritative, else kept until its roots expire.
func (run *reconciliation) unlisted(id string) {
	name := id + fileSuffix
	if run.pass.Authoritative {
		if err := run.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			run.fail(id, fmt.Errorf("removing a CA file: %w", err))
		}
		return
	}
	current, err := run.file(name)
	switch {
	case err != nil:
		run.fail(id, err)
	case current == nil:
	case !IsMarker(current) && !run.trusted(id, current):
		run.withhold(id, ReasonExpired)
	default:
		run.keep(id)
	}
}

// Withhold writes a marker in every CA file of the profile and stops
// Reconcile from writing roots until Resume: meshd stopped serving it (down,
// logout, a profile change, a graceful stop). It goes over every file,
// whatever fails (review e1a H2).
func (manager *Manager) Withhold(reason Reason) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.withheld = reason
	return manager.withholdAll(reason)
}

// withholdAll writes reason's marker in every file that does not hold a
// marker yet; manager.mu is held.
func (manager *Manager) withholdAll(reason Reason) error {
	root, err := manager.dir.Open()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	run := reconciliation{root: root, now: manager.now().Round(0),
		next: manifest{Format: formatVersion, Files: map[string]manifestEntry{}}}
	run.recorded = readManifest(root)
	held, err := heldFiles(root)
	if err != nil {
		return err
	}
	for _, id := range held {
		if current, err := run.file(id + fileSuffix); err == nil && IsMarker(current) {
			run.keep(id)
			continue
		}
		run.withhold(id, reason)
	}
	if err := writeManifest(root, run.recorded, run.next); err != nil {
		run.errs = append(run.errs, err)
	}
	return errors.Join(run.errs...)
}

// Resume lets Reconcile write again: meshd serves the profile with a map it
// took since (review e1a M2).
func (manager *Manager) Resume() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.withheld = ""
}

// Clean removes temporary files an interrupted write left (at start).
func (manager *Manager) Clean() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	root, err := manager.dir.Open()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return fmt.Errorf("listing CA files: %w", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), tempInfix) && entry.Type().IsRegular() {
			if err := root.Remove(entry.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("removing a temporary CA file: %w", err)
			}
		}
	}
	return nil
}

// failed reports every cluster's file in error: nothing was written.
func (manager *Manager) failed(clusters []networkmap.KubernetesCluster) map[string]Status {
	statuses := make(map[string]Status, len(clusters))
	for _, cluster := range clusters {
		if validID(cluster.ID) {
			statuses[cluster.ID] = Status{Path: manager.path(cluster.ID + fileSuffix), State: StateError}
		}
	}
	return statuses
}

func (manager *Manager) path(name string) string {
	return manager.dir.Path() + string(os.PathSeparator) + name
}

// usableRoots are a cluster's roots kubectl may trust, or the reason none
// may be: the map's checks (K1a4d §6) plus a P-256 key (K1e §3.2).
func usableRoots(cluster networkmap.KubernetesCluster) ([][]byte, Reason) {
	switch cluster.State {
	case networkmap.KubernetesClusterTrusted, networkmap.KubernetesClusterIncomplete:
	case networkmap.KubernetesClusterInvalid:
		return nil, ReasonInvalid
	default:
		return nil, ReasonPending
	}
	var roots [][]byte
	for _, der := range cluster.Roots {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if key, ok := certificate.PublicKey.(*ecdsa.PublicKey); ok && key.Curve == elliptic.P256() {
			roots = append(roots, der)
		}
	}
	switch {
	case len(roots) > 0:
		return roots, ""
	case len(cluster.Roots) > 0:
		return nil, ReasonUnsupportedKey
	case cluster.State == networkmap.KubernetesClusterIncomplete:
		return nil, ReasonPending
	}
	return nil, ReasonInvalid
}

func encodeRoots(roots [][]byte) []byte {
	var buffer bytes.Buffer
	for _, der := range roots {
		_ = pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return buffer.Bytes()
}

func marker(reason Reason) []byte { return []byte(markerPrefix + string(reason) + ")\n") }

// IsMarker reports whether content is a marker rather than roots.
func IsMarker(content []byte) bool { return bytes.HasPrefix(content, []byte(markerPrefix)) }

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// writeIfChanged writes content to name unless the file on disk already
// holds it: through a temporary file in the same directory, synced and
// renamed over it, so a reader sees the old or the new file, never part.
func writeIfChanged(root *os.Root, name string, content []byte) error {
	if current, err := readBounded(root, name, maxFileSize); err == nil && bytes.Equal(current, content) {
		return nil
	}
	return writeAtomic(root, name, content)
}

func writeAtomic(root *os.Root, name string, content []byte) (resultErr error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("naming a temporary CA file: %w", err)
	}
	temp := name + tempInfix + hex.EncodeToString(suffix[:])
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("creating a CA file: %w", err)
	}
	defer func() {
		if resultErr != nil {
			_ = root.Remove(temp)
		}
	}()
	_, writeErr := file.Write(content)
	// The service's umask would narrow the mode: readers are other users.
	chmodErr := file.Chmod(fileMode)
	syncErr := file.Sync()
	if err := errors.Join(writeErr, chmodErr, syncErr, file.Close()); err != nil {
		return fmt.Errorf("writing a CA file: %w", err)
	}
	if err := renameRetrying(root, temp, name); err != nil {
		return fmt.Errorf("replacing a CA file: %w", err)
	}
	if err := privatefile.SyncDir(root); err != nil {
		return fmt.Errorf("syncing CA files: %w", err)
	}
	return nil
}

// renameRetrying renames, retrying briefly where a reader holds the target
// open (Windows sharing violations).
func renameRetrying(root *os.Root, from, to string) error {
	var err error
	for attempt := range 8 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 40 * time.Millisecond) // about 1 s in all
		}
		if err = root.Rename(from, to); err == nil || !retryableRename(err) {
			return err
		}
	}
	return err
}

func readBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%w: %s is not a regular file of at most %d bytes", ErrDirectory, name, limit)
	}
	return root.ReadFile(name)
}

// readManifest reads the manifest; one meshd cannot read confirms nothing,
// so every roots file it would have dated expires unless Core confirms it
// (review e1a H1).
func readManifest(root *os.Root) manifest {
	empty := manifest{Format: formatVersion, Files: map[string]manifestEntry{}}
	raw, err := readBounded(root, manifestName, maxManifest)
	if err != nil {
		return empty
	}
	var recorded manifest
	if json.Unmarshal(raw, &recorded) != nil || recorded.Format != formatVersion || recorded.Files == nil {
		return empty
	}
	return recorded
}

func writeManifest(root *os.Root, recorded, next manifest) error {
	if manifestsEqual(recorded, next) {
		if _, err := root.Lstat(manifestName); err == nil || len(next.Files) == 0 {
			return nil
		}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encoding the CA manifest: %w", err)
	}
	return writeIfChanged(root, manifestName, raw)
}

func manifestsEqual(a, b manifest) bool {
	if len(a.Files) != len(b.Files) {
		return false
	}
	for id, entry := range a.Files {
		other, ok := b.Files[id]
		if !ok || other.SHA256 != entry.SHA256 || !other.VerifiedAt.Equal(entry.VerifiedAt) {
			return false
		}
	}
	return true
}

// heldFiles lists the cluster IDs with a CA file in the directory; files
// that are not named by a cluster ID are left alone.
func heldFiles(root *os.Root) ([]string, error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("listing CA files: %w", err)
	}
	var ids []string
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), fileSuffix)
		if ok && validID(id) && entry.Type().IsRegular() {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// validID accepts a canonical lowercase UUID: the only file names written.
func validID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range []byte(value) {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}
