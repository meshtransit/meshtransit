// Package kubeconfig adds and removes the kubeconfig entries meshctl
// manages (K1e design §4): a cluster and a context per cluster and group,
// marked with an extension, and the user mt-none, which holds only a
// placeholder token. It edits files the way client-go chooses them, keeps
// every other entry, field, comment and the order, and never writes a
// credential.
package kubeconfig

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// ExtensionName marks the entries meshctl manages.
	ExtensionName = "meshtransit.net/managed"
	// NoUser is the user the contexts name: no credential, the gateway
	// knows the Device by its WireGuard key.
	NoUser = "mt-none"
	// PlaceholderToken is all NoUser holds: client-go asks for a username
	// when a user has nothing (K1b Q78). It is no secret and grants
	// nothing: the gateway drops Authorization, an API server refuses it.
	PlaceholderToken = "meshtransit-mesh-identity"

	maxFileSize = 4 << 20
	lockStale   = time.Minute
)

// LockWait bounds how long a write waits for another writer's lock.
var LockWait = 5 * time.Second

// beforeRename runs between the re-read check and the rename (tests).
var beforeRename = func(string) {}

var (
	// ErrJSON reports a kubeconfig written as JSON: meshctl edits YAML only.
	ErrJSON = errors.New("kubeconfig: the file is JSON; convert it to YAML (kubectl config view --flatten)")
	// ErrConflict reports an entry of the same name meshctl does not manage.
	ErrConflict = errors.New("kubeconfig: an entry of that name is not meshctl's (use --force to replace it)")
	// ErrNameTaken reports a name another managed entry holds: another
	// cluster, group or profile (review e2 H1).
	ErrNameTaken = errors.New("kubeconfig: another cluster's entry has that name")
	// ErrCredential reports a user mt-none that carries a credential.
	ErrCredential = errors.New("kubeconfig: a user named mt-none carries a credential; remove it")

	// ErrLocked reports a lock another writer holds.
	ErrLocked = errors.New("kubeconfig: locked by another writer")
	// ErrUnsafe reports a file meshctl must not write: another user's, or a
	// link while running as root.
	ErrUnsafe = errors.New("kubeconfig: not a file this user may write")
	// ErrChanged reports a file that kept changing under meshctl.
	ErrChanged = errors.New("kubeconfig: the file changed while meshctl wrote it; try again")
)

// Marker identifies a managed entry.
type Marker struct {
	ProfileID string `yaml:"profile_id"`
	ClusterID string `yaml:"cluster_id"`
	Group     string `yaml:"group,omitempty"`
}

// Entry is a cluster and context to write.
type Entry struct {
	Name          string
	Server        string
	TLSServerName string
	CAFile        string
	Marker        Marker
}

// Result says where Login wrote, and which earlier files hold entries of
// the same name that kubectl would use instead.
type Result struct {
	File     string
	Shadowed []string
}

// Files lists the kubeconfig files to consider, as client-go does: the
// explicit one, else KUBECONFIG split by the OS list separator, else the
// default under home.
func Files(explicit, env, home string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	var files []string
	seen := map[string]bool{}
	for _, file := range filepath.SplitList(env) {
		if file != "" && !seen[file] {
			seen[file] = true
			files = append(files, file)
		}
	}
	if len(files) > 0 {
		return files
	}
	return []string{filepath.Join(home, ".kube", "config")}
}

// Login writes entry: into the file that holds it already, else the first
// file that exists, else the last; with use, sets the current context in
// the first file that sets one, else the same file. A name another entry
// holds, in any file, is refused: ErrNameTaken for a managed one,
// ErrConflict for one meshctl did not write unless force.
func Login(files []string, entry Entry, use, force bool) (Result, error) {
	if len(files) == 0 || entry.Name == "" {
		return Result{}, errors.New("kubeconfig: nothing to write")
	}
	documents, err := readAll(files)
	if err != nil {
		return Result{}, err
	}
	target := -1
	var oldNames []string
	for index, document := range documents {
		if document == nil || document.json {
			continue
		}
		for _, list := range []string{"clusters", "contexts"} {
			if found := document.findManaged(list, entry.Marker); found != nil {
				if target < 0 {
					target = index
				}
				if name := nameOf(found); name != entry.Name {
					oldNames = append(oldNames, name)
				}
			}
		}
	}
	if target < 0 {
		target = firstExisting(documents, len(files)-1)
	}
	result := Result{File: files[target]}
	for index, document := range documents {
		if document == nil {
			continue
		}
		if err := document.nameFree(entry.Name, entry.Marker, force); err != nil {
			return Result{}, fmt.Errorf("%s: %w", files[index], err) //nolint:gosec // G602: documents is files'.
		}
		if err := document.noUserCredential(); err != nil {
			return Result{}, fmt.Errorf("%s: %w", files[index], err) //nolint:gosec // G602: documents is files'.
		}
		if index < target && document.holdsName(entry.Name) {
			result.Shadowed = append(result.Shadowed, files[index]) //nolint:gosec // G602: documents is files'.
		}
	}
	if err := edit(files[target], func(document *config) error {
		return document.upsert(entry, force)
	}); err != nil {
		return Result{}, err
	}
	// A rename (Network or cluster) moves the current context with it
	// (review e2 M1).
	for index, document := range documents {
		if document == nil || document.json || !contains(oldNames, document.currentContext()) {
			continue
		}
		if err := edit(files[index], func(document *config) error { //nolint:gosec // G602: documents is files'.
			// Still an old name under the lock (re-review e2 L4).
			if contains(oldNames, document.currentContext()) {
				document.setCurrentContext(entry.Name)
			}
			return nil
		}); err != nil {
			return result, err
		}
	}
	if use {
		current := target
		for index, document := range documents {
			if document != nil && document.currentContext() != "" {
				current = index // a JSON file here is refused when written
				break
			}
		}
		if err := edit(files[current], func(document *config) error {
			document.setCurrentContext(entry.Name)
			return nil
		}); err != nil {
			return result, err
		}
	}
	return result, nil
}

// Logout removes the managed entries match selects from every file, and
// the current context where it names one; mt-none goes once no context
// names it. It returns how many contexts went.
func Logout(files []string, match func(Marker) bool) (int, error) {
	documents, err := readAll(files)
	if err != nil {
		return 0, err
	}
	total := 0
	for index, document := range documents {
		if document == nil || document.json || !document.managesAny(match) {
			continue
		}
		removed := 0
		err := edit(files[index], func(document *config) error { //nolint:gosec // G602: documents is files'.
			removed = document.remove(match)
			return nil
		})
		if err != nil {
			return total, err
		}
		total += removed
	}
	return total, nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func firstExisting(documents []*config, fallback int) int {
	for index, document := range documents {
		if document != nil {
			return index
		}
	}
	return fallback
}

// readAll reads each file that exists; nil for one that does not. A JSON
// file is only refused when written to (review e2 L3).
func readAll(files []string) ([]*config, error) {
	documents := make([]*config, len(files))
	for index, file := range files {
		raw, err := readFile(file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		document, err := parse(raw)
		if errors.Is(err, ErrJSON) {
			// Read as YAML, a JSON superset: its names and current context
			// count; only writing it is refused (re-review e2 L3).
			document, err = parseYAML(raw)
			if document != nil {
				document.json = true
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		documents[index] = document
	}
	return documents, nil
}

func readFile(file string) ([]byte, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return nil, fmt.Errorf("%w: %s is not a regular file of at most 4 MiB", ErrUnsafe, file)
	}
	return os.ReadFile(file) //nolint:gosec // The user's own kubeconfig, chosen as kubectl chooses it.
}

// edit applies change to file under its lock: read, change, write through
// a temporary file renamed over it, after checking that nobody changed the
// file meanwhile (writers that ignore the lock), retrying a few times. The
// lock is taken on the path as given, as client-go does; a link is written
// through to its target (review e2 L4).
func edit(file string, change func(*config) error) error {
	path, err := writablePath(file)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	unlock, err := lock(file)
	if err != nil {
		return err
	}
	defer unlock()
	for range 3 {
		before, readErr := os.ReadFile(path) //nolint:gosec // As readFile.
		if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
			return readErr
		}
		document, err := parse(before)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := change(document); err != nil {
			return err
		}
		after, err := document.encode()
		if err != nil {
			return err
		}
		written, err := write(path, before, after, readErr == nil)
		if err != nil {
			return err
		}
		if written {
			return nil
		}
	}
	return ErrChanged
}

// write replaces path with content unless it changed since before was
// read; it reports whether it wrote.
func write(path string, before, content []byte, existed bool) (bool, error) {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	temp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	_, writeErr := temp.Write(content)
	chmodErr := temp.Chmod(mode)
	syncErr := temp.Sync()
	if err := errors.Join(writeErr, chmodErr, syncErr, temp.Close()); err != nil {
		return false, err
	}
	beforeRename(path)
	// The directory checked first may have been swapped since, for a
	// junction or link elsewhere: check it again before the rename
	// (review TD-CLI-87 M1).
	if err := ownedByUser(filepath.Dir(path)); err != nil {
		return false, err
	}
	now, err := os.ReadFile(path) //nolint:gosec // As readFile.
	switch {
	case errors.Is(err, fs.ErrNotExist) && !existed:
	case err != nil:
		return false, err
	case sha256.Sum256(now) != sha256.Sum256(before):
		return false, nil
	}
	if err := renameRetrying(temp.Name(), path); err != nil {
		return false, err
	}
	return true, nil
}

func renameRetrying(from, to string) error {
	var err error
	for attempt := range 8 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 40 * time.Millisecond)
		}
		if err = os.Rename(from, to); err == nil || !retryableRename(err) {
			return err
		}
	}
	return err
}

// lock takes <path>.lock as client-go does; a lock older than lockStale is
// reported, never removed: its writer may still run.
func lock(path string) (func(), error) {
	name := path + ".lock"
	deadline := time.Now().Add(LockWait)
	for {
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // Next to the file.
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(name) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			if info, statErr := os.Stat(name); statErr == nil && time.Since(info.ModTime()) > lockStale {
				return nil, fmt.Errorf("%w: %s is over a minute old; remove it if no kubectl or meshctl runs",
					ErrLocked, name)
			}
			return nil, fmt.Errorf("%w: %s", ErrLocked, name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// config is a parsed kubeconfig: its document (comments around the root
// included, review e2 M2), its root mapping, and the BOM and line ending
// it came with; json marks a file meshctl reads past but never writes.
type config struct {
	doc  *yaml.Node
	root *yaml.Node
	bom  bool
	crlf bool
	json bool
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

func parse(raw []byte) (*config, error) {
	document := &config{}
	if bytes.HasPrefix(raw, utf8BOM) {
		document.bom, raw = true, raw[len(utf8BOM):]
	}
	document.crlf = bytes.Contains(raw, []byte("\r\n"))
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, ErrJSON
	}
	return parseYAMLInto(document, raw)
}

// parseYAML parses raw without the JSON refusal.
func parseYAML(raw []byte) (*config, error) {
	document := &config{}
	if bytes.HasPrefix(raw, utf8BOM) {
		document.bom, raw = true, raw[len(utf8BOM):]
	}
	return parseYAMLInto(document, raw)
}

func parseYAMLInto(document *config, raw []byte) (*config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var node yaml.Node
	err := decoder.Decode(&node)
	switch {
	case errors.Is(err, io.EOF):
		// Empty, or comments only: a new kubeconfig (review e2 L3).
		document.doc = &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{newConfig()}}
		document.root = document.doc.Content[0]
		return document, nil
	case err != nil:
		return nil, fmt.Errorf("reading the kubeconfig: %w", err)
	}
	for {
		var extra yaml.Node
		err := decoder.Decode(&extra)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(extra.Content) != 0 {
			return nil, errors.New("kubeconfig: more than one YAML document")
		}
	}
	if node.Kind != yaml.DocumentNode || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("kubeconfig: not a mapping")
	}
	document.doc, document.root = &node, node.Content[0]
	// A list that is something else would lose its entries (review e2 L8).
	for _, key := range []string{"clusters", "contexts", "users"} {
		value := get(document.root, key)
		if value != nil && value.Kind != yaml.SequenceNode && value.Tag != "!!null" {
			return nil, fmt.Errorf("kubeconfig: %s is not a list", key)
		}
	}
	return document, nil
}

func newConfig() *yaml.Node {
	root := &yaml.Node{Kind: yaml.MappingNode}
	set(root, "apiVersion", scalar("v1"))
	set(root, "kind", scalar("Config"))
	for _, key := range []string{"clusters", "contexts", "users"} {
		set(root, key, &yaml.Node{Kind: yaml.SequenceNode})
	}
	set(root, "current-context", scalar(""))
	return root
}

func (document *config) encode() ([]byte, error) {
	if document.json {
		return nil, ErrJSON
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(document.doc); err != nil {
		return nil, fmt.Errorf("writing the kubeconfig: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	out := buffer.Bytes()
	if document.crlf {
		out = bytes.ReplaceAll(out, []byte("\n"), []byte("\r\n"))
	}
	if document.bom {
		out = append(append([]byte{}, utf8BOM...), out...)
	}
	return out, nil
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// get returns key's value in mapping, nil without it.
func get(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

// set replaces key's value in mapping, appending it when missing.
func set(mapping *yaml.Node, key string, value *yaml.Node) {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			mapping.Content[index+1] = value
			return
		}
	}
	mapping.Content = append(mapping.Content, scalar(key), value)
}

// list returns the sequence under key; a missing or null one becomes empty
// (parse refused anything else).
func (document *config) list(key string) *yaml.Node {
	node := get(document.root, key)
	if node == nil || node.Kind != yaml.SequenceNode {
		node = &yaml.Node{Kind: yaml.SequenceNode}
		set(document.root, key, node)
	}
	return node
}

func nameOf(entry *yaml.Node) string {
	if name := get(entry, "name"); name != nil {
		return name.Value
	}
	return ""
}

// itemKey is the key holding an entry's body in each list.
var itemKey = map[string]string{"clusters": "cluster", "contexts": "context", "users": "user"}

// markerOf reads an entry's managed marker; false without one.
func markerOf(entry *yaml.Node, list string) (Marker, bool) {
	extensions := get(get(entry, itemKey[list]), "extensions")
	if extensions == nil || extensions.Kind != yaml.SequenceNode {
		return Marker{}, false
	}
	for _, extension := range extensions.Content {
		if name := get(extension, "name"); name != nil && name.Value == ExtensionName {
			var marker Marker
			value := get(extension, "extension")
			if value == nil || value.Decode(&marker) != nil || marker.ClusterID == "" {
				return Marker{}, false
			}
			return marker, true
		}
	}
	return Marker{}, false
}

func (document *config) findManaged(list string, marker Marker) *yaml.Node {
	for _, entry := range document.list(list).Content {
		if found, ok := markerOf(entry, list); ok && found == marker {
			return entry
		}
	}
	return nil
}

func (document *config) findName(list, name string) *yaml.Node {
	for _, entry := range document.list(list).Content {
		if nameOf(entry) == name {
			return entry
		}
	}
	return nil
}

func (document *config) holdsName(name string) bool {
	return document.findName("clusters", name) != nil || document.findName("contexts", name) != nil
}

// nameFree refuses name when another entry holds it: one another marker
// manages (ErrNameTaken), or one meshctl did not write (ErrConflict,
// unless force).
func (document *config) nameFree(name string, marker Marker, force bool) error {
	for _, list := range []string{"clusters", "contexts"} {
		entry := document.findName(list, name)
		if entry == nil {
			continue
		}
		found, managed := markerOf(entry, list)
		switch {
		case managed && found == marker:
		case managed:
			return fmt.Errorf("%w: %s %q", ErrNameTaken, list, name)
		case !force:
			return fmt.Errorf("%w: %s %q", ErrConflict, list, name)
		}
	}
	return nil
}

// noUserCredential refuses a user mt-none that holds more than the
// placeholder: kubectl would send what it carries to the gateway (review
// e2 L5).
func (document *config) noUserCredential() error {
	user := document.findName("users", NoUser)
	if user == nil {
		return nil
	}
	// A key given twice: meshctl reads the first, client-go the last (re-review L1).
	if keyCount(user, "user") > 1 || keyCount(user, "name") > 1 {
		return ErrCredential
	}
	if body := get(user, "user"); !emptyUser(body) && !placeholderUser(body) {
		return ErrCredential
	}
	return nil
}

// keyCount counts key in mapping.
func keyCount(mapping *yaml.Node, key string) int {
	count := 0
	for index := 0; mapping != nil && mapping.Kind == yaml.MappingNode && index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			count++
		}
	}
	return count
}

// placeholderUser reports a user body that holds the placeholder token and
// nothing else.
func placeholderUser(body *yaml.Node) bool {
	if body == nil || body.Kind != yaml.MappingNode || len(body.Content) != 2 {
		return false
	}
	key, value := body.Content[0], body.Content[1]
	return key.Kind == yaml.ScalarNode && key.Value == "token" &&
		value.Kind == yaml.ScalarNode && value.Tag == "!!str" && value.Value == PlaceholderToken
}

func placeholderBody() *yaml.Node {
	body := &yaml.Node{Kind: yaml.MappingNode}
	set(body, "token", scalar(PlaceholderToken))
	return body
}

// emptyUser reports a user body with nothing in it: missing, null, or an
// empty mapping; an alias kubectl would expand is not (re-review e2 L2).
func emptyUser(body *yaml.Node) bool {
	return body == nil || body.Kind == yaml.ScalarNode && body.Tag == "!!null" ||
		body.Kind == yaml.MappingNode && len(body.Content) == 0
}

func (document *config) currentContext() string {
	if node := get(document.root, "current-context"); node != nil {
		return node.Value
	}
	return ""
}

func (document *config) setCurrentContext(name string) {
	set(document.root, "current-context", scalar(name))
}

func markerNode(marker Marker) (*yaml.Node, error) {
	var value yaml.Node
	if err := value.Encode(marker); err != nil {
		return nil, err
	}
	extension := &yaml.Node{Kind: yaml.MappingNode}
	set(extension, "name", scalar(ExtensionName))
	set(extension, "extension", &value)
	return &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{extension}}, nil
}

// upsert writes entry's cluster and context and the user mt-none: the
// entries the marker names, renamed if need be, else new ones. A name
// another entry holds is checked again here, under the lock.
func (document *config) upsert(entry Entry, force bool) error {
	if err := document.nameFree(entry.Name, entry.Marker, force); err != nil {
		return err
	}
	if err := document.noUserCredential(); err != nil {
		return err
	}
	extensions, err := markerNode(entry.Marker)
	if err != nil {
		return err
	}
	cluster := &yaml.Node{Kind: yaml.MappingNode}
	set(cluster, "server", scalar(entry.Server))
	if entry.TLSServerName != "" {
		set(cluster, "tls-server-name", scalar(entry.TLSServerName))
	}
	set(cluster, "certificate-authority", scalar(entry.CAFile))
	set(cluster, "extensions", extensions)
	contextExtensions, err := markerNode(entry.Marker)
	if err != nil {
		return err
	}
	context := &yaml.Node{Kind: yaml.MappingNode}
	set(context, "cluster", scalar(entry.Name))
	set(context, "user", scalar(NoUser))
	set(context, "extensions", contextExtensions)
	for _, item := range []struct {
		list string
		body *yaml.Node
	}{{"clusters", cluster}, {"contexts", context}} {
		existing := document.findManaged(item.list, entry.Marker)
		if existing == nil {
			existing = document.findName(item.list, entry.Name) // unmanaged, with force
		}
		if existing == nil {
			existing = &yaml.Node{Kind: yaml.MappingNode}
			list := document.list(item.list)
			list.Content = append(list.Content, existing)
		}
		set(existing, "name", scalar(entry.Name))
		set(existing, itemKey[item.list], item.body)
	}
	// An empty mt-none, as meshctl wrote before the placeholder, gets it:
	// kubectl would ask for a username (e5).
	if user := document.findName("users", NoUser); user == nil {
		user = &yaml.Node{Kind: yaml.MappingNode}
		set(user, "name", scalar(NoUser))
		set(user, "user", placeholderBody())
		list := document.list("users")
		list.Content = append(list.Content, user)
	} else if emptyUser(get(user, "user")) {
		set(user, "user", placeholderBody())
	}
	return nil
}

func (document *config) managesAny(match func(Marker) bool) bool {
	for _, list := range []string{"clusters", "contexts"} {
		for _, entry := range document.list(list).Content {
			if marker, ok := markerOf(entry, list); ok && match(marker) {
				return true
			}
		}
	}
	return false
}

// remove drops the managed entries match selects and returns how many
// contexts went.
func (document *config) remove(match func(Marker) bool) int {
	removed := 0
	var names []string
	for _, list := range []string{"clusters", "contexts"} {
		sequence := document.list(list)
		kept := sequence.Content[:0]
		for _, entry := range sequence.Content {
			if marker, ok := markerOf(entry, list); ok && match(marker) {
				if list == "contexts" {
					removed++
					names = append(names, nameOf(entry))
				}
				continue
			}
			kept = append(kept, entry)
		}
		sequence.Content = kept
	}
	if contains(names, document.currentContext()) {
		document.setCurrentContext("")
	}
	for _, entry := range document.list("contexts").Content {
		if user := get(get(entry, "context"), "user"); user != nil && user.Value == NoUser {
			return removed
		}
	}
	users := document.list("users")
	kept := users.Content[:0]
	for _, entry := range users.Content {
		body := get(entry, "user")
		if nameOf(entry) != NoUser || !emptyUser(body) && !placeholderUser(body) {
			kept = append(kept, entry)
		}
	}
	users.Content = kept
	return removed
}

// writablePath is the file to write: a link is followed to its target,
// except as root (refused: a user's link would make root write anywhere);
// the file and its directory must belong to this user.
func writablePath(file string) (string, error) {
	if isRoot() {
		return "", fmt.Errorf("%w: run meshctl kube as the user whose kubeconfig it is, not root", ErrUnsafe)
	}
	path := file
	if resolved, err := filepath.EvalSymlinks(file); err == nil {
		path = resolved
	}
	if !filepath.IsAbs(path) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		path = absolute
	}
	for _, check := range []string{path, filepath.Dir(path)} {
		if err := ownedByUser(check); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return path, nil
}

// Found is a managed context as a kubeconfig holds it: its cluster's
// server, CA file and proxy, whether that cluster entry is missing, and
// the earlier file whose entry of the same name kubectl uses instead.
type Found struct {
	File, Name, Server, CAFile, ProxyURL string
	Marker                               Marker
	ClusterMissing                       bool
	ShadowedBy                           string
}

// Find lists the managed contexts of clusterID in every file that holds
// one; a file named twice is read once.
func Find(files []string, clusterID string) ([]Found, error) {
	documents, err := readAll(files)
	if err != nil {
		return nil, err
	}
	var found []Found
	seen := map[string]bool{}
	for index, document := range documents {
		if document == nil {
			continue
		}
		file := files[index] //nolint:gosec // G602: documents is files'.
		if resolved, err := filepath.EvalSymlinks(file); err == nil {
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
		}
		for _, entry := range document.list("contexts").Content {
			marker, ok := markerOf(entry, "contexts")
			if !ok || marker.ClusterID != clusterID {
				continue
			}
			context := Found{File: file, Name: nameOf(entry), Marker: marker}
			clusterName := scalarValue(get(get(entry, "context"), "cluster"))
			if cluster := document.findName("clusters", clusterName); cluster != nil {
				body := get(cluster, "cluster")
				context.Server = scalarValue(get(body, "server"))
				context.CAFile = scalarValue(get(body, "certificate-authority"))
				context.ProxyURL = scalarValue(get(body, "proxy-url"))
			} else {
				context.ClusterMissing = true
			}
			// client-go merges first file wins (review e3 M5).
			for earlier := range index {
				if documents[earlier] != nil && (documents[earlier].findName("contexts", context.Name) != nil ||
					documents[earlier].findName("clusters", clusterName) != nil) {
					context.ShadowedBy = files[earlier]
					break
				}
			}
			found = append(found, context)
		}
	}
	return found, nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}
