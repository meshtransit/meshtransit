package kubeconfig

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func entry(group string) Entry {
	name := "mt-acme-prod"
	if group != "" {
		name += "-" + group
	}
	server := "https://prod.kube.acme.mesh.internal"
	if group != "" {
		server += "/mt/g/" + group
	}
	return Entry{Name: name, Server: server, TLSServerName: "prod.k8s.example", CAFile: "/var/lib/meshtransit/kube/p/c.pem",
		Marker: Marker{ProfileID: "0a0a", ClusterID: "01890f90-0000-7000-8000-0000000000a1", Group: group}}
}

func readConfig(t *testing.T, file string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(file) //nolint:gosec // The test's own file.
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func names(config map[string]any, list string) []string {
	var out []string
	items, _ := config[list].([]any)
	for _, item := range items {
		out = append(out, item.(map[string]any)["name"].(string))
	}
	return out
}

func TestLoginCreatesAndKeepsOthers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, ".kube", "config")
	if _, err := Login([]string{file}, entry(""), true, false); err != nil {
		t.Fatal(err)
	}
	config := readConfig(t, file)
	if got := names(config, "contexts"); len(got) != 1 || got[0] != "mt-acme-prod" || config["current-context"] != "mt-acme-prod" {
		t.Fatalf("new file: %v", config)
	}
	// Windows keeps no Unix mode: the profile's ACL guards the file.
	if info, err := os.Stat(file); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", info.Mode(), err)
	}
	cluster := config["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
	if cluster["certificate-authority"] != "/var/lib/meshtransit/kube/p/c.pem" || cluster["tls-server-name"] != "prod.k8s.example" {
		t.Fatalf("cluster %v", cluster)
	}
	if strings.Contains(string(must(os.ReadFile(file))), "token") { //nolint:gosec // The test's own file.
		t.Fatal("a credential was written")
	}
	// A group's entry is its own (review v1 H4): the plain one stays.
	if _, err := Login([]string{file}, entry("sre"), false, false); err != nil {
		t.Fatal(err)
	}
	config = readConfig(t, file)
	if got := names(config, "clusters"); len(got) != 2 || config["current-context"] != "mt-acme-prod" {
		t.Fatalf("with a group: %v", config)
	}
	plain := config["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
	if plain["server"] != "https://prod.kube.acme.mesh.internal" {
		t.Fatalf("the group's login changed the plain cluster: %v", plain)
	}
}

func TestLoginRefusesWhatIsNotItsOwn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "config")
	original := "apiVersion: v1\r\nkind: Config\r\n# a comment kept\r\nclusters:\r\n- name: mt-acme-prod\r\n  cluster:\r\n" +
		"    server: https://elsewhere\r\ncontexts: []\r\nusers: []\r\ncurrent-context: \"\"\r\npreferences:\r\n  colors: true\r\n"
	if err := os.WriteFile(file, append([]byte{0xef, 0xbb, 0xbf}, original...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login([]string{file}, entry(""), false, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("an entry of the same name, not meshctl's: %v", err)
	}
	if _, err := Login([]string{file}, entry(""), false, true); err != nil {
		t.Fatalf("--force: %v", err)
	}
	raw := must(os.ReadFile(file)) //nolint:gosec // The test's own file.
	if !strings.HasPrefix(string(raw), "\xef\xbb\xbf") || !strings.Contains(string(raw), "\r\n") ||
		!strings.Contains(string(raw), "colors: true") || !strings.Contains(string(raw), "# a comment kept") {
		t.Fatalf("lost the BOM, CRLF, a field or a comment: %q", raw)
	}
	if err := os.WriteFile(file, []byte(`{"apiVersion":"v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login([]string{file}, entry(""), false, false); !errors.Is(err, ErrJSON) {
		t.Fatalf("JSON: %v", err)
	}
}

// Files are chosen as client-go chooses them.
func TestLoginChoosesTheFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, second, third := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	if err := os.WriteFile(second, []byte("apiVersion: v1\nkind: Config\ncurrent-context: other\ncontexts:\n- name: other\n"+
		"  context: {cluster: x, user: y}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := Files("", strings.Join([]string{first, second, third}, string(os.PathListSeparator)), dir)
	result, err := Login(files, entry(""), true, false)
	if err != nil || result.File != second {
		t.Fatalf("new entries go to the first file that exists: %+v, %v", result, err)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatal("a file that did not exist was created")
	}
	if readConfig(t, second)["current-context"] != "mt-acme-prod" {
		t.Fatal("current-context not set in the file that set it")
	}
	// A same-named entry in an earlier file shadows ours.
	if err := os.WriteFile(first, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: mt-acme-prod\n  cluster: {server: x}\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login(files, entry(""), false, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("an earlier unmanaged entry of the name: %v", err)
	}
	if result, err := Login(files, entry(""), false, true); err != nil || len(result.Shadowed) != 1 ||
		result.Shadowed[0] != first || result.File != second {
		t.Fatalf("shadowed: %+v, %v", result, err)
	}
	if got := Files("", "", dir); len(got) != 1 || got[0] != filepath.Join(dir, ".kube", "config") {
		t.Fatalf("default: %v", got)
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "config")
	for _, group := range []string{"", "sre"} {
		if _, err := Login([]string{file}, entry(group), group == "", false); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := Logout([]string{file}, func(marker Marker) bool { return marker.Group == "" })
	if err != nil || removed != 1 {
		t.Fatalf("Logout() = %d, %v", removed, err)
	}
	config := readConfig(t, file)
	if config["current-context"] != "" || len(names(config, "contexts")) != 1 || len(names(config, "users")) != 1 {
		t.Fatalf("after one: %v", config)
	}
	if removed, err = Logout([]string{file}, func(Marker) bool { return true }); err != nil || removed != 1 {
		t.Fatalf("Logout(all) = %d, %v", removed, err)
	}
	if config = readConfig(t, file); len(names(config, "users")) != 0 {
		t.Fatalf("mt-none outlived its contexts: %v", config)
	}
}

func TestLoginWaitsForTheLock(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(file+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := LockWait
	LockWait = 100 * time.Millisecond
	defer func() { LockWait = previous }()
	if _, err := Login([]string{file}, entry(""), false, false); !errors.Is(err, ErrLocked) {
		t.Fatalf("a held lock: %v", err)
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// Two clusters, groups or profiles never share an entry (review e2 H1); a
// rename moves the current context (M1).
func TestLoginNameCollisionsAndRenames(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "config")
	first := entry("")
	if _, err := Login([]string{file}, first, true, false); err != nil {
		t.Fatal(err)
	}
	other := first
	other.Marker.ClusterID = "01890f90-0000-7000-8000-0000000000b2"
	if _, err := Login([]string{file}, other, false, false); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("another cluster under the same name: %v", err)
	}
	otherProfile := first
	otherProfile.Marker.ProfileID = "0b0b"
	if _, err := Login([]string{file}, otherProfile, false, true); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("another profile's cluster, even with force: %v", err)
	}
	renamed := first
	renamed.Name = "mt-acme2-prod"
	if _, err := Login([]string{file}, renamed, false, false); err != nil {
		t.Fatal(err)
	}
	config := readConfig(t, file)
	if config["current-context"] != "mt-acme2-prod" || len(names(config, "contexts")) != 1 {
		t.Fatalf("after a rename: %v", config)
	}
}

func TestLoginKeepsTheDocumentAndRefusesCredentials(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	commented := filepath.Join(dir, "commented")
	if err := os.WriteFile(commented, []byte("# top of file comment\n\napiVersion: v1\nkind: Config\nclusters: null\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login([]string{commented}, entry(""), false, false); err != nil {
		t.Fatal(err)
	}
	if raw := must(os.ReadFile(commented)); !strings.Contains(string(raw), "# top of file comment") { //nolint:gosec // The test's own file.
		t.Fatalf("lost the top comment: %s", raw)
	}
	onlyComments := filepath.Join(dir, "comments-only")
	if err := os.WriteFile(onlyComments, []byte("# nothing yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login([]string{onlyComments}, entry(""), false, false); err != nil {
		t.Fatalf("a comment-only file: %v", err)
	}
	notAList := filepath.Join(dir, "not-a-list")
	if err := os.WriteFile(notAList, []byte("apiVersion: v1\nclusters: {a: b}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login([]string{notAList}, entry(""), false, false); err == nil {
		t.Fatal("clusters that are not a list were replaced")
	}
	credential := filepath.Join(dir, "credential")
	if err := os.WriteFile(credential, []byte("apiVersion: v1\nusers:\n- name: mt-none\n  user: {token: x}\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login([]string{credential}, entry(""), false, false); !errors.Is(err, ErrCredential) {
		t.Fatalf("a mt-none carrying a credential: %v", err)
	}
	aliased := filepath.Join(dir, "aliased")
	if err := os.WriteFile(aliased, []byte("apiVersion: v1\nusers:\n- name: real\n  user: &cred {token: x}\n"+
		"- name: mt-none\n  user: *cred\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Login([]string{aliased}, entry(""), false, false); !errors.Is(err, ErrCredential) {
		t.Fatalf("a mt-none carrying a credential through an alias: %v", err)
	}
	// JSON in KUBECONFIG is read past; only writing to it is refused.
	jsonFile := filepath.Join(dir, "eks.json")
	if err := os.WriteFile(jsonFile, []byte(`{"apiVersion":"v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := Login([]string{commented, jsonFile}, entry(""), false, false); err != nil || result.File != commented {
		t.Fatalf("a JSON file later in the list: %+v, %v", result, err)
	}
}

// A writer that ignores the lock changes the file under meshctl: meshctl
// reads it again and keeps the other writer's change.
func TestLoginRetriesWhenTheFileChanges(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(file, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := false
	beforeRename = func(path string) {
		if !changed {
			changed = true
			_ = os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\npreferences: {colors: true}\n"), 0o600)
		}
	}
	defer func() { beforeRename = func(string) {} }()
	if _, err := Login([]string{file}, entry(""), false, false); err != nil {
		t.Fatal(err)
	}
	if raw := must(os.ReadFile(file)); !strings.Contains(string(raw), "colors: true") || //nolint:gosec // The test's own file.
		!strings.Contains(string(raw), "mt-acme-prod") {
		t.Fatalf("lost a change or ours: %s", raw)
	}
}

// Find reports a context kubectl would not use as written (review e3 M5).
func TestFind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	earlier, ours := filepath.Join(dir, "earlier"), filepath.Join(dir, "ours")
	if _, err := Login([]string{ours}, entry(""), false, false); err != nil {
		t.Fatal(err)
	}
	found, err := Find([]string{earlier, ours, ours}, entry("").Marker.ClusterID)
	if err != nil || len(found) != 1 || found[0].Server != entry("").Server || found[0].ShadowedBy != "" ||
		found[0].ClusterMissing {
		t.Fatalf("Find() = %+v, %v", found, err)
	}
	if err := os.WriteFile(earlier, []byte("apiVersion: v1\ncontexts:\n- name: mt-acme-prod\n  context: {cluster: x, user: y}\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	if found, err = Find([]string{earlier, ours}, entry("").Marker.ClusterID); err != nil || len(found) != 1 ||
		found[0].ShadowedBy != earlier {
		t.Fatalf("shadowed: %+v, %v", found, err)
	}
	raw := strings.Replace(string(must(os.ReadFile(ours))), "- name: mt-acme-prod\n    cluster:", //nolint:gosec // The test's own file.
		"- name: renamed\n    cluster:", 1)
	if err := os.WriteFile(ours, []byte(raw), 0o600); err != nil { //nolint:gosec // G703: the test's own file.
		t.Fatal(err)
	}
	if found, err = Find([]string{ours}, entry("").Marker.ClusterID); err != nil || len(found) != 1 ||
		!found[0].ClusterMissing {
		t.Fatalf("missing cluster: %+v, %v\n%s", found, err, raw)
	}
}
