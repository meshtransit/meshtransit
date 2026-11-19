package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	moduleRoot   = "../../.."
	manifestPath = "../../migrations/role_grants.json"
)

// notServed are SQL functions and written tables Core names outside the
// serving roles, each run by a command as the migration role or never.
var notServed = map[string]string{
	"mesh_ops.provision_workspace_v1":     "meshcore bootstrap (ApplyBootstrap, migration role)",
	"mesh_ops.change_account_recovery_v1": "meshcore account (ChangeAccountRecovery, migration role)",
	"mesh_ops.resolve_resource_v1":        "unused constant kept for the M1 resolver (nolint:unused)",
	"mesh_ops.resolve_resource_group_v1":  "unused constant kept for the M1 resolver (nolint:unused)",
	"mesh.account":                        "meshcore bootstrap",
	"mesh.deployment":                     "meshcore bootstrap",
	"mesh.identity_provider":              "meshcore bootstrap",
	"mesh.identity_provider_client":       "meshcore bootstrap",
	"mesh.identity_provider_generation":   "meshcore bootstrap",
	"mesh.identity_subject":               "meshcore bootstrap",
	"mesh.principal":                      "meshcore bootstrap",
	"mesh.workspace_feature":              "meshcore bootstrap",
	"mesh_audit.audit_stream":             "meshcore bootstrap",
	"mesh_ops.schema_compatibility":       "meshcore migrate",
	"mesh_ops.schema_migration":           "meshcore migrate",
}

// knownFragments are SQL texts that name a schema and take the object name
// from another constant; the test below proves the names are recognised.
var knownFragments = map[string][]string{
	// mapsession.withSelfIdentityColumns joins "mesh_ops." with
	// read_map_self_identity_v1 or _v2 (map snapshot of the control role).
	"\nLEFT JOIN LATERAL mesh_ops.": {"mesh_ops.read_map_self_identity_v1", "mesh_ops.read_map_self_identity_v2"},
	// migrations operatorRoleFunctionName strips the schema from an operator
	// step's function signature: parsing, not SQL (migration role).
	"mesh_ops.": nil,
}

var (
	analysisOnce   sync.Once
	analysisResult Result
	analysisErr    error
)

func analyzed(t *testing.T) Result {
	t.Helper()
	if testing.Short() {
		t.Skip("whole-program analysis takes about a minute")
	}
	if raceEnabled {
		t.Skip("whole-program analysis runs in the test run without -race")
	}
	analysisOnce.Do(func() { analysisResult, analysisErr = Analyze(moduleRoot) })
	if analysisErr != nil {
		t.Fatal(analysisErr)
	}
	return analysisResult
}

// The checked-in manifest is what the code reaches today. Regenerate with
// make role-grants.
func TestManifestMatchesTheCode(t *testing.T) {
	result := analyzed(t)
	stored, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]Usage
	if err := json.Unmarshal(stored, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != len(Roles) {
		t.Fatalf("manifest roles = %d, want %d", len(manifest), len(Roles))
	}
	for _, role := range Roles {
		if got, want := result.Roles[role], manifest[role]; !equalUsage(got, want) {
			t.Errorf("%s reaches other database objects than %s records; run make role-grants", role, manifestPath)
		}
	}
}

func equalUsage(left, right Usage) bool {
	return slices.Equal(left.Functions, right.Functions) && slices.Equal(left.Inserts, right.Inserts) &&
		slices.Equal(left.Updates, right.Updates) && slices.Equal(left.Deletes, right.Deletes) &&
		slices.Equal(left.Locks, right.Locks) && slices.Equal(left.Reads, right.Reads)
}

// Under-approximation guard: every SQL function and written table named
// anywhere in Core (tools excepted) is reached by a serving role, or is
// listed in notServed with the command that runs it.
func TestEverySQLObjectIsReachedOrExplained(t *testing.T) {
	result := analyzed(t)
	reached := map[string]bool{}
	for _, usage := range result.Roles {
		for _, name := range slices.Concat(usage.Functions, usage.Inserts, usage.Updates, usage.Deletes) {
			reached[name] = true
		}
	}
	everything := result.Everything
	for _, name := range slices.Concat(everything.Functions, everything.Inserts, everything.Updates,
		everything.Deletes) {
		if !reached[name] && notServed[name] == "" {
			t.Errorf("%s is named in Core but reached by no role: a missing grant, or add it to notServed", name)
		}
	}
	for name := range notServed {
		if reached[name] {
			t.Errorf("%s is reached by a role now; remove it from notServed", name)
		}
	}
}

// SQL assembled from a schema fragment and a separate name constant is
// listed, and its names reach the role that runs it.
func TestFragmentsAreKnownAndResolved(t *testing.T) {
	result := analyzed(t)
	for _, text := range result.Fragments {
		names, known := knownFragments[text]
		if !known {
			t.Errorf("SQL fragment %q names a schema without the object: make the name visible or list it", text)
			continue
		}
		for _, name := range names {
			if !slices.Contains(result.Roles["control"].Functions, name) {
				t.Errorf("fragment %q: control does not reach %s", text, name)
			}
		}
	}
	for text := range knownFragments {
		if !slices.Contains(result.Fragments, text) {
			t.Errorf("listed fragment %q is gone; remove it", text)
		}
	}
}

// Direct table writes are pinned per role (TD-SEC-90 §1.2), with the row
// locks registration takes (they need UPDATE).
func TestDirectWritesByRole(t *testing.T) {
	result := analyzed(t)
	control := result.Roles["control"]
	for _, table := range []string{"mesh.device", "mesh.device_machine_key_epoch", "mesh.device_node_key_epoch",
		"mesh.enrollment_credential_use", "mesh.node_address_lease", "mesh.pending_registration",
		"mesh_ops.registration_address_floor"} {
		if !slices.Contains(control.Inserts, table) {
			t.Errorf("control does not insert into %s", table)
		}
	}
	if !slices.Contains(control.Locks, "mesh.enrollment_profile") {
		t.Error("control's registration locks enrollment_profile FOR UPDATE; the lock needs UPDATE")
	}
	// Schema 296 (S3): the api revokes a Device only through
	// mesh_ops.revoke_device_v2, never by writing these tables itself, and
	// since schema 297 (S2.2) it locks them while it resolves only through
	// mesh_ops.lock_device_revocation_target_v1: it needs no UPDATE on them,
	// which S2.3 takes away.
	api := result.Roles["api"]
	for _, function := range []string{"mesh_ops.revoke_device_v2", "mesh_ops.lock_device_revocation_target_v1"} {
		if !slices.Contains(api.Functions, function) {
			t.Errorf("api does not call %s", function)
		}
	}
	for _, table := range []string{"mesh.device", "mesh.device_machine_key_epoch", "mesh.device_node_key_epoch"} {
		if slices.Contains(api.Updates, table) {
			t.Errorf("api updates %s directly; revocation goes through mesh_ops.revoke_device_v2", table)
		}
		if slices.Contains(api.Locks, table) {
			t.Errorf("api locks %s directly; revocation locks through mesh_ops.lock_device_revocation_target_v1", table)
		}
	}
}

var coreSQL = regexp.MustCompile(`\bmesh(?:_ops|_audit)?\.[a-z]`)

// No Core SQL sits behind the dexbroker build tag, which is not analysed.
func TestNoSQLBehindDexbrokerTag(t *testing.T) {
	core := os.DirFS(filepath.Join(moduleRoot, "core"))
	err := fs.WalkDir(core, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		source, err := fs.ReadFile(core, path)
		if err != nil {
			return err
		}
		text := string(source)
		if strings.Contains(text, "//go:build") && strings.Contains(text, "dexbroker") &&
			!strings.Contains(text, "!dexbroker") && coreSQL.MatchString(text) {
			t.Errorf("%s holds Core SQL behind the dexbroker tag, which rolegrants does not analyse", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Each login is one role's pool: worker-gated statements of run() use only
// the worker pool, api and control statements only the runtime pool, so the
// per-role manifest is per login (the all role's runtime login is
// api ∪ control).
func TestRoleStatementsUseTheirPool(t *testing.T) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filepath.Join(moduleRoot, "core/cmd/meshcore/serve.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range parsed.Decls {
		run, ok := declaration.(*ast.FuncDecl)
		if !ok || run.Name.Name != composeFunc {
			continue
		}
		for _, statement := range run.Body.List {
			gated, ok := statement.(*ast.IfStmt)
			if !ok {
				continue
			}
			roles, err := conditionRoles(gated.Cond)
			if err != nil || roles == nil {
				continue
			}
			want := "runtime"
			if slices.Equal(roles, []string{"worker"}) {
				want = "worker"
			} else if !slices.Contains([]string{"api", "control"}, roles[0]) {
				continue
			}
			ast.Inspect(gated, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if base, ok := selector.X.(*ast.Ident); ok && base.Name == "storagePools" &&
					(selector.Sel.Name == "runtime" || selector.Sel.Name == "worker") && selector.Sel.Name != want {
					t.Errorf("%s: a %v statement uses storagePools.%s", files.Position(selector.Pos()), roles,
						selector.Sel.Name)
				}
				return true
			})
		}
	}
}
