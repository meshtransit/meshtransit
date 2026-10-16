package migrations

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// lastContractWindow is the last migration whose operator step still revoked
// a previous function version from the application roles. Those windows are
// closed; from the next migration on, the previous version stays executable
// until a later release contracts it, so rolling back the binary works.
const lastContractWindow = "000093"

var (
	sqlLineComment  = regexp.MustCompile(`--[^\n]*`)
	sqlBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	createFunction  = regexp.MustCompile(`(?is)CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)\s*\(`)
	// A role step is exactly this block, for an owner role that never logs in.
	roleStep = regexp.MustCompile(`(?is)^\s*DO\s+\$(\w*)\$\s*BEGIN\s+IF\s+NOT\s+EXISTS\s*\(\s*SELECT\s+FROM\s+` +
		`pg_catalog\.pg_roles\s+WHERE\s+rolname\s*=\s*'([a-z_][a-z0-9_]*)'\s*\)\s+THEN\s+CREATE\s+ROLE\s+([a-z_][a-z0-9_]*)\s+([A-Z ]+?)\s*;` +
		`\s*ELSE\s+ALTER\s+ROLE\s+([a-z_][a-z0-9_]*)\s+([A-Z ]+?)\s*;\s*END\s+IF\s*;\s*END\s+\$(\w*)\$\s*;\s*$`)
)

const operatorRoleAttributes = "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"

// An operator step after the closed windows may take a function away from
// PUBLIC or an application role (runtime, worker, observer, migrator) only if
// its own migration creates that function (name and argument types) for the
// first time: a new function is kept least-privilege, an older one stays for
// rollback. The check reads the effects the catalog parsed, which are the
// statements the command runs.
func TestOperatorStepsKeepPreviousVersionsForRollback(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		number := step.Name[:6]
		if number <= lastContractWindow || step.Kind != OperatorStepOwnership {
			continue
		}
		for _, problem := range protectedRevokeProblems(step.Effects, firstCreatedBy(t, number)) {
			t.Errorf("%s: %s", step.Name, problem)
		}
	}
}

// Role steps run before their migration and may run again on a database that
// already has the role.
func TestOperatorRoleStepsAreIdempotent(t *testing.T) {
	t.Parallel()
	steps, err := filepath.Glob(filepath.Join("operator", "*_role.sql"))
	if err != nil || len(steps) == 0 {
		t.Fatalf("role steps: %v, %d found", err, len(steps))
	}
	for _, step := range steps {
		if problem := roleStepProblem(readSQL(t, step)); problem != "" {
			t.Errorf("%s: %s", filepath.Base(step), problem)
		}
	}
}

func TestOperatorLintRefusesEvasions(t *testing.T) {
	t.Parallel()
	created := map[string]bool{"mesh_ops.new_v2(UUID,TEXT)": true}
	for name, step := range map[string]string{
		"execute":         "REVOKE EXECUTE ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_runtime;",
		"all privileges":  "REVOKE ALL PRIVILEGES ON FUNCTION mesh_ops.old_v1(UUID) FROM PUBLIC, mesh_share_writer;",
		"second function": "REVOKE ALL ON FUNCTION mesh_ops.new_v2(UUID, TEXT), mesh_ops.old_v1(UUID) FROM mesh_runtime;",
		"quoted role":     `REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM "mesh_runtime";`,
		"other overload":  "REVOKE ALL ON FUNCTION mesh_ops.new_v2(UUID) FROM mesh_runtime;",
		"observer":        "REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_observer;",
		"migrator":        "REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_migrator;",
		"schema-wide":     "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh_ops FROM mesh_runtime;",
		"routine":         "REVOKE ALL ON ROUTINE mesh_ops.old_v1(UUID) FROM mesh_runtime;",
		"do block":        "DO $$ BEGIN EXECUTE 'REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_runtime'; END $$;",
		"default":         "ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM mesh_runtime;",
		"hidden by comment": "-- REVOKE ALL ON FUNCTION mesh_ops.new_v2(UUID,TEXT) FROM mesh_runtime\n" +
			"REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_runtime;",
	} {
		if len(protectedRevokeTextProblems(step, created)) == 0 {
			t.Errorf("%s: accepted %q", name, step)
		}
	}
	allowed := "REVOKE ALL ON FUNCTION mesh_ops.new_v2(UUID, TEXT) FROM PUBLIC, mesh_worker, mesh_observer;\n" +
		"-- REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_runtime;\n" +
		"REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_share_writer;\n"
	if problems := protectedRevokeTextProblems(allowed, created); len(problems) != 0 {
		t.Errorf("refused a valid step: %v", problems)
	}
	for name, step := range map[string]string{
		"plain":   "CREATE ROLE mesh_x NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;",
		"comment": "-- IF NOT EXISTS pg_catalog.pg_roles\nCREATE ROLE mesh_x NOLOGIN;",
		"login": "DO $role$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mesh_x') THEN " +
			"CREATE ROLE mesh_x LOGIN; ELSE ALTER ROLE mesh_x LOGIN; END IF; END $role$;",
		"other role": "DO $role$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mesh_x') THEN " +
			"CREATE ROLE mesh_y " + operatorRoleAttributes + "; ELSE ALTER ROLE mesh_x " + operatorRoleAttributes +
			"; END IF; END $role$;",
	} {
		if roleStepProblem(step) == "" {
			t.Errorf("role %s: accepted %q", name, step)
		}
	}
}

// protectedOperatorRoles may lose EXECUTE only on a function the step's own
// migration creates.
var protectedOperatorRoles = []string{"public", "mesh_runtime", "mesh_worker", "mesh_observer", "mesh_migrator"}

// protectedRevokeProblems lists each parsed revoke that takes a function,
// other than one in created, away from PUBLIC or an application role.
func protectedRevokeProblems(effects []OperatorEffect, created map[string]bool) []string {
	problems := []string{}
	for _, effect := range effects {
		if effect.Kind != OperatorEffectNoExecute || !slices.Contains(protectedOperatorRoles, effect.Role) ||
			created[effect.Function] {
			continue
		}
		problems = append(problems, "revokes "+effect.Function+" from "+effect.Role+", but its migration does not "+
			"create it: keep the previous version executable until a later release contracts it")
	}
	return problems
}

// protectedRevokeTextProblems parses statements as an ownership step does;
// text the parser refuses is a problem too.
func protectedRevokeTextProblems(statements string, created map[string]bool) []string {
	parsed, err := parseOperatorStep(OperatorStepOwnership,
		"-- operator-step: rollout=before\nBEGIN;\n"+statements+"\nCOMMIT;\n")
	if err != nil {
		return []string{err.Error()}
	}
	return protectedRevokeProblems(parsed.Effects, created)
}

func roleStepProblem(step string) string {
	match := roleStep.FindStringSubmatch(stripSQLComments(step))
	switch {
	case match == nil:
		return "a role step is one DO block: IF NOT EXISTS on pg_catalog.pg_roles, CREATE ROLE, else ALTER ROLE"
	case match[1] != match[7] || match[2] != match[3] || match[2] != match[5]:
		return "the block names different roles"
	case match[4] != operatorRoleAttributes || match[6] != operatorRoleAttributes:
		return "the role must be " + operatorRoleAttributes
	}
	return ""
}

// firstCreatedBy returns the signatures migration number creates that no
// earlier migration created.
func firstCreatedBy(t *testing.T, number string) map[string]bool {
	t.Helper()
	migrations, err := filepath.Glob("*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(migrations)
	earlier := map[string]bool{}
	for _, migration := range migrations {
		created := functionsCreatedIn(readSQL(t, migration))
		if strings.HasPrefix(migration, number+"_") {
			first := map[string]bool{}
			for function := range created {
				if !earlier[function] {
					first[function] = true
				}
			}
			return first
		}
		for function := range created {
			earlier[function] = true
		}
	}
	t.Fatalf("migration %s not found", number)
	return nil
}

func functionsCreatedIn(migration string) map[string]bool {
	text := stripSQLComments(migration)
	created := map[string]bool{}
	for _, match := range createFunction.FindAllStringSubmatchIndex(text, -1) {
		name := strings.ToLower(text[match[4]:match[5]])
		arguments, ok := balancedArguments(text[match[1]:])
		if !ok {
			continue
		}
		created[signature(name, argumentTypes(arguments, true))] = true
	}
	return created
}

// balancedArguments returns the text up to the parenthesis that closes the
// argument list starting at text.
func balancedArguments(text string) (string, bool) {
	depth := 1
	for index, character := range text {
		switch character {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return text[:index], true
			}
		}
	}
	return "", false
}

// argumentTypes reduces an argument list to its types. Declarations name
// their parameters ("p_id UUID DEFAULT NULL"); a REVOKE may or may not.
func argumentTypes(arguments string, declared bool) []string {
	types := []string{}
	for _, argument := range splitTopLevel(arguments) {
		fields := strings.Fields(strings.ToUpper(argument))
		if len(fields) == 0 {
			continue
		}
		if index := indexOf(fields, "DEFAULT"); index >= 0 {
			fields = fields[:index]
		}
		if len(fields) > 0 && (fields[0] == "IN" || fields[0] == "VARIADIC" || fields[0] == "INOUT" || fields[0] == "OUT") {
			fields = fields[1:]
		}
		if (declared || len(fields) > 1 && !isTypeWord(fields[1])) && len(fields) > 1 {
			fields = fields[1:]
		}
		types = append(types, strings.Join(fields, " "))
	}
	return types
}

func isTypeWord(word string) bool {
	return word == "PRECISION" || word == "VARYING" || word == "ZONE" || strings.HasPrefix(word, "WITH")
}

func splitTopLevel(text string) []string {
	parts := []string{}
	depth, start := 0, 0
	for index, character := range text {
		switch character {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, text[start:index])
				start = index + 1
			}
		}
	}
	return append(parts, text[start:])
}

func indexOf(fields []string, word string) int {
	for index, field := range fields {
		if field == word || strings.HasPrefix(field, word+"=") {
			return index
		}
	}
	return -1
}

func signature(name string, types []string) string {
	return name + "(" + strings.Join(types, ",") + ")"
}

func stripSQLComments(text string) string {
	return sqlLineComment.ReplaceAllString(sqlBlockComment.ReplaceAllString(text, " "), " ")
}

func readSQL(t *testing.T, path string) string {
	t.Helper()
	text, err := os.ReadFile(path) //nolint:gosec // Files of this package.
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}
