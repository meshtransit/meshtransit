package migrations

import (
	"os"
	"path/filepath"
	"regexp"
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
	// REVOKE {ALL [PRIVILEGES] | EXECUTE} ON FUNCTION f(args)[, g(args)...] FROM roles
	revokeFunctions = regexp.MustCompile(`(?is)^REVOKE\s+(?:ALL(?:\s+PRIVILEGES)?|EXECUTE)\s+ON\s+FUNCTION\s+(.+)\s+FROM\s+(.+)$`)
	functionTarget  = regexp.MustCompile(`(?is)^\s*([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)\s*\(([^()]*)\)\s*(?:,|$)`)
	createFunction  = regexp.MustCompile(`(?is)CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)\s*\(`)
	applicationRole = regexp.MustCompile(`(?i)(^|[\s,"])mesh_(runtime|worker)([\s,"]|$)`)
	forbiddenInStep = regexp.MustCompile(`(?i)\bALL\s+(FUNCTIONS|ROUTINES|PROCEDURES)\s+IN\s+SCHEMA\b|\bDEFAULT\s+PRIVILEGES\b|` +
		`\bON\s+(ROUTINE|PROCEDURE)\b|^\s*DO\b|\bEXECUTE\s+format\b|\bREVOKE\b.*\bGRANTED\s+BY\b`)
	// A role step is exactly this block, for an owner role that never logs in.
	roleStep = regexp.MustCompile(`(?is)^\s*DO\s+\$(\w*)\$\s*BEGIN\s+IF\s+NOT\s+EXISTS\s*\(\s*SELECT\s+FROM\s+` +
		`pg_catalog\.pg_roles\s+WHERE\s+rolname\s*=\s*'([a-z_][a-z0-9_]*)'\s*\)\s+THEN\s+CREATE\s+ROLE\s+([a-z_][a-z0-9_]*)\s+([A-Z ]+?)\s*;` +
		`\s*ELSE\s+ALTER\s+ROLE\s+([a-z_][a-z0-9_]*)\s+([A-Z ]+?)\s*;\s*END\s+IF\s*;\s*END\s+\$(\w*)\$\s*;\s*$`)
)

const operatorRoleAttributes = "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"

// An operator step after the closed windows may take a function away from the
// runtime or worker role only if its own migration creates that function
// (name and argument types) for the first time: a new function is kept
// least-privilege, an older one stays for rollback.
func TestOperatorStepsKeepPreviousVersionsForRollback(t *testing.T) {
	t.Parallel()
	steps, err := filepath.Glob(filepath.Join("operator", "*.sql"))
	if err != nil || len(steps) == 0 {
		t.Fatalf("operator steps: %v, %d found", err, len(steps))
	}
	for _, step := range steps {
		name := filepath.Base(step)
		if !strings.HasSuffix(name, "_ownership.sql") && !strings.HasSuffix(name, "_role.sql") {
			t.Errorf("%s: operator steps are …_ownership.sql or …_role.sql", name)
			continue
		}
		number := name[:6]
		if number <= lastContractWindow || strings.HasSuffix(name, "_role.sql") {
			continue
		}
		created := firstCreatedBy(t, number)
		for _, problem := range operatorStepProblems(readSQL(t, step), created) {
			t.Errorf("%s: %s", name, problem)
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
		"all privileges":  "REVOKE ALL PRIVILEGES ON FUNCTION mesh_ops.old_v1(UUID) FROM PUBLIC, mesh_worker;",
		"second function": "REVOKE ALL ON FUNCTION mesh_ops.new_v2(UUID, TEXT), mesh_ops.old_v1(UUID) FROM mesh_runtime;",
		"quoted role":     `REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM "mesh_runtime";`,
		"other overload":  "REVOKE ALL ON FUNCTION mesh_ops.new_v2(UUID) FROM mesh_runtime;",
		"schema-wide":     "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh_ops FROM mesh_runtime;",
		"routine":         "REVOKE ALL ON ROUTINE mesh_ops.old_v1(UUID) FROM mesh_runtime;",
		"do block":        "DO $$ BEGIN EXECUTE 'REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_runtime'; END $$;",
		"default":         "ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM mesh_runtime;",
		"hidden by comment": "-- REVOKE ALL ON FUNCTION mesh_ops.new_v2(UUID,TEXT) FROM mesh_runtime\n" +
			"REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_runtime;",
	} {
		if len(operatorStepProblems(step, created)) == 0 {
			t.Errorf("%s: accepted %q", name, step)
		}
	}
	allowed := "REVOKE ALL ON FUNCTION mesh_ops.new_v2(p UUID, q TEXT) FROM PUBLIC, mesh_worker;\n" +
		"-- REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_runtime;\n" +
		"REVOKE ALL ON FUNCTION mesh_ops.old_v1(UUID) FROM mesh_observer;\n"
	if problems := operatorStepProblems(allowed, created); len(problems) != 0 {
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

// operatorStepProblems lists every statement of an ownership step that could
// take a function, other than one in created, away from an application role.
func operatorStepProblems(step string, created map[string]bool) []string {
	problems := []string{}
	for _, statement := range strings.Split(stripSQLComments(step), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if forbiddenInStep.MatchString(statement) {
			problems = append(problems, "uses a schema-wide, default, dynamic or block form: "+statement)
			continue
		}
		if !regexp.MustCompile(`(?i)^REVOKE\b`).MatchString(statement) {
			continue
		}
		match := revokeFunctions.FindStringSubmatch(statement)
		if match == nil {
			if applicationRole.MatchString(statement) {
				problems = append(problems, "unrecognised revoke from an application role: "+statement)
			}
			continue
		}
		if !applicationRole.MatchString(match[2]) {
			continue
		}
		targets, ok := revokeTargets(match[1])
		if !ok {
			problems = append(problems, "unrecognised function list: "+statement)
			continue
		}
		for _, target := range targets {
			if !created[target] {
				problems = append(problems, "revokes "+target+" from an application role, but its migration does not "+
					"create it: keep the previous version executable until a later release contracts it")
			}
		}
	}
	return problems
}

func revokeTargets(list string) ([]string, bool) {
	targets := []string{}
	for rest := strings.TrimSpace(list); rest != ""; {
		match := functionTarget.FindStringSubmatchIndex(rest)
		if match == nil {
			return nil, false
		}
		name := strings.ToLower(rest[match[2]:match[3]])
		targets = append(targets, signature(name, argumentTypes(rest[match[4]:match[5]], false)))
		rest = strings.TrimSpace(rest[match[1]:])
	}
	return targets, len(targets) != 0
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
