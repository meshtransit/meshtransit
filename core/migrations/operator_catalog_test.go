package migrations

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every file under operator/ is a step of the embedded catalog, in file
// order with a role step before the ownership step of its migration.
func TestOperatorStepsCoverEveryOperatorFileInOrder(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatalf("OperatorSteps() error = %v", err)
	}
	files, err := filepath.Glob(filepath.Join("operator", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("operator files: %v, %d found", err, len(files))
	}
	if len(steps) != len(files) {
		t.Fatalf("OperatorSteps() = %d steps, want one per file (%d)", len(steps), len(files))
	}
	seen := map[string]bool{}
	for index, step := range steps {
		if seen[step.Name] {
			t.Fatalf("step %s listed twice", step.Name)
		}
		seen[step.Name] = true
		if step.SQL != readSQL(t, filepath.Join("operator", step.Name+".sql")) {
			t.Errorf("%s: SQL differs from its file", step.Name)
		}
		if len(step.Checksum) != 64 || step.Version <= 0 || step.Version > int64(len(Catalog())) {
			t.Errorf("%s: checksum %q version %d", step.Name, step.Checksum, step.Version)
		}
		if len(step.Effects) == 0 {
			t.Errorf("%s: no recognised effect", step.Name)
		}
		if index == 0 {
			continue
		}
		previous := steps[index-1]
		if previous.Version > step.Version ||
			previous.Version == step.Version && previous.Kind == OperatorStepOwnership && step.Kind == OperatorStepRole {
			t.Errorf("%s is listed after %s", step.Name, previous.Name)
		}
	}
}

// Steps 53 to 93 revoke a function version the previous release still calls,
// and the schema 170 and 171 steps let a previous worker undo their effect:
// they wait until no replica of the previous release is left. Add a new
// step here when it has the same constraint.
func TestOperatorStepsMarkThoseThatWaitForTheRollout(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		want := step.Kind == OperatorStepOwnership &&
			(step.Version >= 53 && step.Version <= 93 || step.Version == 170 || step.Version == 171)
		if step.AfterRollout != want {
			t.Errorf("%s: AfterRollout = %t, want %t", step.Name, step.AfterRollout, want)
		}
		if step.Kind == OperatorStepRole && !strings.HasSuffix(step.Name, "_role") ||
			step.Kind == OperatorStepOwnership && !strings.HasSuffix(step.Name, "_ownership") {
			t.Errorf("%s: kind %s", step.Name, step.Kind)
		}
	}
}

// The command runs a step's statements inside its own transaction: an
// ownership step loses exactly its BEGIN and COMMIT, a role step is unchanged.
func TestOperatorStepBodyDropsOnlyTheTransactionWrapper(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	transactionControl := regexp.MustCompile(`(?im)^\s*(BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION|SAVEPOINT|END)\s*;`)
	for _, step := range steps {
		body := step.Body()
		if step.Kind == OperatorStepRole {
			if body != step.SQL {
				t.Errorf("%s: role step body changed", step.Name)
			}
			continue
		}
		if transactionControl.MatchString(stripSQLComments(body)) {
			t.Errorf("%s: body keeps transaction control: %q", step.Name, body)
		}
		if !strings.Contains(body, "ALTER FUNCTION") && !strings.Contains(body, "GRANT") {
			t.Errorf("%s: body lost its statements", step.Name)
		}
	}
}

func TestParseOperatorStepRefusesUnknownStatements(t *testing.T) {
	t.Parallel()
	for name, text := range map[string]string{
		"no wrapper":        "ALTER FUNCTION mesh_ops.f_v1(UUID) OWNER TO mesh_x;",
		"table grant":       "BEGIN;\nGRANT SELECT ON TABLE mesh.device TO mesh_runtime;\nCOMMIT;\n",
		"inner commit":      "BEGIN;\nGRANT EXECUTE ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_runtime;\nCOMMIT;\nBEGIN;\nCOMMIT;\n",
		"dynamic":           "BEGIN;\nDO $$ BEGIN EXECUTE 'GRANT ALL ON SCHEMA mesh TO mesh_runtime'; END $$;\nCOMMIT;\n",
		"schema-wide":       "BEGIN;\nGRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA mesh_ops TO mesh_runtime;\nCOMMIT;\n",
		"other privilege":   "BEGIN;\nGRANT ALL ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_runtime;\nCOMMIT;\n",
		"unqualified":       "BEGIN;\nALTER FUNCTION f_v1(UUID) OWNER TO mesh_x;\nCOMMIT;\n",
		"login role":        "DO $role$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mesh_x') THEN CREATE ROLE mesh_x LOGIN; ELSE ALTER ROLE mesh_x LOGIN; END IF; END $role$;",
		"ownership as role": "BEGIN;\nCOMMIT;\n",
	} {
		kind := OperatorStepOwnership
		if strings.HasPrefix(text, "DO") {
			kind = OperatorStepRole
		}
		if _, err := parseOperatorStepEffects(kind, text); err == nil {
			t.Errorf("%s: accepted %q", name, text)
		}
	}
}

func TestParseOperatorStepReadsOwnersGrantsAndRevokes(t *testing.T) {
	t.Parallel()
	effects, err := parseOperatorStepEffects(OperatorStepOwnership, `BEGIN;
-- comment GRANT EXECUTE ON FUNCTION mesh_ops.hidden_v1(UUID) TO mesh_worker;
ALTER FUNCTION mesh_ops.f_v2(
    BIGINT,  UUID,
    TIMESTAMPTZ
) OWNER TO mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.f_v2(BIGINT, UUID, TIMESTAMPTZ), mesh_ops.g_v1(UUID[]) FROM PUBLIC, mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ) TO mesh_runtime;
COMMIT;
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []OperatorEffect{
		{Kind: OperatorEffectOwner, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "mesh_share_writer"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "public"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "mesh_worker"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.g_v1(UUID[])", Role: "public"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.g_v1(UUID[])", Role: "mesh_worker"},
		{Kind: OperatorEffectExecute, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "mesh_runtime"},
	}
	if len(effects) != len(want) {
		t.Fatalf("effects = %+v", effects)
	}
	for index := range want {
		if effects[index] != want[index] {
			t.Errorf("effect %d = %+v, want %+v", index, effects[index], want[index])
		}
	}
	role, err := parseOperatorStepEffects(OperatorStepRole, readSQL(t, filepath.Join("operator", "000080_direct_device_map_role.sql")))
	if err != nil || len(role) != 1 || role[0] != (OperatorEffect{Kind: OperatorEffectRole, Role: "mesh_direct_map_reader"}) {
		t.Fatalf("role effects = %+v, %v", role, err)
	}
}

// A later step decides the final owner and privileges of a function an
// earlier one also touched; each requirement names the step that set it last.
func TestOperatorRequirementsKeepTheLastStepThatSetEachFact(t *testing.T) {
	t.Parallel()
	steps := []OperatorStep{
		{Name: "000083_a_ownership", Version: 83, Kind: OperatorStepOwnership, Effects: []OperatorEffect{
			{Kind: OperatorEffectOwner, Function: "mesh_ops.f_v1(UUID)", Role: "mesh_a"},
			{Kind: OperatorEffectExecute, Function: "mesh_ops.f_v1(UUID)", Role: "mesh_runtime"},
			{Kind: OperatorEffectExecute, Function: "mesh_ops.g_v1(UUID)", Role: "mesh_runtime"},
		}},
		{Name: "000093_b_ownership", Version: 93, Kind: OperatorStepOwnership, Effects: []OperatorEffect{
			{Kind: OperatorEffectOwner, Function: "mesh_ops.f_v1(UUID)", Role: "mesh_b"},
			{Kind: OperatorEffectNoExecute, Function: "mesh_ops.f_v1(UUID)", Role: "mesh_runtime"},
		}},
	}
	requirements := OperatorRequirements(steps)
	want := []OperatorRequirement{
		{Step: "000093_b_ownership", Effect: OperatorEffect{Kind: OperatorEffectOwner, Function: "mesh_ops.f_v1(UUID)", Role: "mesh_b"}},
		{Step: "000093_b_ownership", Effect: OperatorEffect{Kind: OperatorEffectNoExecute, Function: "mesh_ops.f_v1(UUID)", Role: "mesh_runtime"}},
		{Step: "000083_a_ownership", Effect: OperatorEffect{Kind: OperatorEffectExecute, Function: "mesh_ops.g_v1(UUID)", Role: "mesh_runtime"}},
	}
	if len(requirements) != len(want) {
		t.Fatalf("requirements = %+v", requirements)
	}
	for index := range want {
		if requirements[index] != want[index] {
			t.Errorf("requirement %d = %+v, want %+v", index, requirements[index], want[index])
		}
	}
}

// A function is spelled one way across the catalog, so two spellings never
// hold contradicting requirements for one function.
func TestOperatorStepsSpellEachFunctionOnce(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	spelled := map[string]string{}
	for _, step := range steps {
		for _, effect := range step.Effects {
			if effect.Function == "" {
				continue
			}
			name := effect.Function[:strings.Index(effect.Function, "(")]
			arity := strings.Count(effect.Function, ",")
			key := name + "/" + strconv.Itoa(arity)
			if previous, ok := spelled[key]; ok && previous != effect.Function {
				t.Errorf("%s: %s also spelled %s", step.Name, effect.Function, previous)
			}
			spelled[key] = effect.Function
		}
	}
}

// After an operator step moved a function to its owner, a later migration
// must not change that function's owner or privileges: the command would
// otherwise find the step pending and run it again over the migration.
func TestMigrationsLeaveOperatorManagedFunctionsAlone(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	firstManaged := map[string]int64{}
	for _, step := range steps {
		for _, effect := range step.Effects {
			name := operatorFunctionName(effect.Function)
			if name == "" {
				continue
			}
			if _, ok := firstManaged[name]; !ok {
				firstManaged[name] = step.Version
			}
		}
	}
	privilege := regexp.MustCompile(`(?is)^(GRANT|REVOKE|ALTER\s+FUNCTION)\b`)
	function := regexp.MustCompile(`(?i)mesh_ops\.([a-z0-9_]+)\s*\(`)
	target := regexp.MustCompile(`(?is)\bTO\s+(.+)$`)
	for _, migration := range Catalog() {
		for _, statement := range strings.Split(stripSQLComments(migration.SQL), ";") {
			statement = strings.TrimSpace(statement)
			if !privilege.MatchString(statement) {
				continue
			}
			for _, match := range function.FindAllStringSubmatch(statement, -1) {
				version, managed := firstManaged["mesh_ops."+strings.ToLower(match[1])]
				if !managed || migration.Version <= version {
					continue
				}
				// Granting a new owner role the right to call a managed
				// function adds a privilege no step takes away.
				if grant := target.FindStringSubmatch(statement); strings.HasPrefix(strings.ToUpper(statement), "GRANT") &&
					grant != nil && !operatorStepsRevoke(steps, "mesh_ops."+strings.ToLower(match[1]), grant[1]) {
					continue
				}
				t.Errorf("migration %d changes operator-managed mesh_ops.%s: %s", migration.Version, match[1], statement)
			}
		}
	}
}

func operatorStepsRevoke(steps []OperatorStep, function, roles string) bool {
	for _, step := range steps {
		for _, effect := range step.Effects {
			if effect.Kind != OperatorEffectNoExecute || operatorFunctionName(effect.Function) != function {
				continue
			}
			for _, role := range strings.Split(roles, ",") {
				if strings.EqualFold(strings.TrimSpace(role), effect.Role) {
					return true
				}
			}
		}
	}
	return false
}

func operatorFunctionName(signature string) string {
	if index := strings.Index(signature, "("); index > 0 {
		return strings.ToLower(signature[:index])
	}
	return ""
}
