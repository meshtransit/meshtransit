package migrations

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// Every ownership file states on its first line whether it waits for the
// rollout. Steps 53 to 93 revoke a function version the previous release
// still calls, and the schema 170 and 171 steps let a previous worker undo
// their effect.
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
	for name, text := range map[string]string{
		"no marker":     "BEGIN;\nGRANT EXECUTE ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_runtime;\nCOMMIT;\n",
		"late marker":   "BEGIN;\n-- operator-step: rollout=after\nGRANT EXECUTE ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_runtime;\nCOMMIT;\n",
		"other value":   "-- operator-step: rollout=later\nBEGIN;\nGRANT EXECUTE ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_runtime;\nCOMMIT;\n",
		"second marker": ownershipMarker + "-- operator-step: rollout=after\nBEGIN;\nCOMMIT;\n",
	} {
		if _, err := parseOperatorStep(OperatorStepOwnership, text); err == nil {
			t.Errorf("%s: accepted %q", name, text)
		}
	}
}

// A step that runs before the rollout ends may take EXECUTE away from the
// runtime, worker or migrator role only on a function its own migration
// creates for the first time; anything else the previous release may call.
func TestOperatorStepsBeforeTheRolloutRevokeOnlyNewFunctions(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		if step.Kind != OperatorStepOwnership || step.AfterRollout {
			continue
		}
		created := firstCreatedBy(t, step.Name[:6])
		for _, effect := range step.Effects {
			if effect.Kind != OperatorEffectNoExecute ||
				effect.Role != "mesh_runtime" && effect.Role != "mesh_worker" && effect.Role != "mesh_migrator" {
				continue
			}
			if !created[strings.ToLower(effect.Function)] && !createdIgnoringCase(created, effect.Function) {
				t.Errorf("%s: rollout=before but revokes %s from %s, which migration %s does not create; mark it rollout=after",
					step.Name, effect.Function, effect.Role, step.Name[:6])
			}
		}
	}
}

func createdIgnoringCase(created map[string]bool, function string) bool {
	for signature := range created {
		if strings.EqualFold(signature, function) {
			return true
		}
	}
	return false
}

// The command runs the statements rebuilt from what the parser read, never
// the file's text: an ownership step is one statement per effect, a role
// step the canonical block for its role.
func TestOperatorStepBodyIsRebuiltFromItsEffects(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		body := step.Body()
		if strings.Contains(body, "--") || strings.ContainsAny(body, "\r\\\"") ||
			strings.Contains(body, "/*") || strings.Contains(body, "COMMIT") || strings.Contains(body, "BEGIN;") {
			t.Errorf("%s: body %q", step.Name, body)
		}
		if step.Kind == OperatorStepOwnership && strings.Count(body, ";") != len(step.Effects) {
			t.Errorf("%s: %d statements for %d effects", step.Name, strings.Count(body, ";"), len(step.Effects))
		}
		reparsed, err := parseOperatorStep(step.Kind, renderParseable(step))
		if err != nil || !slices.Equal(reparsed.Effects, step.Effects) {
			t.Errorf("%s: rebuilt body does not parse back: %v", step.Name, err)
		}
	}
}

const ownershipMarker = "-- operator-step: rollout=before\n"

func renderParseable(step OperatorStep) string {
	if step.Kind == OperatorStepRole {
		return step.Body()
	}
	return ownershipMarker + "BEGIN;\n" + step.Body() + "COMMIT;\n"
}

func TestParseOperatorStepRefusesUnknownStatements(t *testing.T) {
	t.Parallel()
	owner := "ALTER FUNCTION mesh_ops.f_v1(BIGINT) OWNER TO mesh_direct_map_reader;\n"
	for name, text := range map[string]string{
		"no wrapper":      "ALTER FUNCTION mesh_ops.f_v1(UUID) OWNER TO mesh_x;",
		"table grant":     "BEGIN;\nGRANT SELECT ON TABLE mesh.device TO mesh_runtime;\nCOMMIT;\n",
		"inner commit":    "BEGIN;\nGRANT EXECUTE ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_runtime;\nCOMMIT;\nBEGIN;\nCOMMIT;\n",
		"inner rollback":  "BEGIN;\n" + owner + "ROLLBACK;\n" + owner + "COMMIT;\n",
		"set role":        "BEGIN;\nSET ROLE mesh_runtime;\n" + owner + "COMMIT;\n",
		"dynamic":         "BEGIN;\nDO $$ BEGIN EXECUTE 'GRANT ALL ON SCHEMA mesh TO mesh_runtime'; END $$;\nCOMMIT;\n",
		"schema-wide":     "BEGIN;\nGRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA mesh_ops TO mesh_runtime;\nCOMMIT;\n",
		"other privilege": "BEGIN;\nGRANT ALL ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_runtime;\nCOMMIT;\n",
		"unqualified":     "BEGIN;\nALTER FUNCTION f_v1(UUID) OWNER TO mesh_x;\nCOMMIT;\n",
		"lowercase":       "BEGIN;\nalter function mesh_ops.f_v1(UUID) owner to mesh_direct_map_reader;\nCOMMIT;\n",
		// PostgreSQL ends a line comment at the line end, so the block
		// comment never starts and ALTER ROLE runs.
		"line comment opens block": "BEGIN;\n" + strings.TrimSuffix(owner, "\n") + " -- /*\nALTER ROLE mesh_direct_map_reader SUPERUSER;\n-- */\nCOMMIT;\n",
		"block comment":            "BEGIN;\n/* ALTER ROLE x */\n" + owner + "COMMIT;\n",
		"nested block comment":     "BEGIN;\n/* /* */ ALTER ROLE mesh_direct_map_reader SUPERUSER; */\n" + owner + "COMMIT;\n",
		"carriage return":          "BEGIN;\n-- note\rALTER ROLE mesh_direct_map_reader SUPERUSER;\n" + owner + "COMMIT;\n",
		"trailing comment":         "BEGIN;\n" + strings.TrimSuffix(owner, "\n") + " -- note\nCOMMIT;\n",
		"quoted identifier":        "BEGIN;\nALTER FUNCTION \"mesh_ops\".f_v1(BIGINT) OWNER TO mesh_direct_map_reader;\nCOMMIT;\n",
		"backslash":                "BEGIN;\n" + owner + "\\i other.sql\nCOMMIT;\n",
		"argument name":            "BEGIN;\nALTER FUNCTION mesh_ops.f_v1(p BIGINT) OWNER TO mesh_direct_map_reader;\nCOMMIT;\n",
		"login role": "DO $role$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mesh_x') THEN " +
			"CREATE ROLE mesh_x LOGIN; ELSE ALTER ROLE mesh_x LOGIN; END IF; END $role$;",
		"role then statement": readSQL(t, filepath.Join("operator", "000080_direct_device_map_role.sql")) +
			"ALTER ROLE mesh_direct_map_reader SUPERUSER;\n",
		"role hidden by comment": "-- /*\n" + readSQL(t, filepath.Join("operator", "000080_direct_device_map_role.sql")) +
			"ALTER ROLE mesh_direct_map_reader SUPERUSER; -- */\n",
		"role for postgres": strings.ReplaceAll(readSQL(t, filepath.Join("operator", "000080_direct_device_map_role.sql")),
			"mesh_direct_map_reader", "postgres"),
		"ownership as role": "BEGIN;\nCOMMIT;\n",
	} {
		kind := OperatorStepOwnership
		if strings.Contains(text, "DO $role$") || name == "role hidden by comment" {
			kind = OperatorStepRole
		} else {
			text = ownershipMarker + text
		}
		if _, err := parseOperatorStep(kind, text); err == nil {
			t.Errorf("%s: accepted %q", name, text)
		}
	}
}

// Roles come from fixed sets: an owner is an owner role (one a role step
// creates, or an install owner), a grantee is a MeshTransit role, PUBLIC
// appears only in a REVOKE, and a role step never names an application role.
func TestOperatorCatalogRefusesRolesOutsideTheAllowlist(t *testing.T) {
	t.Parallel()
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	owner := func(role string) []OperatorStep {
		return append(slices.Clone(steps), OperatorStep{Name: "000999_x_ownership", Version: 999, Kind: OperatorStepOwnership,
			Effects: []OperatorEffect{{Kind: OperatorEffectOwner, Function: "mesh_ops.x_v1(UUID)", Role: role}}})
	}
	grant := func(kind OperatorEffectKind, role string) []OperatorStep {
		return append(slices.Clone(steps), OperatorStep{Name: "000999_x_ownership", Version: 999, Kind: OperatorStepOwnership,
			Effects: []OperatorEffect{{Kind: kind, Function: "mesh_ops.x_v1(UUID)", Role: role}}})
	}
	role := func(name string) []OperatorStep {
		return append(slices.Clone(steps), OperatorStep{Name: "000999_x_role", Version: 999, Kind: OperatorStepRole,
			Effects: []OperatorEffect{{Kind: OperatorEffectRole, Role: name}}})
	}
	for name, candidate := range map[string][]OperatorStep{
		"owner superuser":        owner("postgres"),
		"owner runtime":          owner("mesh_runtime"),
		"owner unknown mesh":     owner("mesh_unknown"),
		"grant to other":         grant(OperatorEffectExecute, "postgres"),
		"grant to public":        grant(OperatorEffectExecute, "public"),
		"revoke from other":      grant(OperatorEffectNoExecute, "app_user"),
		"role step for runtime":  role("mesh_runtime"),
		"role step for migrator": role("mesh_migrator"),
	} {
		if err := validateOperatorRoles(candidate); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validateOperatorRoles(steps); err != nil {
		t.Fatalf("embedded catalog: %v", err)
	}
	managed, err := OperatorManagedRoles()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mesh_runtime", "mesh_worker", "mesh_observer", "mesh_migrator", "mesh_share_writer",
		"mesh_audit_writer", "mesh_direct_map_reader", "mesh_device_alias_writer"} {
		if !slices.Contains(managed, want) {
			t.Errorf("OperatorManagedRoles() lacks %s: %v", want, managed)
		}
	}
}

func TestParseOperatorStepReadsOwnersGrantsAndRevokes(t *testing.T) {
	t.Parallel()
	parsed, err := parseOperatorStep(OperatorStepOwnership, `-- operator-step: rollout=after
-- A comment line, even with GRANT EXECUTE ON FUNCTION mesh_ops.hidden_v1(UUID) TO mesh_worker; in it.
BEGIN;
ALTER FUNCTION mesh_ops.f_v2(
    BIGINT,  UUID,
    TIMESTAMPTZ
) OWNER TO mesh_share_writer;
  -- an indented comment line
REVOKE ALL ON FUNCTION mesh_ops.f_v2(BIGINT, UUID, TIMESTAMPTZ), mesh_ops.g_v1(UUID[]) FROM PUBLIC, mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ) TO mesh_runtime;
COMMIT;
`)
	if err != nil {
		t.Fatal(err)
	}
	effects := parsed.Effects
	want := []OperatorEffect{
		{Kind: OperatorEffectOwner, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "mesh_share_writer"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "public"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "mesh_worker"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.g_v1(UUID[])", Role: "public"},
		{Kind: OperatorEffectNoExecute, Function: "mesh_ops.g_v1(UUID[])", Role: "mesh_worker"},
		{Kind: OperatorEffectExecute, Function: "mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ)", Role: "mesh_runtime"},
	}
	if !parsed.AfterRollout || !slices.Equal(effects, want) {
		t.Fatalf("parsed = %+v", parsed)
	}
	if body := renderOperatorEffects(OperatorStepOwnership, effects); body != "ALTER FUNCTION mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ) OWNER TO mesh_share_writer;\n"+
		"REVOKE ALL ON FUNCTION mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ) FROM PUBLIC;\n"+
		"REVOKE ALL ON FUNCTION mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ) FROM mesh_worker;\n"+
		"REVOKE ALL ON FUNCTION mesh_ops.g_v1(UUID[]) FROM PUBLIC;\n"+
		"REVOKE ALL ON FUNCTION mesh_ops.g_v1(UUID[]) FROM mesh_worker;\n"+
		"GRANT EXECUTE ON FUNCTION mesh_ops.f_v2(BIGINT,UUID,TIMESTAMPTZ) TO mesh_runtime;\n" {
		t.Fatalf("body = %q", body)
	}
	role, err := parseOperatorStep(OperatorStepRole, readSQL(t, filepath.Join("operator", "000080_direct_device_map_role.sql")))
	if err != nil || len(role.Effects) != 1 || role.Effects[0] != (OperatorEffect{Kind: OperatorEffectRole, Role: "mesh_direct_map_reader"}) {
		t.Fatalf("role effects = %+v, %v", role, err)
	}
}

// Whatever text the parser accepts, the command runs exactly the statements
// rebuilt from the effects it read, and those parse back to the same effects.
func FuzzParseOperatorStep(f *testing.F) {
	files, err := filepath.Glob(filepath.Join("operator", "*.sql"))
	if err != nil {
		f.Fatal(err)
	}
	for _, file := range files {
		text, err := os.ReadFile(file) //nolint:gosec // Files of this package.
		if err != nil {
			f.Fatal(err)
		}
		f.Add(strings.HasSuffix(file, "_role.sql"), string(text))
	}
	f.Add(false, ownershipMarker+"BEGIN;\nALTER FUNCTION mesh_ops.f_v1(BIGINT) OWNER TO mesh_share_writer; -- /*\nALTER ROLE x SUPERUSER;\n-- */\nCOMMIT;\n")
	f.Fuzz(func(t *testing.T, role bool, text string) {
		kind := OperatorStepOwnership
		if role {
			kind = OperatorStepRole
		}
		parsed, err := parseOperatorStep(kind, text)
		if err != nil {
			return
		}
		step := OperatorStep{Kind: kind, Effects: parsed.Effects}
		body := step.Body()
		if body != renderOperatorEffects(kind, parsed.Effects) {
			t.Fatalf("body differs from the rebuilt effects: %q", body)
		}
		if strings.Contains(body, "--") || strings.Contains(body, "/*") || strings.ContainsAny(body, "\r\\\"") {
			t.Fatalf("rebuilt body carries comment or escape text: %q", body)
		}
		again, err := parseOperatorStep(kind, renderParseable(step))
		if err != nil || !slices.Equal(again.Effects, parsed.Effects) {
			t.Fatalf("rebuilt body %q parses to %+v, %v", body, again, err)
		}
	})
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
