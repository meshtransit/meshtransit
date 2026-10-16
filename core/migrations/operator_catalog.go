package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// operatorFiles holds every operator step. The command runs only these
// embedded files, never SQL read from a path at run time.
//
//go:embed operator/*.sql
var operatorFiles embed.FS

// OperatorStepKind tells when a step runs relative to its migration.
type OperatorStepKind string

const (
	// OperatorStepRole creates a NOLOGIN owner role; it runs before the
	// migration of the same number and may run again at any time.
	OperatorStepRole OperatorStepKind = "role"
	// OperatorStepOwnership hands the functions of its migration to their
	// owner role and grants them; it runs after that migration.
	OperatorStepOwnership OperatorStepKind = "ownership"
)

// OperatorEffectKind names one fact a step establishes in PostgreSQL.
type OperatorEffectKind string

const (
	// OperatorEffectRole means the role exists, NOLOGIN, with no other privilege.
	OperatorEffectRole OperatorEffectKind = "role"
	// OperatorEffectOwner means Role owns Function.
	OperatorEffectOwner OperatorEffectKind = "owner"
	// OperatorEffectExecute means Role holds an explicit EXECUTE grant on Function.
	OperatorEffectExecute OperatorEffectKind = "execute"
	// OperatorEffectNoExecute means Role ("public" for PUBLIC) holds no EXECUTE
	// grant on Function.
	OperatorEffectNoExecute OperatorEffectKind = "no_execute"
)

// OperatorEffect is one fact of a step. Function is the schema-qualified
// signature with argument types, as the step spells it, without spaces.
type OperatorEffect struct {
	Kind     OperatorEffectKind
	Function string
	Role     string
}

// OperatorStep is one embedded operator SQL file.
type OperatorStep struct {
	// Name is the file name without ".sql", e.g. 000170_…_ownership.
	Name    string
	Version int64
	Kind    OperatorStepKind
	SQL     string
	// Checksum is the hex SHA-256 of SQL.
	Checksum string
	// AfterRollout marks a step that must not run while a replica of the
	// previous release is left: it revokes a function version the previous
	// release calls, or a previous worker would undo its effect.
	AfterRollout bool
	Effects      []OperatorEffect
}

// OperatorRequirement is one effect as it must hold once every step up to
// the newest one ran: a later step that sets the same fact replaces it.
type OperatorRequirement struct {
	Step   string
	Effect OperatorEffect
}

var (
	// ErrInvalidOperatorStep reports an operator file the catalog cannot
	// classify or whose statements it does not recognise.
	ErrInvalidOperatorStep = errors.New("invalid operator step")

	operatorStepName = regexp.MustCompile(`^([0-9]{6})_[a-z0-9_]+_(role|ownership)\.sql$`)
	operatorLineNote = regexp.MustCompile(`--[^\n]*`)
	operatorNote     = regexp.MustCompile(`(?s)/\*.*?\*/`)
	operatorBegin    = regexp.MustCompile(`(?is)^\s*BEGIN\s*;`)
	operatorCommit   = regexp.MustCompile(`(?is)COMMIT\s*;\s*$`)
	operatorRoleDo   = regexp.MustCompile(`(?is)^\s*DO\s+\$(\w*)\$\s*BEGIN\s+IF\s+NOT\s+EXISTS\s*\(\s*SELECT\s+FROM\s+` +
		`pg_catalog\.pg_roles\s+WHERE\s+rolname\s*=\s*'([a-z_][a-z0-9_]*)'\s*\)\s+THEN\s+CREATE\s+ROLE\s+([a-z_][a-z0-9_]*)\s+` +
		`NOLOGIN\s+NOSUPERUSER\s+NOCREATEDB\s+NOCREATEROLE\s+NOREPLICATION\s+NOBYPASSRLS\s*;` +
		`\s*ELSE\s+ALTER\s+ROLE\s+([a-z_][a-z0-9_]*)\s+NOLOGIN\s+NOSUPERUSER\s+NOCREATEDB\s+NOCREATEROLE\s+NOREPLICATION\s+NOBYPASSRLS\s*;` +
		`\s*END\s+IF\s*;\s*END\s+\$(\w*)\$\s*;\s*$`)
	operatorAlterOwner = regexp.MustCompile(`(?is)^ALTER\s+FUNCTION\s+(.+?)\s+OWNER\s+TO\s+([a-z_][a-z0-9_]*)$`)
	operatorGrant      = regexp.MustCompile(`(?is)^GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+(.+)\s+TO\s+([a-z_][a-z0-9_,\s]*)$`)
	operatorRevoke     = regexp.MustCompile(`(?is)^REVOKE\s+(?:ALL(?:\s+PRIVILEGES)?|EXECUTE)\s+ON\s+FUNCTION\s+(.+)\s+FROM\s+([a-z_][a-z0-9_,\s]*)$`)
	operatorFunction   = regexp.MustCompile(`(?is)^\s*(mesh_ops\.[a-z_][a-z0-9_]*)\s*\(([^()]*)\)\s*(?:,|$)`)
	operatorRole       = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
)

// afterRolloutVersions lists the ownership steps that wait for the rollout
// (see OperatorStep.AfterRollout). Steps 53 to 93 revoke the previous
// version of a function; 170 and 171 change what a previous alias worker
// would undo.
func afterRolloutVersion(version int64) bool {
	return version >= 53 && version <= 93 || version == 170 || version == 171
}

// OperatorSteps returns every embedded operator step, ordered by migration
// and, within one migration, the role step first. Each call returns a copy.
func OperatorSteps() ([]OperatorStep, error) {
	steps, err := parsedOperatorSteps()
	if err != nil {
		return nil, err
	}
	copied := make([]OperatorStep, len(steps))
	for index, step := range steps {
		step.Effects = slices.Clone(step.Effects)
		copied[index] = step
	}
	return copied, nil
}

// parsedOperatorSteps parses the embedded files once: readiness checks read
// the catalog on every check.
var parsedOperatorSteps = sync.OnceValues(readOperatorSteps)

func readOperatorSteps() ([]OperatorStep, error) {
	entries, err := fs.ReadDir(operatorFiles, "operator")
	if err != nil {
		return nil, errors.Join(ErrInvalidOperatorStep, err)
	}
	steps := make([]OperatorStep, 0, len(entries))
	for _, entry := range entries {
		step, err := readOperatorStep(entry.Name())
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	slices.SortStableFunc(steps, func(left, right OperatorStep) int {
		switch {
		case left.Version != right.Version:
			return int(left.Version - right.Version)
		case left.Kind != right.Kind && left.Kind == OperatorStepRole:
			return -1
		case left.Kind != right.Kind:
			return 1
		}
		return strings.Compare(left.Name, right.Name)
	})
	return steps, nil
}

func readOperatorStep(file string) (OperatorStep, error) {
	match := operatorStepName.FindStringSubmatch(file)
	if match == nil {
		return OperatorStep{}, fmt.Errorf("%w: %s: name is NNNNNN_…_role.sql or NNNNNN_…_ownership.sql", ErrInvalidOperatorStep, file)
	}
	version, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || version <= 0 {
		return OperatorStep{}, fmt.Errorf("%w: %s: version", ErrInvalidOperatorStep, file)
	}
	text, err := operatorFiles.ReadFile("operator/" + file)
	if err != nil {
		return OperatorStep{}, errors.Join(ErrInvalidOperatorStep, err)
	}
	kind := OperatorStepKind(match[2])
	effects, err := parseOperatorStepEffects(kind, string(text))
	if err != nil {
		return OperatorStep{}, fmt.Errorf("%s: %w", file, err)
	}
	sum := sha256.Sum256(text)
	return OperatorStep{
		Name:         strings.TrimSuffix(file, ".sql"),
		Version:      version,
		Kind:         kind,
		SQL:          string(text),
		Checksum:     hex.EncodeToString(sum[:]),
		AfterRollout: kind == OperatorStepOwnership && afterRolloutVersion(version),
		Effects:      effects,
	}, nil
}

// Body returns the statements the command runs inside its own transaction:
// an ownership step without its BEGIN and COMMIT, a role step as it is.
func (step OperatorStep) Body() string {
	if step.Kind != OperatorStepOwnership {
		return step.SQL
	}
	body := operatorBegin.ReplaceAllString(step.SQL, "")
	return operatorCommit.ReplaceAllString(body, "")
}

// parseOperatorStepEffects reads the facts a step establishes and refuses
// any statement other than the few an operator step may hold.
func parseOperatorStepEffects(kind OperatorStepKind, text string) ([]OperatorEffect, error) {
	stripped := operatorLineNote.ReplaceAllString(operatorNote.ReplaceAllString(text, " "), " ")
	if kind == OperatorStepRole {
		match := operatorRoleDo.FindStringSubmatch(stripped)
		if match == nil || match[1] != match[5] || match[2] != match[3] || match[2] != match[4] {
			return nil, fmt.Errorf("%w: a role step is one DO block creating or resetting one NOLOGIN role", ErrInvalidOperatorStep)
		}
		return []OperatorEffect{{Kind: OperatorEffectRole, Role: match[2]}}, nil
	}
	if kind != OperatorStepOwnership {
		return nil, fmt.Errorf("%w: kind %q", ErrInvalidOperatorStep, kind)
	}
	if !operatorBegin.MatchString(text) || !operatorCommit.MatchString(text) {
		return nil, fmt.Errorf("%w: an ownership step starts with BEGIN; and ends with COMMIT;", ErrInvalidOperatorStep)
	}
	statements := strings.Split(stripped, ";")
	effects := []OperatorEffect{}
	body := statements[:0]
	for _, statement := range statements {
		if statement = strings.Join(strings.Fields(statement), " "); statement != "" {
			body = append(body, statement)
		}
	}
	if len(body) < 3 || !strings.EqualFold(body[0], "BEGIN") || !strings.EqualFold(body[len(body)-1], "COMMIT") {
		return nil, fmt.Errorf("%w: an ownership step is BEGIN, its statements, COMMIT", ErrInvalidOperatorStep)
	}
	for _, statement := range body[1 : len(body)-1] {
		parsed, err := parseOperatorStatement(statement)
		if err != nil {
			return nil, err
		}
		effects = append(effects, parsed...)
	}
	return effects, nil
}

func parseOperatorStatement(statement string) ([]OperatorEffect, error) {
	if match := operatorAlterOwner.FindStringSubmatch(statement); match != nil {
		functions, ok := operatorFunctions(match[1])
		if !ok || len(functions) != 1 {
			return nil, fmt.Errorf("%w: unrecognised function: %s", ErrInvalidOperatorStep, statement)
		}
		return []OperatorEffect{{Kind: OperatorEffectOwner, Function: functions[0], Role: match[2]}}, nil
	}
	kind := OperatorEffectExecute
	match := operatorGrant.FindStringSubmatch(statement)
	if match == nil {
		kind = OperatorEffectNoExecute
		match = operatorRevoke.FindStringSubmatch(statement)
	}
	if match == nil || strings.Contains(strings.ToUpper(match[1]), " IN SCHEMA ") {
		return nil, fmt.Errorf("%w: only ALTER FUNCTION … OWNER TO, GRANT EXECUTE and REVOKE on listed functions: %s",
			ErrInvalidOperatorStep, statement)
	}
	functions, ok := operatorFunctions(match[1])
	roles, rolesOK := operatorRoles(match[2], kind == OperatorEffectNoExecute)
	if !ok || !rolesOK {
		return nil, fmt.Errorf("%w: unrecognised function or role list: %s", ErrInvalidOperatorStep, statement)
	}
	effects := make([]OperatorEffect, 0, len(functions)*len(roles))
	for _, function := range functions {
		for _, role := range roles {
			effects = append(effects, OperatorEffect{Kind: kind, Function: function, Role: role})
		}
	}
	return effects, nil
}

// operatorFunctions reads "mesh_ops.f(T, T), mesh_ops.g(T)" into normalized
// signatures. Argument names are not allowed: the signature is resolved with
// to_regprocedure.
func operatorFunctions(list string) ([]string, bool) {
	functions := []string{}
	for rest := strings.TrimSpace(list); rest != ""; {
		match := operatorFunction.FindStringSubmatchIndex(rest)
		if match == nil {
			return nil, false
		}
		arguments := []string{}
		if text := strings.TrimSpace(rest[match[4]:match[5]]); text != "" {
			for _, argument := range strings.Split(text, ",") {
				argument = strings.ToUpper(strings.Join(strings.Fields(argument), " "))
				if argument == "" {
					return nil, false
				}
				arguments = append(arguments, argument)
			}
		}
		functions = append(functions, strings.ToLower(rest[match[2]:match[3]])+"("+strings.Join(arguments, ",")+")")
		rest = strings.TrimSpace(rest[match[1]:])
	}
	return functions, len(functions) != 0
}

func operatorRoles(list string, allowPublic bool) ([]string, bool) {
	roles := []string{}
	for _, role := range strings.Split(list, ",") {
		role = strings.TrimSpace(role)
		if strings.EqualFold(role, "PUBLIC") {
			if !allowPublic {
				return nil, false
			}
			role = "public"
		}
		if !operatorRole.MatchString(role) {
			return nil, false
		}
		roles = append(roles, role)
	}
	return roles, len(roles) != 0
}

// OperatorRequirements returns what must hold once steps ran in order: for
// each fact (a role, a function's owner, one role's EXECUTE on a function)
// the value the last step that set it gives, attributed to that step, in the
// order the facts first appear.
func OperatorRequirements(steps []OperatorStep) []OperatorRequirement {
	order := []string{}
	final := map[string]OperatorRequirement{}
	for _, step := range steps {
		for _, effect := range step.Effects {
			key := string(effect.Kind) + "|" + effect.Role
			switch effect.Kind {
			case OperatorEffectOwner:
				key = "owner|" + effect.Function
			case OperatorEffectExecute, OperatorEffectNoExecute:
				key = "execute|" + effect.Function + "|" + effect.Role
			}
			if _, seen := final[key]; !seen {
				order = append(order, key)
			}
			final[key] = OperatorRequirement{Step: step.Name, Effect: effect}
		}
	}
	requirements := make([]OperatorRequirement, 0, len(order))
	for _, key := range order {
		requirements = append(requirements, final[key])
	}
	return requirements
}
