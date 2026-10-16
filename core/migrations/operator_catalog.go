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
	// release calls, or a previous worker would undo its effect. An
	// ownership file declares it on its first line,
	// "-- operator-step: rollout=before" or "…=after".
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
	// classify, whose text it does not accept or whose roles fall outside
	// the allowlist.
	ErrInvalidOperatorStep = errors.New("invalid operator step")

	operatorStepName = regexp.MustCompile(`^([0-9]{6})_[a-z0-9_]+_(role|ownership)\.sql$`)
)

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
	if err := validateOperatorRoles(steps); err != nil {
		return nil, err
	}
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
	parsed, err := parseOperatorStep(kind, string(text))
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
		AfterRollout: parsed.AfterRollout,
		Effects:      parsed.Effects,
	}, nil
}

// Body returns the statements the command runs inside its own transaction,
// rebuilt from the effects the parser read and never the file's text: one
// statement per effect for an ownership step, the canonical block for a role
// step. What the catalog checks is therefore exactly what runs.
func (step OperatorStep) Body() string {
	return renderOperatorEffects(step.Kind, step.Effects)
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
