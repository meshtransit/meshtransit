package migrations

import (
	"fmt"
	"regexp"
	"strings"
)

// The operator file grammar is deliberately narrow, and the command never
// executes a file's text: it runs the statements renderOperatorEffects
// rebuilds from what this parser read. So a comment, quote or escape that
// PostgreSQL would lex differently cannot hide a statement.
//
// Both kinds: no "/*", "*/", carriage return, backslash or NUL anywhere; a
// comment is a whole line starting with "--".
//
// An ownership file: first line "-- operator-step: rollout=before|after",
// then BEGIN; ALTER FUNCTION … OWNER TO …; GRANT EXECUTE ON FUNCTION … TO …;
// REVOKE {ALL [PRIVILEGES] | EXECUTE} ON FUNCTION … FROM …; COMMIT; with
// upper-case keywords, mesh_ops functions, upper-case argument types and no
// quotes or dollar signs.
//
// A role file: exactly the DO $role$ block that creates or resets one
// mesh_… role as NOLOGIN without other privileges.

var (
	operatorRolloutMarker = regexp.MustCompile(`^-- operator-step: rollout=(before|after)$`)
	operatorMarkerPrefix  = "-- operator-step:"
	operatorAlterOwner    = regexp.MustCompile(`^ALTER FUNCTION (.+?) OWNER TO ([a-z_][a-z0-9_]*)$`)
	operatorGrant         = regexp.MustCompile(`^GRANT EXECUTE ON FUNCTION (.+) TO ([a-z_][a-z0-9_, ]*)$`)
	operatorRevoke        = regexp.MustCompile(`^REVOKE (?:ALL(?: PRIVILEGES)?|EXECUTE) ON FUNCTION (.+) FROM ([A-Za-z_][a-z0-9_, A-Z]*)$`)
	operatorFunction      = regexp.MustCompile(`^ ?(mesh_ops\.[a-z_][a-z0-9_]*) ?\(([^()]*)\) ?(?:,|$)`)
	operatorArgumentType  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*(?:\[\])?$`)
	operatorRoleName      = regexp.MustCompile(`^mesh_[a-z0-9_]+$`)
	operatorRoleDo        = regexp.MustCompile(`^DO \$role\$ BEGIN IF NOT EXISTS \(SELECT FROM pg_catalog\.pg_roles WHERE rolname = ` +
		`'(mesh_[a-z0-9_]+)'\) THEN CREATE ROLE (mesh_[a-z0-9_]+) ` + operatorRoleAttributeText +
		`; ELSE ALTER ROLE (mesh_[a-z0-9_]+) ` + operatorRoleAttributeText + `; END IF; END \$role\$;$`)
)

const operatorRoleAttributeText = "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"

type parsedOperatorStep struct {
	AfterRollout bool
	Effects      []OperatorEffect
}

func operatorParseError(format string, arguments ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidOperatorStep}, arguments...)...)
}

// parseOperatorStep reads the facts a step establishes and refuses any text
// outside the grammar above.
func parseOperatorStep(kind OperatorStepKind, text string) (parsedOperatorStep, error) {
	if strings.Contains(text, "/*") || strings.Contains(text, "*/") || strings.ContainsAny(text, "\r\\\x00") {
		return parsedOperatorStep{}, operatorParseError("block comments, carriage returns, backslashes and NUL are not allowed")
	}
	lines := strings.Split(text, "\n")
	code := make([]string, 0, len(lines))
	marker := ""
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			if strings.HasPrefix(trimmed, operatorMarkerPrefix) {
				if index != 0 || kind != OperatorStepOwnership {
					return parsedOperatorStep{}, operatorParseError("the rollout marker is the first line of an ownership step")
				}
				marker = trimmed
			}
			continue
		}
		if strings.Contains(line, "--") {
			return parsedOperatorStep{}, operatorParseError("a comment is a whole line starting with --")
		}
		code = append(code, trimmed)
	}
	body := strings.Join(strings.Fields(strings.Join(code, " ")), " ")
	switch kind {
	case OperatorStepRole:
		return parseOperatorRoleStep(body)
	case OperatorStepOwnership:
		match := operatorRolloutMarker.FindStringSubmatch(marker)
		if match == nil {
			return parsedOperatorStep{}, operatorParseError(`an ownership step starts with "-- operator-step: rollout=before" or "=after"`)
		}
		effects, err := parseOperatorOwnershipStep(body)
		if err != nil {
			return parsedOperatorStep{}, err
		}
		return parsedOperatorStep{AfterRollout: match[1] == "after", Effects: effects}, nil
	}
	return parsedOperatorStep{}, operatorParseError("kind %q", kind)
}

func parseOperatorRoleStep(body string) (parsedOperatorStep, error) {
	match := operatorRoleDo.FindStringSubmatch(body)
	if match == nil || match[1] != match[2] || match[1] != match[3] {
		return parsedOperatorStep{}, operatorParseError("a role step is one DO $role$ block creating or resetting one NOLOGIN mesh_ role")
	}
	return parsedOperatorStep{Effects: []OperatorEffect{{Kind: OperatorEffectRole, Role: match[1]}}}, nil
}

func parseOperatorOwnershipStep(body string) ([]OperatorEffect, error) {
	if strings.ContainsAny(body, `'"$`) {
		return nil, operatorParseError("an ownership step has no quotes or dollar signs")
	}
	statements := strings.Split(body, ";")
	for index := range statements {
		statements[index] = strings.TrimSpace(statements[index])
	}
	if len(statements) < 4 || statements[0] != "BEGIN" || statements[len(statements)-2] != "COMMIT" ||
		statements[len(statements)-1] != "" {
		return nil, operatorParseError("an ownership step is BEGIN;, its statements, COMMIT;")
	}
	effects := []OperatorEffect{}
	for _, statement := range statements[1 : len(statements)-2] {
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
		if !ok || len(functions) != 1 || !operatorRoleName.MatchString(match[2]) {
			return nil, operatorParseError("unrecognised function or owner: %s", statement)
		}
		return []OperatorEffect{{Kind: OperatorEffectOwner, Function: functions[0], Role: match[2]}}, nil
	}
	kind := OperatorEffectExecute
	match := operatorGrant.FindStringSubmatch(statement)
	if match == nil {
		kind = OperatorEffectNoExecute
		match = operatorRevoke.FindStringSubmatch(statement)
	}
	if match == nil {
		return nil, operatorParseError("only ALTER FUNCTION … OWNER TO, GRANT EXECUTE and REVOKE on listed functions: %s", statement)
	}
	functions, ok := operatorFunctions(match[1])
	roles, rolesOK := operatorRoles(match[2], kind == OperatorEffectNoExecute)
	if !ok || !rolesOK {
		return nil, operatorParseError("unrecognised function or role list: %s", statement)
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
// signatures. Each argument is one upper-case type name: no argument names.
func operatorFunctions(list string) ([]string, bool) {
	functions := []string{}
	for rest := list; rest != ""; {
		match := operatorFunction.FindStringSubmatchIndex(rest)
		if match == nil {
			return nil, false
		}
		arguments := []string{}
		if text := strings.TrimSpace(rest[match[4]:match[5]]); text != "" {
			for _, argument := range strings.Split(text, ",") {
				argument = strings.TrimSpace(argument)
				if !operatorArgumentType.MatchString(argument) {
					return nil, false
				}
				arguments = append(arguments, argument)
			}
		}
		functions = append(functions, rest[match[2]:match[3]]+"("+strings.Join(arguments, ",")+")")
		rest = strings.TrimSpace(rest[match[1]:])
	}
	return functions, len(functions) != 0
}

func operatorRoles(list string, allowPublic bool) ([]string, bool) {
	roles := []string{}
	for _, role := range strings.Split(list, ",") {
		role = strings.TrimSpace(role)
		if role == "PUBLIC" && allowPublic {
			roles = append(roles, "public")
			continue
		}
		if !operatorRoleName.MatchString(role) {
			return nil, false
		}
		roles = append(roles, role)
	}
	return roles, len(roles) != 0
}

// renderOperatorEffects rebuilds the statements of a step from its effects.
// Every identifier was validated against a closed character set, so the text
// needs no quoting.
func renderOperatorEffects(kind OperatorStepKind, effects []OperatorEffect) string {
	var text strings.Builder
	for _, effect := range effects {
		role := effect.Role
		if role == "public" {
			role = "PUBLIC"
		}
		switch {
		case kind == OperatorStepRole && effect.Kind == OperatorEffectRole:
			text.WriteString("DO $role$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '" + role +
				"') THEN CREATE ROLE " + role + " " + operatorRoleAttributeText + "; ELSE ALTER ROLE " + role + " " +
				operatorRoleAttributeText + "; END IF; END $role$;\n")
		case kind != OperatorStepOwnership:
		case effect.Kind == OperatorEffectOwner:
			text.WriteString("ALTER FUNCTION " + effect.Function + " OWNER TO " + role + ";\n")
		case effect.Kind == OperatorEffectExecute:
			text.WriteString("GRANT EXECUTE ON FUNCTION " + effect.Function + " TO " + role + ";\n")
		case effect.Kind == OperatorEffectNoExecute:
			text.WriteString("REVOKE ALL ON FUNCTION " + effect.Function + " FROM " + role + ";\n")
		}
	}
	return text.String()
}
