package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/migrations"
)

var (
	// ErrInvalidLoginPassword reports a login password that is too short, too
	// long or not printable ASCII without spaces.
	ErrInvalidLoginPassword = errors.New("invalid operator login password")
	// ErrOperatorLoginsNeedSuperuser reports an operator that cannot keep
	// logins safely: it must read stored verifiers (to never reset a working
	// password by mistake) and silence statement logging.
	ErrOperatorLoginsNeedSuperuser = errors.New("keeping operator logins needs a superuser operator")
	// ErrOperatorLoginPasswordDiffers reports a login whose stored password
	// is not the one given: replacing it would cut off the running serving
	// pods, so it needs an explicit rotation.
	ErrOperatorLoginPasswordDiffers = errors.New("operator login password differs from the stored one")
)

const (
	minimumLoginPasswordLength = 32
	maximumLoginPasswordLength = 256
	scramIterations            = 4096
	scramSaltLength            = 16
)

var (
	loginName = regexp.MustCompile(`^mesh_[a-z_]{1,48}$`)
	// scramVerifierPattern is PostgreSQL's stored SCRAM-SHA-256 form; only
	// base64 characters follow the fixed prefix, so the verifier can be
	// written as a literal without quoting issues.
	scramVerifierPattern = regexp.MustCompile(
		`^SCRAM-SHA-256\$([0-9]{4,7}):([A-Za-z0-9+/]+=*)\$([A-Za-z0-9+/]+=*):([A-Za-z0-9+/]+=*)$`)
)

// OperatorLoginResult is what one apply did to one login.
type OperatorLoginResult struct {
	Name            string `json:"name"`
	Created         bool   `json:"created"`
	PasswordChanged bool   `json:"password_changed"`
}

const operatorLoginStateSQL = `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)`

const operatorLoginPrivilegesSQL = `SELECT
    pg_catalog.has_table_privilege('pg_catalog.pg_authid', 'SELECT')
    AND pg_catalog.has_parameter_privilege('log_statement', 'SET')
    AND pg_catalog.has_parameter_privilege('log_min_error_statement', 'SET')
    AND pg_catalog.has_parameter_privilege('log_min_duration_statement', 'SET')`

// operatorLoginSilenceSQL keeps the verifier out of every server log for the
// rest of the transaction: statements, failing statements, slow statements.
const operatorLoginSilenceSQL = `SET LOCAL log_statement = 'none';
SET LOCAL log_min_error_statement = 'panic';
SET LOCAL log_min_duration_statement = -1`

const operatorLoginVerifierSQL = `SELECT COALESCE(rolpassword, '') FROM pg_catalog.pg_authid WHERE rolname = $1`

// ensureOperatorLogins creates each catalog login that is missing, resets
// its attributes and settings, grants its memberships (INHERIT, no SET, no
// ADMIN) and sets the given password on a new login. An existing login whose
// stored password differs is refused unless rotate is set: the running pods
// still use the stored one. The password travels only as a SCRAM-SHA-256
// verifier computed here, and no server log records it.
func ensureOperatorLogins(
	ctx context.Context,
	transaction migrationTransaction,
	passwords map[string][]byte,
	rotate bool,
) ([]OperatorLoginResult, error) {
	logins := migrations.OperatorLogins()
	for name := range passwords {
		if !slices.ContainsFunc(logins, func(login migrations.OperatorLogin) bool { return login.Name == name }) {
			return nil, fmt.Errorf("%w: %s is not an operator login", ErrInvalidOperatorOptions, name)
		}
	}
	var privileged bool
	if err := transaction.QueryRow(ctx, operatorLoginPrivilegesSQL).Scan(&privileged); err != nil {
		return nil, fmt.Errorf("read operator privileges: %w", err)
	}
	if !privileged {
		return nil, ErrOperatorLoginsNeedSuperuser
	}
	if err := transaction.Exec(ctx, operatorLoginSilenceSQL); err != nil {
		return nil, fmt.Errorf("silence server logs: %w", err)
	}
	results := make([]OperatorLoginResult, 0, len(logins))
	for _, login := range logins {
		password, wanted := passwords[login.Name]
		if !wanted {
			continue
		}
		if err := validLoginPassword(password); err != nil {
			return nil, err
		}
		result, err := ensureOperatorLogin(ctx, transaction, login, password, rotate)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func ensureOperatorLogin(
	ctx context.Context,
	transaction migrationTransaction,
	login migrations.OperatorLogin,
	password []byte,
	rotate bool,
) (OperatorLoginResult, error) {
	if !loginName.MatchString(login.Name) {
		return OperatorLoginResult{}, fmt.Errorf("%w: login name %q", ErrOperatorCatalog, login.Name)
	}
	identifier := pgx.Identifier{login.Name}.Sanitize()
	result := OperatorLoginResult{Name: login.Name}
	var exists bool
	if err := transaction.QueryRow(ctx, operatorLoginStateSQL, login.Name).Scan(&exists); err != nil {
		return result, fmt.Errorf("read login %s: %w", login.Name, err)
	}
	attributes := "LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
		"CONNECTION LIMIT -1 VALID UNTIL 'infinity'"
	var database string
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.current_database()`).Scan(&database); err != nil {
		return result, fmt.Errorf("read current database: %w", err)
	}
	// Settings attached to the login, in every database and in this one,
	// are cleared: the serving process sets its own.
	statements := []string{
		"ALTER ROLE " + identifier + " " + attributes,
		"ALTER ROLE " + identifier + " RESET ALL",
		"ALTER ROLE " + identifier + " IN DATABASE " + pgx.Identifier{database}.Sanitize() + " RESET ALL",
	}
	if !exists {
		statements = []string{"CREATE ROLE " + identifier + " " + attributes}
		result.Created = true
	}
	for _, statement := range statements {
		if err := transaction.Exec(ctx, statement); err != nil {
			return result, fmt.Errorf("keep login %s: %w", login.Name, err)
		}
	}
	for _, role := range login.MemberOf {
		if !loginName.MatchString(role) {
			return result, fmt.Errorf("%w: member role %q", ErrOperatorCatalog, role)
		}
		granted := pgx.Identifier{role}.Sanitize()
		for _, grant := range []string{
			"GRANT " + granted + " TO " + identifier + " WITH INHERIT TRUE, SET FALSE",
			"REVOKE ADMIN OPTION FOR " + granted + " FROM " + identifier,
		} {
			if err := transaction.Exec(ctx, grant); err != nil {
				return result, fmt.Errorf("grant %s to login %s: %w", role, login.Name, err)
			}
		}
	}
	if !result.Created {
		var stored string
		if err := transaction.QueryRow(ctx, operatorLoginVerifierSQL, login.Name).Scan(&stored); err != nil {
			return result, fmt.Errorf("read login %s verifier: %w", login.Name, err)
		}
		if scramVerifierMatches(stored, password) {
			return result, nil
		}
		if stored != "" && !rotate {
			return result, fmt.Errorf("%w: %s", ErrOperatorLoginPasswordDiffers, login.Name)
		}
	}
	verifier, err := scramVerifier(password, rand.Reader)
	if err != nil {
		return result, err
	}
	// The verifier holds only base64 characters after a fixed prefix
	// (checked), so it is written as a literal: ALTER ROLE takes no
	// parameters.
	if !scramVerifierPattern.MatchString(verifier) {
		return result, errors.New("scram verifier has an unexpected form")
	}
	if err := transaction.Exec(ctx, "ALTER ROLE "+identifier+" PASSWORD '"+verifier+"'"); err != nil {
		return result, fmt.Errorf("set login %s password: %w", login.Name, err)
	}
	result.PasswordChanged = true
	return result, nil
}

func validLoginPassword(password []byte) error {
	if len(password) < minimumLoginPasswordLength || len(password) > maximumLoginPasswordLength {
		return ErrInvalidLoginPassword
	}
	for _, character := range password {
		if character <= ' ' || character > '~' || character == '\'' || character == '\\' {
			return ErrInvalidLoginPassword
		}
	}
	return nil
}

// scramVerifier returns PostgreSQL's stored SCRAM-SHA-256 verifier
// (RFC 5802, RFC 7677) for password with a fresh salt.
func scramVerifier(password []byte, entropy interface{ Read([]byte) (int, error) }) (string, error) {
	salt := make([]byte, scramSaltLength)
	if _, err := entropy.Read(salt); err != nil {
		return "", fmt.Errorf("draw scram salt: %w", err)
	}
	storedKey, serverKey, err := scramKeys(password, salt, scramIterations)
	if err != nil {
		return "", err
	}
	encoding := base64.StdEncoding
	return "SCRAM-SHA-256$" + strconv.Itoa(scramIterations) + ":" + encoding.EncodeToString(salt) + "$" +
		encoding.EncodeToString(storedKey) + ":" + encoding.EncodeToString(serverKey), nil
}

// scramVerifierMatches reports whether stored is a SCRAM-SHA-256 verifier
// of password.
func scramVerifierMatches(stored string, password []byte) bool {
	parts := scramVerifierPattern.FindStringSubmatch(stored)
	if parts == nil {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return false
	}
	encoding := base64.StdEncoding
	salt, saltErr := encoding.DecodeString(parts[2])
	wantStored, storedErr := encoding.DecodeString(parts[3])
	wantServer, serverErr := encoding.DecodeString(parts[4])
	if saltErr != nil || storedErr != nil || serverErr != nil {
		return false
	}
	storedKey, serverKey, err := scramKeys(password, salt, iterations)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(storedKey, wantStored) == 1 &&
		subtle.ConstantTimeCompare(serverKey, wantServer) == 1
}

func scramKeys(password, salt []byte, iterations int) (storedKey, serverKey []byte, err error) {
	salted, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, sha256.Size)
	if err != nil {
		return nil, nil, fmt.Errorf("derive scram key: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	return stored[:], hmacSHA256(salted, "Server Key"), nil
}

func hmacSHA256(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// operatorLoginNames returns the names of the operator logins.
func operatorLoginNames() []string {
	names := []string{}
	for _, login := range migrations.OperatorLogins() {
		names = append(names, login.Name)
	}
	return names
}
