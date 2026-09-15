package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	envConfirmation = "MESHTRANSIT_QUALIFICATION_CONFIRM_AUTH_SCOPE"
	envEnable       = "MESHTRANSIT_QUALIFICATION_ENABLE_SYNTHETIC_IDENTITY"

	envPostgreSQLAddress      = "MESHTRANSIT_POSTGRES_ADDRESS"
	envPostgreSQLDatabase     = "MESHTRANSIT_POSTGRES_DATABASE"
	envPostgreSQLAdminUser    = "MESHTRANSIT_POSTGRES_ADMIN_USER"
	envPostgreSQLPasswordFile = "MESHTRANSIT_POSTGRES_ADMIN_PASSWORD_FILE"
	envPostgreSQLTrustFile    = "MESHTRANSIT_POSTGRES_CA_FILE"

	envSessionDigestKeyID   = "MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID"
	envSessionDigestKeyFile = "MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE"

	enableConfirmation = "qualification-only"

	minimumExpiry = time.Minute
	maximumExpiry = 15 * time.Minute

	maximumAuditReasonBytes = 256
	maximumPathBytes        = 4096

	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
)

var errInvalidInput = errors.New("management session qualification: invalid input")

type rawOptions struct {
	deploymentID string
	workspaceID  string
	networkID    string
	principalID  string
	tokenOutput  string
	expiresIn    time.Duration
	auditReason  string
}

type seedSpec struct {
	deploymentID deployment.ID
	scope        network.Scope
	principalID  identity.PrincipalID
	tokenOutput  string
	expiresIn    time.Duration
	auditReason  string
}

type databaseSettings struct {
	address       string
	database      string
	user          string
	passwordFile  config.SecretFile
	trustFile     config.TrustFile
	digestKeyID   accountsession.DigestKeyID
	digestKeyFile config.SecretFile
}

type seedOutput struct {
	SessionID         string    `json:"session_id"`
	IdentitySubjectID string    `json:"identity_subject_id"`
	MembershipID      string    `json:"membership_id"`
	RoleDefinitionID  string    `json:"role_definition_id"`
	RoleBindingID     string    `json:"role_binding_id"`
	ExpiresAt         time.Time `json:"expires_at"`
	Permission        string    `json:"permission"`
}

type seedExecutor func(
	context.Context,
	seedSpec,
	databaseSettings,
	io.Reader,
) (seedOutput, error)

func run(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
	entropy io.Reader,
	execute seedExecutor,
) int {
	if ctx == nil || lookup == nil || output == nil || errorOutput == nil ||
		entropy == nil || execute == nil {
		return exitFailure
	}

	spec, err := parseSeedSpec(args, lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "managementsession: invalid input")
		return exitUsage
	}
	database, err := loadDatabaseSettings(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "managementsession: invalid database configuration")
		return exitFailure
	}

	result, err := execute(ctx, spec, database, entropy)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "managementsession: seed failed")
		return exitFailure
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "managementsession: encode result failed")
		return exitFailure
	}
	return exitSuccess
}

func parseSeedSpec(args []string, lookup config.LookupFunc) (seedSpec, error) {
	options := rawOptions{}
	flags := flag.NewFlagSet("managementsession", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.deploymentID, "deployment-id", "", "exact Deployment public ID")
	flags.StringVar(&options.workspaceID, "workspace-id", "", "exact Workspace public ID")
	flags.StringVar(&options.networkID, "network-id", "", "exact Network public ID")
	flags.StringVar(&options.principalID, "principal-id", "", "existing Account Principal public ID")
	flags.StringVar(&options.tokenOutput, "token-output-file", "", "new absolute bearer-token file")
	flags.DurationVar(&options.expiresIn, "expires-in", 0, "short fixture lifetime")
	flags.StringVar(&options.auditReason, "audit-reason", "", "bounded qualification reason")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return seedSpec{}, errInvalidInput
	}
	return validateRawOptions(options, lookup)
}

func validateRawOptions(options rawOptions, lookup config.LookupFunc) (seedSpec, error) {
	deploymentID, err := deployment.ParseID(options.deploymentID)
	if err != nil {
		return seedSpec{}, errInvalidInput
	}
	workspaceID, err := workspace.ParseID(options.workspaceID)
	if err != nil {
		return seedSpec{}, errInvalidInput
	}
	networkID, err := network.ParseID(options.networkID)
	if err != nil {
		return seedSpec{}, errInvalidInput
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return seedSpec{}, errInvalidInput
	}
	principalID, err := identity.ParsePrincipalID(options.principalID)
	if err != nil || !validTokenOutputPath(options.tokenOutput) ||
		options.expiresIn < minimumExpiry || options.expiresIn > maximumExpiry ||
		options.expiresIn%time.Second != 0 ||
		!validAuditReason(options.auditReason) {
		return seedSpec{}, errInvalidInput
	}

	expectedConfirmation := strings.Join([]string{
		deploymentID.String(),
		workspaceID.String(),
		networkID.String(),
		principalID.String(),
	}, "/")
	confirmation, confirmed := lookup(envConfirmation)
	enabled, enableFound := lookup(envEnable)
	if !confirmed || confirmation != expectedConfirmation || !enableFound ||
		enabled != enableConfirmation {
		return seedSpec{}, errInvalidInput
	}

	return seedSpec{
		deploymentID: deploymentID,
		scope:        scope,
		principalID:  principalID,
		tokenOutput:  options.tokenOutput,
		expiresIn:    options.expiresIn,
		auditReason:  options.auditReason,
	}, nil
}

func (spec seedSpec) isValid() bool {
	return spec.deploymentID.IsValid() && spec.scope.IsValid() &&
		spec.principalID.IsValid() && validTokenOutputPath(spec.tokenOutput) &&
		spec.expiresIn >= minimumExpiry && spec.expiresIn <= maximumExpiry &&
		spec.expiresIn%time.Second == 0 &&
		validAuditReason(spec.auditReason)
}

func loadDatabaseSettings(lookup config.LookupFunc) (databaseSettings, error) {
	address, err := requiredEnvironment(lookup, envPostgreSQLAddress, validateAddress)
	if err != nil {
		return databaseSettings{}, err
	}
	database, err := requiredEnvironment(lookup, envPostgreSQLDatabase, validateIdentifier)
	if err != nil {
		return databaseSettings{}, err
	}
	user, err := requiredEnvironment(lookup, envPostgreSQLAdminUser, validateIdentifier)
	if err != nil || user == "mesh_runtime" || user == "mesh_worker" || user == "mesh_migrator" {
		return databaseSettings{}, errInvalidInput
	}
	passwordPath, err := requiredEnvironment(lookup, envPostgreSQLPasswordFile, nil)
	if err != nil {
		return databaseSettings{}, err
	}
	passwordFile, err := config.NewSecretFile(passwordPath)
	if err != nil {
		return databaseSettings{}, errInvalidInput
	}
	trustPath, err := requiredEnvironment(lookup, envPostgreSQLTrustFile, nil)
	if err != nil {
		return databaseSettings{}, err
	}
	trustFile, err := config.NewTrustFile(trustPath)
	if err != nil {
		return databaseSettings{}, errInvalidInput
	}
	digestKeyIDValue, err := requiredEnvironment(lookup, envSessionDigestKeyID, validateIdentifier)
	if err != nil {
		return databaseSettings{}, err
	}
	digestKeyID, err := accountsession.NewDigestKeyID(digestKeyIDValue)
	if err != nil {
		return databaseSettings{}, errInvalidInput
	}
	digestKeyPath, err := requiredEnvironment(lookup, envSessionDigestKeyFile, nil)
	if err != nil {
		return databaseSettings{}, err
	}
	digestKeyFile, err := config.NewSecretFile(digestKeyPath)
	if err != nil {
		return databaseSettings{}, errInvalidInput
	}
	return databaseSettings{
		address:       address,
		database:      database,
		user:          user,
		passwordFile:  passwordFile,
		trustFile:     trustFile,
		digestKeyID:   digestKeyID,
		digestKeyFile: digestKeyFile,
	}, nil
}

func requiredEnvironment(
	lookup config.LookupFunc,
	key string,
	validate func(string) error,
) (string, error) {
	value, found := lookup(key)
	if !found || value == "" || strings.TrimSpace(value) != value {
		return "", errInvalidInput
	}
	if validate != nil {
		if err := validate(value); err != nil {
			return "", errInvalidInput
		}
	}
	return value, nil
}

func validateAddress(value string) error {
	host, portValue, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errInvalidInput
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return errInvalidInput
	}
	return nil
}

func validateIdentifier(value string) error {
	if len(value) > 128 {
		return errInvalidInput
	}
	for _, character := range value {
		if character <= ' ' || character == 127 {
			return errInvalidInput
		}
	}
	return nil
}

func validTokenOutputPath(value string) bool {
	return value != "" && len(value) <= maximumPathBytes && filepath.IsAbs(value) &&
		filepath.Clean(value) == value && value != string(filepath.Separator) &&
		filepath.Base(value) != "." && filepath.Base(value) != string(filepath.Separator)
}

func validAuditReason(value string) bool {
	return value != "" && len(value) <= maximumAuditReasonBytes &&
		strings.TrimSpace(value) == value && utf8.ValidString(value)
}

func validPositiveInt64(value int64) bool { return value > 0 && value < math.MaxInt64 }
