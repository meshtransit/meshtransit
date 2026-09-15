package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	envConfirmation = "MESHTRANSIT_QUALIFICATION_CONFIRM_ENROLLMENT_SCOPE"
	envEnable       = "MESHTRANSIT_QUALIFICATION_ENABLE_ENROLLMENT_ISSUE"

	envPostgreSQLAddress      = "MESHTRANSIT_POSTGRES_ADDRESS"
	envPostgreSQLDatabase     = "MESHTRANSIT_POSTGRES_DATABASE"
	envPostgreSQLAdminUser    = "MESHTRANSIT_POSTGRES_ADMIN_USER"
	envPostgreSQLPasswordFile = "MESHTRANSIT_POSTGRES_ADMIN_PASSWORD_FILE"
	envPostgreSQLTrustFile    = "MESHTRANSIT_POSTGRES_CA_FILE"

	envEnrollmentDigestKeyID   = "MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID"
	envEnrollmentDigestKeyFile = "MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE"

	enableConfirmation = "qualification-only"

	minimumExpiry = time.Minute
	maximumExpiry = 15 * time.Minute

	maximumAuditReasonBytes = 256
	maximumPathBytes        = 4096

	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
)

var errInvalidInput = errors.New("enrollment credential qualification: invalid input")

type rawOptions struct {
	deploymentID    string
	workspaceID     string
	networkID       string
	profileID       string
	issuerPrincipal string
	tokenOutput     string
	expiresIn       time.Duration
	auditReason     string
}

type issueSpec struct {
	deploymentID    deployment.ID
	scope           network.Scope
	profileID       enrollment.ProfileID
	issuerPrincipal identity.PrincipalID
	tokenOutput     string
	expiresIn       time.Duration
	auditReason     string
}

type databaseSettings struct {
	address       string
	database      string
	user          string
	passwordFile  config.SecretFile
	trustFile     config.TrustFile
	digestKeyID   enrollment.DigestKeyID
	digestKeyFile config.SecretFile
}

type issueOutput struct {
	CredentialID string    `json:"credential_id"`
	ProfileID    string    `json:"profile_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaximumUses  int64     `json:"maximum_uses"`
}

type issueExecutor func(
	context.Context,
	issueSpec,
	databaseSettings,
	io.Reader,
) (issueOutput, error)

func run(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
	entropy io.Reader,
	execute issueExecutor,
) int {
	if ctx == nil || lookup == nil || output == nil || errorOutput == nil ||
		entropy == nil || execute == nil {
		return exitFailure
	}

	spec, err := parseIssueSpec(args, lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "enrollmentcredential: invalid input")
		return exitUsage
	}
	database, err := loadDatabaseSettings(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "enrollmentcredential: invalid database configuration")
		return exitFailure
	}

	result, err := execute(ctx, spec, database, entropy)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "enrollmentcredential: issue failed")
		return exitFailure
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "enrollmentcredential: encode result failed")
		return exitFailure
	}
	return exitSuccess
}

func parseIssueSpec(args []string, lookup config.LookupFunc) (issueSpec, error) {
	options := rawOptions{}
	flags := flag.NewFlagSet("enrollmentcredential", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.deploymentID, "deployment-id", "", "exact Deployment public ID")
	flags.StringVar(&options.workspaceID, "workspace-id", "", "exact Workspace public ID")
	flags.StringVar(&options.networkID, "network-id", "", "exact Network public ID")
	flags.StringVar(&options.profileID, "profile-id", "", "exact Enrollment Profile public ID")
	flags.StringVar(
		&options.issuerPrincipal,
		"issuer-principal-id",
		"",
		"existing issuer Principal public ID",
	)
	flags.StringVar(&options.tokenOutput, "token-output-file", "", "new absolute credential file")
	flags.DurationVar(&options.expiresIn, "expires-in", 0, "short credential lifetime")
	flags.StringVar(&options.auditReason, "audit-reason", "", "bounded qualification reason")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return issueSpec{}, errInvalidInput
	}
	return validateRawOptions(options, lookup)
}

func validateRawOptions(options rawOptions, lookup config.LookupFunc) (issueSpec, error) {
	deploymentID, err := deployment.ParseID(options.deploymentID)
	if err != nil {
		return issueSpec{}, errInvalidInput
	}
	workspaceID, err := workspace.ParseID(options.workspaceID)
	if err != nil {
		return issueSpec{}, errInvalidInput
	}
	networkID, err := network.ParseID(options.networkID)
	if err != nil {
		return issueSpec{}, errInvalidInput
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return issueSpec{}, errInvalidInput
	}
	profileID, err := enrollment.ParseProfileID(options.profileID)
	if err != nil {
		return issueSpec{}, errInvalidInput
	}
	issuerPrincipal, err := identity.ParsePrincipalID(options.issuerPrincipal)
	if err != nil || !validTokenOutputPath(options.tokenOutput) ||
		options.expiresIn < minimumExpiry || options.expiresIn > maximumExpiry ||
		options.expiresIn%time.Second != 0 || !validAuditReason(options.auditReason) {
		return issueSpec{}, errInvalidInput
	}

	expectedConfirmation := strings.Join([]string{
		deploymentID.String(),
		workspaceID.String(),
		networkID.String(),
		profileID.String(),
		issuerPrincipal.String(),
	}, "/")
	confirmation, confirmed := lookup(envConfirmation)
	enabled, enableFound := lookup(envEnable)
	if !confirmed || confirmation != expectedConfirmation || !enableFound ||
		enabled != enableConfirmation {
		return issueSpec{}, errInvalidInput
	}

	return issueSpec{
		deploymentID:    deploymentID,
		scope:           scope,
		profileID:       profileID,
		issuerPrincipal: issuerPrincipal,
		tokenOutput:     options.tokenOutput,
		expiresIn:       options.expiresIn,
		auditReason:     options.auditReason,
	}, nil
}

func (spec issueSpec) isValid() bool {
	return spec.deploymentID.IsValid() && spec.scope.IsValid() &&
		spec.profileID.IsValid() && spec.issuerPrincipal.IsValid() &&
		validTokenOutputPath(spec.tokenOutput) &&
		spec.expiresIn >= minimumExpiry && spec.expiresIn <= maximumExpiry &&
		spec.expiresIn%time.Second == 0 && validAuditReason(spec.auditReason)
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
	digestKeyIDValue, err := requiredEnvironment(lookup, envEnrollmentDigestKeyID, validateIdentifier)
	if err != nil {
		return databaseSettings{}, err
	}
	digestKeyID, err := enrollment.NewDigestKeyID(digestKeyIDValue)
	if err != nil {
		return databaseSettings{}, errInvalidInput
	}
	digestKeyPath, err := requiredEnvironment(lookup, envEnrollmentDigestKeyFile, nil)
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

func validPositiveInt64(value int64) bool { return value > 0 }
