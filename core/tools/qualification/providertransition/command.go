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
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

const (
	envConfirmation = "MESHTRANSIT_QUALIFICATION_CONFIRM_PROVIDER_TRANSITION"
	envEnable       = "MESHTRANSIT_QUALIFICATION_ENABLE_PROVIDER_TRANSITION"

	envPostgreSQLAddress      = "MESHTRANSIT_POSTGRES_ADDRESS"
	envPostgreSQLDatabase     = "MESHTRANSIT_POSTGRES_DATABASE"
	envPostgreSQLAdminUser    = "MESHTRANSIT_POSTGRES_ADMIN_USER"
	envPostgreSQLPasswordFile = "MESHTRANSIT_POSTGRES_ADMIN_PASSWORD_FILE"
	envPostgreSQLTrustFile    = "MESHTRANSIT_POSTGRES_CA_FILE"

	enableConfirmation = "provider-client-scope-v1"

	maximumAuditReasonBytes = 256

	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
)

var errInvalidInput = errors.New("provider transition: invalid input")

type transitionMode string

const (
	transitionModeDryRun transitionMode = "dry-run"
	transitionModeApply  transitionMode = "apply"
)

type rawOptions struct {
	deploymentID              string
	providerID                string
	clientID                  string
	actorPrincipalID          string
	expectedGeneration        int64
	expectedGenerationVersion int64
	expectedProviderVersion   int64
	expectedClientVersion     int64
	mode                      string
	auditReason               string
}

type transitionSpec struct {
	deploymentID              deployment.ID
	providerID                oidcauth.ProviderID
	clientID                  oidcauth.ClientID
	actorPrincipalID          identity.PrincipalID
	expectedGeneration        int64
	expectedGenerationVersion int64
	expectedProviderVersion   int64
	expectedClientVersion     int64
	mode                      transitionMode
	auditReason               string
}

type databaseSettings struct {
	address      string
	database     string
	user         string
	passwordFile config.SecretFile
	trustFile    config.TrustFile
}

type transitionOutput struct {
	Operation               string   `json:"operation"`
	ProviderID              string   `json:"provider_id"`
	ClientID                string   `json:"client_id"`
	PreviousGeneration      int64    `json:"previous_generation"`
	CurrentGeneration       int64    `json:"current_generation"`
	PreviousProviderVersion int64    `json:"previous_provider_version"`
	CurrentProviderVersion  int64    `json:"current_provider_version"`
	PreviousClientVersion   int64    `json:"previous_client_version"`
	CurrentClientVersion    int64    `json:"current_client_version"`
	PreviousScopes          []string `json:"previous_scopes"`
	CurrentScopes           []string `json:"current_scopes"`
	ChangeID                string   `json:"change_id,omitempty"`
	GenerationID            string   `json:"generation_id,omitempty"`
	AuditEventID            string   `json:"audit_event_id,omitempty"`
	OutboxEventID           string   `json:"outbox_event_id,omitempty"`
}

type transitionExecutor func(
	context.Context,
	transitionSpec,
	databaseSettings,
) (transitionOutput, error)

func run(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
	execute transitionExecutor,
) int {
	if ctx == nil || lookup == nil || output == nil || errorOutput == nil || execute == nil {
		return exitFailure
	}
	spec, err := parseTransitionSpec(args, lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "providertransition: invalid input")
		return exitUsage
	}
	database, err := loadDatabaseSettings(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "providertransition: invalid database configuration")
		return exitFailure
	}
	result, err := execute(ctx, spec, database)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "providertransition: transition failed")
		return exitFailure
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "providertransition: encode result failed")
		return exitFailure
	}
	return exitSuccess
}

func parseTransitionSpec(args []string, lookup config.LookupFunc) (transitionSpec, error) {
	options := rawOptions{}
	flags := flag.NewFlagSet("providertransition", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.deploymentID, "deployment-id", "", "exact Deployment public ID")
	flags.StringVar(&options.providerID, "provider-id", "", "exact identity provider public ID")
	flags.StringVar(&options.clientID, "client-id", "", "exact provider-client public ID")
	flags.StringVar(&options.actorPrincipalID, "actor-principal-id", "", "audit actor public ID")
	flags.Int64Var(&options.expectedGeneration, "expected-generation", 0, "current provider generation")
	flags.Int64Var(
		&options.expectedGenerationVersion,
		"expected-generation-version",
		0,
		"current generation row version",
	)
	flags.Int64Var(&options.expectedProviderVersion, "expected-provider-version", 0, "provider row version")
	flags.Int64Var(&options.expectedClientVersion, "expected-client-version", 0, "provider-client row version")
	flags.StringVar(&options.mode, "mode", "", "dry-run or apply")
	flags.StringVar(&options.auditReason, "audit-reason", "", "bounded operator reason")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return transitionSpec{}, errInvalidInput
	}
	return validateRawOptions(options, lookup)
}

func validateRawOptions(options rawOptions, lookup config.LookupFunc) (transitionSpec, error) {
	deploymentID, err := deployment.ParseID(options.deploymentID)
	if err != nil {
		return transitionSpec{}, errInvalidInput
	}
	providerID, err := oidcauth.ParseProviderID(options.providerID)
	if err != nil {
		return transitionSpec{}, errInvalidInput
	}
	clientID, err := oidcauth.ParseClientID(options.clientID)
	if err != nil {
		return transitionSpec{}, errInvalidInput
	}
	actorID, err := identity.ParsePrincipalID(options.actorPrincipalID)
	if err != nil || !validExpectedVersion(options.expectedGeneration) ||
		!validExpectedVersion(options.expectedGenerationVersion) ||
		!validExpectedVersion(options.expectedProviderVersion) ||
		!validExpectedVersion(options.expectedClientVersion) ||
		!validAuditReason(options.auditReason) {
		return transitionSpec{}, errInvalidInput
	}
	mode := transitionMode(options.mode)
	if mode != transitionModeDryRun && mode != transitionModeApply {
		return transitionSpec{}, errInvalidInput
	}
	expectedConfirmation := strings.Join([]string{
		deploymentID.String(),
		providerID.String(),
		clientID.String(),
	}, "/")
	confirmation, confirmed := lookup(envConfirmation)
	if !confirmed || confirmation != expectedConfirmation {
		return transitionSpec{}, errInvalidInput
	}
	if mode == transitionModeApply {
		enabled, found := lookup(envEnable)
		if !found || enabled != enableConfirmation {
			return transitionSpec{}, errInvalidInput
		}
	}
	return transitionSpec{
		deploymentID:              deploymentID,
		providerID:                providerID,
		clientID:                  clientID,
		actorPrincipalID:          actorID,
		expectedGeneration:        options.expectedGeneration,
		expectedGenerationVersion: options.expectedGenerationVersion,
		expectedProviderVersion:   options.expectedProviderVersion,
		expectedClientVersion:     options.expectedClientVersion,
		mode:                      mode,
		auditReason:               options.auditReason,
	}, nil
}

func (spec transitionSpec) isValid() bool {
	return spec.deploymentID.IsValid() && spec.providerID.IsValid() && spec.clientID.IsValid() &&
		spec.actorPrincipalID.IsValid() && validExpectedVersion(spec.expectedGeneration) &&
		validExpectedVersion(spec.expectedGenerationVersion) &&
		validExpectedVersion(spec.expectedProviderVersion) &&
		validExpectedVersion(spec.expectedClientVersion) && validAuditReason(spec.auditReason) &&
		(spec.mode == transitionModeDryRun || spec.mode == transitionModeApply)
}

func validExpectedVersion(value int64) bool { return value > 0 && value < math.MaxInt64 }

func validAuditReason(value string) bool {
	if value == "" || !utf8.ValidString(value) || len(value) > maximumAuditReasonBytes ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == 127 {
			return false
		}
	}
	return true
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
	return databaseSettings{
		address: address, database: database, user: user,
		passwordFile: passwordFile, trustFile: trustFile,
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
	if value == "" || len(value) > 128 {
		return errInvalidInput
	}
	for _, character := range value {
		if character <= ' ' || character == 127 {
			return errInvalidInput
		}
	}
	return nil
}
