package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

const (
	envConfirmation = "MESHTRANSIT_QUALIFICATION_CONFIRM_IDENTITY_SUBJECT_TRANSITION"
	envEnable       = "MESHTRANSIT_QUALIFICATION_ENABLE_IDENTITY_SUBJECT_TRANSITION"

	envPostgreSQLAddress      = "MESHTRANSIT_POSTGRES_ADDRESS"
	envPostgreSQLDatabase     = "MESHTRANSIT_POSTGRES_DATABASE"
	envPostgreSQLAdminUser    = "MESHTRANSIT_POSTGRES_ADMIN_USER"
	envPostgreSQLPasswordFile = "MESHTRANSIT_POSTGRES_ADMIN_PASSWORD_FILE"
	envPostgreSQLTrustFile    = "MESHTRANSIT_POSTGRES_CA_FILE"

	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2

	applyEnableConfirmation = "identity-subject-transition-apply-v1"
)

var errInvalidInput = errors.New("identity subject transition: invalid input")

type rawOptions struct {
	manifestPath         string
	expectedManifestHash string
	sourceKeyPath        string
	targetKeyPath        string
	mode                 string
}

type transitionMode string

const (
	transitionModePlan  transitionMode = "plan"
	transitionModeApply transitionMode = "apply"
)

type databaseSettings struct {
	address      string
	database     string
	user         string
	passwordFile config.SecretFile
	trustFile    config.TrustFile
}

type planOutput struct {
	SchemaVersion            string `json:"schema_version"`
	Operation                string `json:"operation"`
	MigrationID              string `json:"migration_id"`
	ManifestSHA256           string `json:"manifest_sha256"`
	DeploymentID             string `json:"deployment_id"`
	SourceProviderID         string `json:"source_provider_id"`
	TargetProviderID         string `json:"target_provider_id"`
	MappingCount             int    `json:"mapping_count"`
	ActiveSourceSubjectCount int64  `json:"active_source_subject_count"`
	ActiveSessionCount       int64  `json:"active_session_count"`
	OpenAuthTransactionCount int64  `json:"open_auth_transaction_count"`
	ChangeID                 string `json:"change_id,omitempty"`
	AuditEventID             string `json:"audit_event_id,omitempty"`
	OutboxEventID            string `json:"outbox_event_id,omitempty"`
	SourceProviderVersion    int64  `json:"source_provider_version,omitempty"`
}

type planExecutor func(context.Context, planSpec, databaseSettings) (planOutput, error)

func run(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
	execute planExecutor,
) int {
	if ctx == nil || lookup == nil || output == nil || errorOutput == nil || execute == nil {
		return exitFailure
	}
	options, err := parseOptions(args)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "identitysubjecttransition: invalid input")
		return exitUsage
	}
	spec, err := loadPlanSpec(ctx, options, lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "identitysubjecttransition: invalid plan")
		return exitUsage
	}
	defer spec.clear()
	database, err := loadDatabaseSettings(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "identitysubjecttransition: invalid database configuration")
		return exitFailure
	}
	result, err := execute(ctx, spec, database)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "identitysubjecttransition: operation failed")
		return exitFailure
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "identitysubjecttransition: encode result failed")
		return exitFailure
	}
	return exitSuccess
}

func parseOptions(args []string) (rawOptions, error) {
	options := rawOptions{}
	flags := flag.NewFlagSet("identitysubjecttransition", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.manifestPath, "manifest", "", "absolute protected transition manifest")
	flags.StringVar(&options.expectedManifestHash, "expected-manifest-sha256", "", "exact manifest SHA-256")
	flags.StringVar(&options.sourceKeyPath, "source-key-file", "", "protected source subject key")
	flags.StringVar(&options.targetKeyPath, "target-key-file", "", "protected target subject key")
	flags.StringVar(&options.mode, "mode", string(transitionModePlan), "plan or apply")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		options.manifestPath == "" || options.sourceKeyPath == "" || options.targetKeyPath == "" ||
		!validSHA256(options.expectedManifestHash) ||
		transitionMode(options.mode) != transitionModePlan &&
			transitionMode(options.mode) != transitionModeApply {
		return rawOptions{}, errInvalidInput
	}
	return options, nil
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
