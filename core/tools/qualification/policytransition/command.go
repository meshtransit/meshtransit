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

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	policypublication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/config"
)

const (
	envConfirmation           = "MESHTRANSIT_QUALIFICATION_CONFIRM_NETWORK_ID"
	envPostgreSQLAddress      = "MESHTRANSIT_POSTGRES_ADDRESS"
	envPostgreSQLDatabase     = "MESHTRANSIT_POSTGRES_DATABASE"
	envPostgreSQLUser         = "MESHTRANSIT_POSTGRES_RUNTIME_USER"
	envPostgreSQLPasswordFile = "MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE"
	envPostgreSQLTrustFile    = "MESHTRANSIT_POSTGRES_CA_FILE"

	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
)

var errInvalidInput = errors.New("policy transition: invalid input")

type transitionMode string

const (
	transitionModeDeny              transitionMode = "deny"
	transitionModeBidirectionalICMP transitionMode = "bidirectional-icmp"
)

type rawOptions struct {
	workspaceID        string
	networkID          string
	actorPrincipalID   string
	basePolicyRevision int64
	mode               string
	sourceNodeID       string
	destinationNodeID  string
	auditReason        string
}

type transitionSpec struct {
	scope              network.Scope
	actorPrincipalID   identity.PrincipalID
	basePolicyRevision int64
	mode               transitionMode
	sourceNodeID       node.ID
	destinationNodeID  node.ID
	auditReason        policypublication.AuditReason
}

type databaseSettings struct {
	address      string
	database     string
	user         string
	passwordFile config.SecretFile
	trustFile    config.TrustFile
}

type transitionOutput struct {
	Mode            string `json:"mode"`
	RuleCount       int    `json:"rule_count"`
	PolicyRevision  int64  `json:"policy_revision"`
	NetworkRevision int64  `json:"network_revision"`
	ReleaseID       string `json:"release_id"`
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
		_, _ = fmt.Fprintln(errorOutput, "policytransition: invalid input")
		return exitUsage
	}
	database, err := loadDatabaseSettings(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "policytransition: invalid database configuration")
		return exitFailure
	}

	result, err := execute(ctx, spec, database)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "policytransition: publication failed")
		return exitFailure
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "policytransition: encode result failed")
		return exitFailure
	}
	return exitSuccess
}

func parseTransitionSpec(
	args []string,
	lookup config.LookupFunc,
) (transitionSpec, error) {
	options := rawOptions{}
	flags := flag.NewFlagSet("policytransition", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.workspaceID, "workspace-id", "", "exact Workspace public ID")
	flags.StringVar(&options.networkID, "network-id", "", "exact Network public ID")
	flags.StringVar(&options.actorPrincipalID, "actor-principal-id", "", "audit actor public ID")
	flags.Int64Var(&options.basePolicyRevision, "base-policy-revision", 0, "current policy revision")
	flags.StringVar(&options.mode, "mode", "", "deny or bidirectional-icmp")
	flags.StringVar(&options.sourceNodeID, "source-node-id", "", "first Device public ID")
	flags.StringVar(&options.destinationNodeID, "destination-node-id", "", "second Device public ID")
	flags.StringVar(&options.auditReason, "audit-reason", "", "bounded audit reason")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return transitionSpec{}, errInvalidInput
	}
	return validateRawOptions(options, lookup)
}

func validateRawOptions(options rawOptions, lookup config.LookupFunc) (transitionSpec, error) {
	workspaceID, err := workspace.ParseID(options.workspaceID)
	if err != nil {
		return transitionSpec{}, errInvalidInput
	}
	networkID, err := network.ParseID(options.networkID)
	if err != nil {
		return transitionSpec{}, errInvalidInput
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return transitionSpec{}, errInvalidInput
	}
	actorID, err := identity.ParsePrincipalID(options.actorPrincipalID)
	if err != nil {
		return transitionSpec{}, errInvalidInput
	}
	reason, err := policypublication.NewAuditReason(options.auditReason)
	if err != nil || options.basePolicyRevision <= 0 || options.basePolicyRevision == math.MaxInt64 {
		return transitionSpec{}, errInvalidInput
	}
	confirmation, confirmed := lookup(envConfirmation)
	if !confirmed || confirmation != networkID.String() {
		return transitionSpec{}, errInvalidInput
	}

	spec := transitionSpec{
		scope:              scope,
		actorPrincipalID:   actorID,
		basePolicyRevision: options.basePolicyRevision,
		mode:               transitionMode(options.mode),
		auditReason:        reason,
	}
	switch spec.mode {
	case transitionModeDeny:
		if options.sourceNodeID != "" || options.destinationNodeID != "" {
			return transitionSpec{}, errInvalidInput
		}
	case transitionModeBidirectionalICMP:
		sourceID, parseErr := node.ParseID(options.sourceNodeID)
		if parseErr != nil {
			return transitionSpec{}, errInvalidInput
		}
		destinationID, parseErr := node.ParseID(options.destinationNodeID)
		if parseErr != nil || sourceID == destinationID {
			return transitionSpec{}, errInvalidInput
		}
		spec.sourceNodeID = sourceID
		spec.destinationNodeID = destinationID
	default:
		return transitionSpec{}, errInvalidInput
	}
	return spec, nil
}

func (spec transitionSpec) isValid() bool {
	baseIsValid := spec.basePolicyRevision > 0 && spec.basePolicyRevision < math.MaxInt64
	if !spec.scope.IsValid() || !spec.actorPrincipalID.IsValid() || !baseIsValid ||
		!spec.auditReason.IsValid() {
		return false
	}
	switch spec.mode {
	case transitionModeDeny:
		return !spec.sourceNodeID.IsValid() && !spec.destinationNodeID.IsValid()
	case transitionModeBidirectionalICMP:
		return spec.sourceNodeID.IsValid() && spec.destinationNodeID.IsValid() &&
			spec.sourceNodeID != spec.destinationNodeID
	default:
		return false
	}
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
	user, err := requiredEnvironment(lookup, envPostgreSQLUser, validateIdentifier)
	if err != nil {
		return databaseSettings{}, err
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
		address:      address,
		database:     database,
		user:         user,
		passwordFile: passwordFile,
		trustFile:    trustFile,
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
