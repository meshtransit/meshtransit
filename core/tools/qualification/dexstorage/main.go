//go:build dexbroker && qualification

// Command dexstorage owns the migration/runtime-open boundary used by the
// embedded identity-broker upgrade qualification.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"meshtransit.net/core/internal/adapter/dexbroker"
	"meshtransit.net/core/internal/platform/config"
)

const (
	operationTimeout = 30 * time.Second
	cleanupTimeout   = 5 * time.Second
)

var errInvalidInput = errors.New("identity broker storage qualification: invalid input")

type options struct {
	mode         string
	address      string
	database     string
	user         string
	passwordFile string
	caFile       string
}

type output struct {
	SchemaVersion string `json:"schema_version"`
	Operation     string `json:"operation"`
	Status        string `json:"status"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if ctx == nil || stdout == nil || stderr == nil {
		return errInvalidInput
	}
	settings, err := parseOptions(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "dexstorage: invalid input")
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := qualifyStorage(operationCtx, settings); err != nil {
		_, _ = fmt.Fprintln(stderr, "dexstorage: operation failed")
		return err
	}
	if err := json.NewEncoder(stdout).Encode(output{
		SchemaVersion: "meshtransit.identity-broker-storage-qualification/v1",
		Operation:     settings.mode,
		Status:        "passed",
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, "dexstorage: output failed")
		return errors.New("encode identity broker storage result")
	}
	return nil
}

func parseOptions(args []string) (options, error) {
	settings := options{}
	flags := flag.NewFlagSet("dexstorage", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&settings.mode, "mode", "", "migrate or verify")
	flags.StringVar(&settings.address, "address", "", "PostgreSQL host and port")
	flags.StringVar(&settings.database, "database", "", "PostgreSQL database")
	flags.StringVar(&settings.user, "user", "", "PostgreSQL role")
	flags.StringVar(&settings.passwordFile, "password-file", "", "protected password file")
	flags.StringVar(&settings.caFile, "ca-file", "", "PostgreSQL CA bundle")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		settings.mode != "migrate" && settings.mode != "verify" ||
		!validIdentifier(settings.database) || !validIdentifier(settings.user) {
		return options{}, errInvalidInput
	}
	host, portValue, err := net.SplitHostPort(settings.address)
	if err != nil || host == "" {
		return options{}, errInvalidInput
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return options{}, errInvalidInput
	}
	_, passwordErr := config.NewSecretFile(settings.passwordFile)
	_, trustErr := config.NewTrustFile(settings.caFile)
	if passwordErr != nil || trustErr != nil {
		return options{}, errInvalidInput
	}
	return settings, nil
}

func qualifyStorage(ctx context.Context, settings options) error {
	host, portValue, err := net.SplitHostPort(settings.address)
	if err != nil {
		return errInvalidInput
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return errInvalidInput
	}
	passwordFile, err := config.NewSecretFile(settings.passwordFile)
	if err != nil {
		return errInvalidInput
	}
	trustFile, err := config.NewTrustFile(settings.caFile)
	if err != nil {
		return errInvalidInput
	}
	options := dexbroker.PostgreSQLResourceOptions{
		Address:               net.JoinHostPort(host, portValue),
		Database:              settings.database,
		User:                  settings.user,
		PasswordFile:          passwordFile,
		CAFile:                trustFile,
		MaxOpenConnections:    2,
		MaxIdleConnections:    1,
		ConnectTimeout:        5 * time.Second,
		MaxConnectionLifetime: time.Minute,
	}
	logger := slog.New(slog.DiscardHandler)
	if settings.mode == "migrate" {
		if err := dexbroker.PreparePostgreSQLSchemaForQualification(ctx, options, logger); err != nil {
			return errors.New("migrate identity broker storage")
		}
		return nil
	}
	resource, err := dexbroker.OpenPostgreSQLResource(ctx, options, logger)
	if err != nil {
		return errors.New("verify prepared identity broker storage")
	}
	if err := resource.Check(ctx); err != nil {
		_ = shutdownStorage(ctx, resource)
		return errors.New("check prepared identity broker storage")
	}
	if err := shutdownStorage(ctx, resource); err != nil {
		return errors.New("close prepared identity broker storage")
	}
	return nil
}

func shutdownStorage(ctx context.Context, resource *dexbroker.PostgreSQLResource) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	return resource.Shutdown(cleanupCtx)
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' && index > 0 ||
			character == '_' && index > 0 {
			continue
		}
		return false
	}
	return true
}
