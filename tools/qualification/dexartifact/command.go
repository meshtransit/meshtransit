package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

const (
	exitSuccess         = 0
	exitFailure         = 1
	exitUsage           = 2
	verificationTimeout = 5 * time.Minute
)

var errInvalidOptions = errors.New("dex artifact verifier: invalid options")

type rawOptions struct {
	manifestPath        string
	sourcePath          string
	binaryPath          string
	preparedRootPath    string
	workspaceModulePath string
}

type verificationReport struct {
	SchemaVersion         string `json:"schema_version"`
	UpstreamVersion       string `json:"upstream_version"`
	UpstreamCommit        string `json:"upstream_commit"`
	UpstreamModuleVersion string `json:"upstream_module_version"`
	PatchCount            int    `json:"patch_count"`
	SourceTreeSHA256      string `json:"source_tree_sha256"`
	BinarySHA256          string `json:"binary_sha256"`
	SourcePrepared        bool   `json:"source_prepared,omitempty"`
	WorkspacePrepared     bool   `json:"workspace_prepared,omitempty"`
	Verified              bool   `json:"verified"`
}

type artifactVerifier func(context.Context, rawOptions) (verificationReport, error)

func run(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
	verify artifactVerifier,
) int {
	if ctx == nil || output == nil || errorOutput == nil || verify == nil {
		return exitFailure
	}

	options, err := parseOptions(args)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "dexartifact: invalid input")
		return exitUsage
	}
	verificationContext, cancel := context.WithTimeout(ctx, verificationTimeout)
	defer cancel()
	report, err := verify(verificationContext, options)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "dexartifact: verification failed")
		return exitFailure
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "dexartifact: encode result failed")
		return exitFailure
	}
	return exitSuccess
}

func parseOptions(args []string) (rawOptions, error) {
	options := rawOptions{}
	flags := flag.NewFlagSet("dexartifact", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.manifestPath, "manifest", "", "absolute artifact manifest path")
	flags.StringVar(&options.sourcePath, "source", "", "absolute local upstream Git checkout")
	flags.StringVar(&options.binaryPath, "binary", "", "absolute built Dex binary path")
	flags.StringVar(&options.preparedRootPath, "prepared-root", "", "optional absolute empty output directory")
	flags.StringVar(&options.workspaceModulePath, "workspace-module", "", "optional absolute MeshCore module path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		options.manifestPath == "" || options.sourcePath == "" || options.binaryPath == "" ||
		(options.workspaceModulePath != "" && options.preparedRootPath == "") {
		return rawOptions{}, errInvalidOptions
	}
	return options, nil
}
