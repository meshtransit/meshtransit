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
	exitSuccess        = 0
	exitFailure        = 1
	exitUsage          = 2
	compilationTimeout = 10 * time.Minute
)

var errInvalidOptions = errors.New("dex compile verifier: invalid options")

type rawOptions struct {
	upstreamSourcePath  string
	candidateSourcePath string
}

type verificationReport struct {
	UpstreamBaseCompiled                bool `json:"upstream_base_compiled"`
	UpstreamAuthTimePatchRequired       bool `json:"upstream_auth_time_patch_required"`
	UpstreamWorkerJoinPatchRequired     bool `json:"upstream_worker_join_patch_required"`
	UpstreamPreparedOpenPatchRequired   bool `json:"upstream_prepared_open_patch_required"`
	UpstreamHTTPClientMapPatchRequired  bool `json:"upstream_http_client_map_patch_required"`
	UpstreamOIDCClientOpenPatchRequired bool `json:"upstream_oidc_client_open_patch_required"`
	CandidateContractPassed             bool `json:"candidate_contract_passed"`
	Verified                            bool `json:"verified"`
}

type contractVerifier func(context.Context, rawOptions) (verificationReport, error)

func run(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
	verify contractVerifier,
) int {
	if ctx == nil || output == nil || errorOutput == nil || verify == nil {
		return exitFailure
	}

	options, err := parseOptions(args)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "dexcompile: invalid input")
		return exitUsage
	}
	compilationContext, cancel := context.WithTimeout(ctx, compilationTimeout)
	defer cancel()

	report, err := verify(compilationContext, options)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, "dexcompile: verification failed")
		return exitFailure
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "dexcompile: encode result failed")
		return exitFailure
	}
	return exitSuccess
}

func parseOptions(args []string) (rawOptions, error) {
	options := rawOptions{}
	flags := flag.NewFlagSet("dexcompile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.upstreamSourcePath, "upstream-source", "", "absolute unmodified Dex source path")
	flags.StringVar(&options.candidateSourcePath, "candidate-source", "", "absolute prepared Dex source path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		options.upstreamSourcePath == "" || options.candidateSourcePath == "" {
		return rawOptions{}, errInvalidOptions
	}
	return options, nil
}
