package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestParseOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantError bool
	}{
		{
			name: "complete",
			args: []string{
				"-upstream-source", "/tmp/upstream",
				"-candidate-source", "/tmp/candidate",
			},
		},
		{
			name:      "missing candidate",
			args:      []string{"-upstream-source", "/tmp/upstream"},
			wantError: true,
		},
		{
			name:      "positional argument",
			args:      []string{"-upstream-source", "/tmp/upstream", "-candidate-source", "/tmp/candidate", "extra"},
			wantError: true,
		},
		{
			name:      "unknown flag",
			args:      []string{"-unknown"},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			options, err := parseOptions(test.args)
			if test.wantError {
				if !errors.Is(err, errInvalidOptions) {
					t.Fatalf("parseOptions() error = %v, want errInvalidOptions", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOptions() error = %v", err)
			}
			if options.upstreamSourcePath != "/tmp/upstream" ||
				options.candidateSourcePath != "/tmp/candidate" {
				t.Fatalf("parseOptions() = %+v", options)
			}
		})
	}
}

func TestRunWritesBoundedReport(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := run(
		t.Context(),
		[]string{"-upstream-source", "/tmp/upstream", "-candidate-source", "/tmp/candidate"},
		&output,
		&errorOutput,
		func(_ context.Context, options rawOptions) (verificationReport, error) {
			if options.candidateSourcePath != "/tmp/candidate" {
				t.Fatal("verifier received unparsed options")
			}
			return verificationReport{
				UpstreamBaseCompiled:                true,
				UpstreamAuthTimePatchRequired:       true,
				UpstreamWorkerJoinPatchRequired:     true,
				UpstreamPreparedOpenPatchRequired:   true,
				UpstreamHTTPClientMapPatchRequired:  true,
				UpstreamOIDCClientOpenPatchRequired: true,
				CandidateContractPassed:             true,
				Verified:                            true,
			}, nil
		},
	)
	if exitCode != exitSuccess || errorOutput.Len() != 0 {
		t.Fatalf("run() exit/stderr = %d/%q", exitCode, errorOutput.String())
	}
	report := verificationReport{}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !report.Verified || !report.UpstreamAuthTimePatchRequired ||
		!report.UpstreamWorkerJoinPatchRequired ||
		!report.UpstreamPreparedOpenPatchRequired ||
		!report.UpstreamHTTPClientMapPatchRequired ||
		!report.UpstreamOIDCClientOpenPatchRequired || !report.CandidateContractPassed {
		t.Fatalf("run() report = %+v", report)
	}
}

func TestRunRedactsVerificationFailure(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := run(
		t.Context(),
		[]string{"-upstream-source", "/tmp/private/upstream", "-candidate-source", "/tmp/private/candidate"},
		&output,
		&errorOutput,
		func(context.Context, rawOptions) (verificationReport, error) {
			return verificationReport{}, errors.New("/tmp/private/candidate contained private-build-data")
		},
	)
	if exitCode != exitFailure || output.Len() != 0 ||
		errorOutput.String() != "dexcompile: verification failed\n" {
		t.Fatalf("run() exit/stdout/stderr = %d/%q/%q", exitCode, output.String(), errorOutput.String())
	}
}
