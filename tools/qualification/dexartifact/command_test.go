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
		name                string
		args                []string
		preparedRootPath    string
		workspaceModulePath string
		wantError           bool
	}{
		{
			name: "complete",
			args: []string{
				"-manifest", "/tmp/manifest.json",
				"-source", "/tmp/source",
				"-binary", "/tmp/dex",
			},
		},
		{
			name: "prepare source",
			args: []string{
				"-manifest", "/tmp/manifest.json",
				"-source", "/tmp/source",
				"-binary", "/tmp/dex",
				"-prepared-root", "/tmp/prepared",
			},
			preparedRootPath: "/tmp/prepared",
		},
		{
			name: "prepare workspace",
			args: []string{
				"-manifest", "/tmp/manifest.json",
				"-source", "/tmp/source",
				"-binary", "/tmp/dex",
				"-prepared-root", "/tmp/prepared",
				"-workspace-module", "/tmp/meshcore",
			},
			preparedRootPath:    "/tmp/prepared",
			workspaceModulePath: "/tmp/meshcore",
		},
		{
			name: "workspace without preparation",
			args: []string{
				"-manifest", "/tmp/manifest.json",
				"-source", "/tmp/source",
				"-binary", "/tmp/dex",
				"-workspace-module", "/tmp/meshcore",
			},
			wantError: true,
		},
		{
			name:      "missing manifest",
			args:      []string{"-source", "/tmp/source", "-binary", "/tmp/dex"},
			wantError: true,
		},
		{
			name:      "positional argument",
			args:      []string{"-manifest", "/tmp/manifest.json", "-source", "/tmp/source", "-binary", "/tmp/dex", "extra"},
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
			if options.manifestPath != "/tmp/manifest.json" || options.sourcePath != "/tmp/source" ||
				options.binaryPath != "/tmp/dex" || options.preparedRootPath != test.preparedRootPath ||
				options.workspaceModulePath != test.workspaceModulePath {
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
		[]string{"-manifest", "/tmp/manifest.json", "-source", "/tmp/source", "-binary", "/tmp/dex"},
		&output,
		&errorOutput,
		func(_ context.Context, options rawOptions) (verificationReport, error) {
			if options.sourcePath != "/tmp/source" {
				t.Fatal("verifier received unparsed options")
			}
			return verificationReport{
				SchemaVersion:         manifestSchemaVersion,
				UpstreamVersion:       "v2.45.1",
				UpstreamCommit:        testCommit,
				UpstreamModuleVersion: "v0.0.0-20260303133905-11d2eeb52b42",
				PatchCount:            2,
				SourceTreeSHA256:      testDigestA,
				BinarySHA256:          testDigestB,
				Verified:              true,
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
	if !report.Verified || report.PatchCount != 2 || report.UpstreamCommit != testCommit {
		t.Fatalf("run() report = %+v", report)
	}
}

func TestRunRedactsVerificationFailure(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := run(
		t.Context(),
		[]string{"-manifest", "/tmp/secret/manifest.json", "-source", "/tmp/source", "-binary", "/tmp/dex"},
		&output,
		&errorOutput,
		func(context.Context, rawOptions) (verificationReport, error) {
			return verificationReport{}, errors.New("/tmp/secret/manifest.json contained private-build-data")
		},
	)
	if exitCode != exitFailure || output.Len() != 0 ||
		errorOutput.String() != "dexartifact: verification failed\n" {
		t.Fatalf("run() exit/stdout/stderr = %d/%q/%q", exitCode, output.String(), errorOutput.String())
	}
}
