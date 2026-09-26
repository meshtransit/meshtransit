package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestVerifyContracts(t *testing.T) {
	t.Parallel()

	sources := sourceSet{upstream: "/upstream", candidate: "/candidate"}
	var requests []compileRequest
	report, err := verifyContracts(t.Context(), sources, func(
		_ context.Context,
		request compileRequest,
	) (compileResult, error) {
		requests = append(requests, request)
		switch request {
		case compileRequest{sourcePath: sources.upstream}:
			return compileResult{compiled: true}, nil
		case compileRequest{sourcePath: sources.upstream, requireAuthTime: true}:
			return compileResult{diagnostic: "contract.go: unknown field AuthTime in struct literal"}, nil
		case compileRequest{sourcePath: sources.upstream, requireServerDone: true}:
			return compileResult{diagnostic: "*server.Server does not implement interface (missing method Done)"}, nil
		case compileRequest{sourcePath: sources.upstream, requireSignerJoin: true}:
			return compileResult{diagnostic: "signer.Signer does not implement interface (wrong type for method Start)"}, nil
		case compileRequest{sourcePath: sources.upstream, requirePreparedOpen: true}:
			return compileResult{diagnostic: "*sql.Postgres has no field or method OpenWithPreparedSchema"}, nil
		case compileRequest{sourcePath: sources.upstream, requireHTTPClientMap: true}:
			return compileResult{diagnostic: "unknown field ConnectorHTTPClients in struct literal"}, nil
		case compileRequest{sourcePath: sources.upstream, requireOIDCClientOpen: true}:
			return compileResult{diagnostic: "*oidc.Config has no field or method OpenWithHTTPClient"}, nil
		case compileRequest{
			sourcePath:            sources.candidate,
			requireAuthTime:       true,
			requireServerDone:     true,
			requireSignerJoin:     true,
			requirePreparedOpen:   true,
			requireHTTPClientMap:  true,
			requireOIDCClientOpen: true,
		}:
			return compileResult{compiled: true}, nil
		default:
			return compileResult{}, fmt.Errorf("unexpected request: %+v", request)
		}
	})
	if err != nil {
		t.Fatalf("verifyContracts() error = %v", err)
	}
	if !report.UpstreamBaseCompiled || !report.UpstreamAuthTimePatchRequired ||
		!report.UpstreamWorkerJoinPatchRequired || !report.CandidateContractPassed ||
		!report.UpstreamPreparedOpenPatchRequired || !report.UpstreamHTTPClientMapPatchRequired ||
		!report.UpstreamOIDCClientOpenPatchRequired || !report.Verified {
		t.Fatalf("verifyContracts() report = %+v", report)
	}
	want := []compileRequest{
		{sourcePath: sources.upstream},
		{sourcePath: sources.upstream, requireAuthTime: true},
		{sourcePath: sources.upstream, requireServerDone: true},
		{sourcePath: sources.upstream, requireSignerJoin: true},
		{sourcePath: sources.upstream, requirePreparedOpen: true},
		{sourcePath: sources.upstream, requireHTTPClientMap: true},
		{sourcePath: sources.upstream, requireOIDCClientOpen: true},
		{
			sourcePath:            sources.candidate,
			requireAuthTime:       true,
			requireServerDone:     true,
			requireSignerJoin:     true,
			requirePreparedOpen:   true,
			requireHTTPClientMap:  true,
			requireOIDCClientOpen: true,
		},
	}
	if !slices.Equal(requests, want) {
		t.Fatalf("verifyContracts() requests = %+v, want %+v", requests, want)
	}
}

func TestVerifyContractsFailsClosed(t *testing.T) {
	t.Parallel()

	passingSequence := []compileResult{
		{compiled: true},
		{diagnostic: expectedMissingAuthTime},
		{diagnostic: expectedMissingServerDone},
		{diagnostic: expectedSignerStartMismatch},
		{diagnostic: expectedMissingPreparedOpen},
		{diagnostic: expectedMissingHTTPClientMap},
		{diagnostic: expectedMissingOIDCClientOpen},
		{compiled: true},
	}
	tests := []struct {
		name   string
		index  int
		result compileResult
	}{
		{name: "upstream base contract fails", index: 0, result: compileResult{}},
		{name: "upstream unexpectedly has auth time patch", index: 1, result: compileResult{compiled: true}},
		{name: "auth time fails for another reason", index: 1, result: compileResult{diagnostic: "unrelated"}},
		{name: "server join unexpectedly exists upstream", index: 2, result: compileResult{compiled: true}},
		{name: "server join fails for another reason", index: 2, result: compileResult{diagnostic: "unrelated"}},
		{name: "signer join unexpectedly exists upstream", index: 3, result: compileResult{compiled: true}},
		{name: "signer join fails for another reason", index: 3, result: compileResult{diagnostic: "unrelated"}},
		{name: "prepared open unexpectedly exists upstream", index: 4, result: compileResult{compiled: true}},
		{name: "prepared open fails for another reason", index: 4, result: compileResult{diagnostic: "unrelated"}},
		{name: "HTTP client map unexpectedly exists upstream", index: 5, result: compileResult{compiled: true}},
		{name: "HTTP client map fails for another reason", index: 5, result: compileResult{diagnostic: "unrelated"}},
		{name: "OIDC client open unexpectedly exists upstream", index: 6, result: compileResult{compiled: true}},
		{name: "OIDC client open fails for another reason", index: 6, result: compileResult{diagnostic: "unrelated"}},
		{name: "candidate contract fails", index: 7, result: compileResult{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			results := slices.Clone(passingSequence)
			results[test.index] = test.result
			index := 0
			_, err := verifyContracts(
				t.Context(),
				sourceSet{upstream: "/upstream", candidate: "/candidate"},
				func(context.Context, compileRequest) (compileResult, error) {
					result := results[index]
					index++
					return result, nil
				},
			)
			if err == nil {
				t.Fatal("verifyContracts() succeeded for an invalid sequence")
			}
		})
	}
}

func TestValidateSources(t *testing.T) {
	t.Parallel()

	upstream := createDexModule(t, false, false, false, false, true)
	candidate := createDexModule(t, true, true, true, true, false)
	sources, err := validateSources(rawOptions{
		upstreamSourcePath:  upstream,
		candidateSourcePath: candidate,
	})
	if err != nil {
		t.Fatalf("validateSources() error = %v", err)
	}
	resolvedUpstream, err := filepath.EvalSymlinks(upstream)
	if err != nil {
		t.Fatalf("resolve upstream test path: %v", err)
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		t.Fatalf("resolve candidate test path: %v", err)
	}
	if sources.upstream != resolvedUpstream || sources.candidate != resolvedCandidate {
		t.Fatalf("validateSources() = %+v", sources)
	}
}

func TestValidateSourcesRejectsCandidateGitMetadata(t *testing.T) {
	t.Parallel()

	upstream := createDexModule(t, false, false, false, false, true)
	candidate := createDexModule(t, true, true, true, true, true)
	if _, err := validateSources(rawOptions{
		upstreamSourcePath:  upstream,
		candidateSourcePath: candidate,
	}); err == nil {
		t.Fatal("validateSources() accepted candidate Git metadata")
	}
}

func TestGoCompilerContract(t *testing.T) {
	upstream := createDexModule(t, false, false, false, false, false)
	candidate := createDexModule(t, true, true, true, true, false)
	compiler, err := newGoCompiler()
	if err != nil {
		t.Fatalf("newGoCompiler() error = %v", err)
	}

	base, err := compiler.compile(t.Context(), compileRequest{sourcePath: upstream})
	if err != nil || !base.compiled {
		t.Fatalf("compile(base) = %+v, %v", base, err)
	}
	unmodified, err := compiler.compile(t.Context(), compileRequest{
		sourcePath:      upstream,
		requireAuthTime: true,
	})
	if err != nil || unmodified.compiled ||
		!strings.Contains(unmodified.diagnostic, expectedMissingAuthTime) {
		t.Fatalf("compile(unmodified) = %+v, %v", unmodified, err)
	}
	serverJoin, err := compiler.compile(t.Context(), compileRequest{
		sourcePath:        upstream,
		requireServerDone: true,
	})
	if err != nil || serverJoin.compiled ||
		!strings.Contains(serverJoin.diagnostic, expectedMissingServerDone) {
		t.Fatalf("compile(server join) = %+v, %v", serverJoin, err)
	}
	signerJoin, err := compiler.compile(t.Context(), compileRequest{
		sourcePath:        upstream,
		requireSignerJoin: true,
	})
	if err != nil || signerJoin.compiled ||
		!strings.Contains(signerJoin.diagnostic, expectedSignerStartMismatch) {
		t.Fatalf("compile(signer join) = %+v, %v", signerJoin, err)
	}
	preparedOpen, err := compiler.compile(t.Context(), compileRequest{
		sourcePath:          upstream,
		requirePreparedOpen: true,
	})
	if err != nil || preparedOpen.compiled ||
		!strings.Contains(preparedOpen.diagnostic, expectedMissingPreparedOpen) {
		t.Fatalf("compile(prepared open) = %+v, %v", preparedOpen, err)
	}
	httpClientMap, err := compiler.compile(t.Context(), compileRequest{
		sourcePath:           upstream,
		requireHTTPClientMap: true,
	})
	if err != nil || httpClientMap.compiled ||
		!strings.Contains(httpClientMap.diagnostic, expectedMissingHTTPClientMap) {
		t.Fatalf("compile(HTTP client map) = %+v, %v", httpClientMap, err)
	}
	oidcClientOpen, err := compiler.compile(t.Context(), compileRequest{
		sourcePath:            upstream,
		requireOIDCClientOpen: true,
	})
	if err != nil || oidcClientOpen.compiled ||
		!strings.Contains(oidcClientOpen.diagnostic, expectedMissingOIDCClientOpen) {
		t.Fatalf("compile(OIDC client open) = %+v, %v", oidcClientOpen, err)
	}
	patched, err := compiler.compile(t.Context(), compileRequest{
		sourcePath:            candidate,
		requireAuthTime:       true,
		requireServerDone:     true,
		requireSignerJoin:     true,
		requirePreparedOpen:   true,
		requireHTTPClientMap:  true,
		requireOIDCClientOpen: true,
	})
	if err != nil || !patched.compiled {
		t.Fatalf("compile(candidate) = %+v, %v", patched, err)
	}
}

func TestContractSourceOnlyAddsAuthenticationTime(t *testing.T) {
	t.Parallel()

	base := contractSource(compileRequest{})
	qualified := contractSource(compileRequest{requireAuthTime: true})
	if strings.Contains(base, "AuthTime") || !strings.Contains(qualified, "AuthTime: 1") {
		t.Fatal("unexpected contract sources")
	}
	withoutField := strings.Replace(qualified, `, AuthTime: 1`, "", 1)
	if withoutField != base {
		t.Fatal("qualified contract changes more than AuthTime")
	}
}

func TestContractSourceOnlyAddsWorkerJoinContracts(t *testing.T) {
	t.Parallel()

	base := contractSource(compileRequest{})
	serverJoin := contractSource(compileRequest{requireServerDone: true})
	if strings.Contains(base, "Done()") || !strings.Contains(serverJoin, "Done() <-chan struct{}") {
		t.Fatal("server join contract is not isolated")
	}
	signerJoin := contractSource(compileRequest{requireSignerJoin: true})
	if strings.Contains(base, "Start(context.Context) <-chan struct{}") ||
		!strings.Contains(signerJoin, "Start(context.Context) <-chan struct{}") {
		t.Fatal("signer join contract is not isolated")
	}
}

func TestContractSourceOnlyAddsPreparedOpenContract(t *testing.T) {
	t.Parallel()

	base := contractSource(compileRequest{})
	prepared := contractSource(compileRequest{requirePreparedOpen: true})
	if strings.Contains(base, ".OpenWithPreparedSchema") ||
		!strings.Contains(prepared, ".OpenWithPreparedSchema") {
		t.Fatal("prepared-schema open contract is not isolated")
	}
}

func TestContractSourceOnlyAddsOutboundHTTPContracts(t *testing.T) {
	t.Parallel()

	base := contractSource(compileRequest{})
	httpClientMap := contractSource(compileRequest{requireHTTPClientMap: true})
	if strings.Contains(base, "ConnectorHTTPClients:") ||
		!strings.Contains(httpClientMap, "ConnectorHTTPClients:") {
		t.Fatal("HTTP client map contract is not isolated")
	}
	oidcClientOpen := contractSource(compileRequest{requireOIDCClientOpen: true})
	if strings.Contains(base, ".OpenWithHTTPClient") ||
		!strings.Contains(oidcClientOpen, ".OpenWithHTTPClient") {
		t.Fatal("OIDC client open contract is not isolated")
	}
}

func createDexModule(
	t *testing.T,
	authTime bool,
	workerJoin bool,
	preparedOpen bool,
	outboundHTTP bool,
	gitMetadata bool,
) string {
	t.Helper()

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module github.com/dexidp/dex\n\ngo 1.26.0\n")
	writeTestFile(t, filepath.Join(root, "api", "v2", "go.mod"), "module github.com/dexidp/dex/api/v2\n\ngo 1.26.0\n")
	writeTestFile(t, filepath.Join(root, "connector", "connector.go"), `package connector

type Connector interface{}
`)
	writeTestFile(t, filepath.Join(root, "connector", "oidc", "oidc.go"), `package oidc

`+func() string {
		if !outboundHTTP {
			return "type Config struct{}\n"
		}
		return `import (
	"log/slog"
	"net/http"

	"github.com/dexidp/dex/connector"
)

type Config struct{}

func (*Config) OpenWithHTTPClient(string, *slog.Logger, *http.Client) (connector.Connector, error) {
	return nil, nil
}
`
	}())
	writeTestFile(t, filepath.Join(root, "storage", "storage.go"), `package storage

type Storage interface{}

type Claims struct {
	UserID string
`+func() string {
		if authTime {
			return "\tAuthTime int64\n"
		}
		return ""
	}()+`}
`)
	writeTestFile(t, filepath.Join(root, "storage", "sql", "config.go"), `package sql

`+func() string {
		if preparedOpen {
			return `import (
	"context"
	"log/slog"

	"github.com/dexidp/dex/storage"
)

type Postgres struct{}

type PreparedPostgresStorage interface {
	storage.Storage
	CheckPreparedSchema(context.Context) error
}

func (*Postgres) OpenWithPreparedSchema(context.Context, *slog.Logger) (PreparedPostgresStorage, error) {
	return nil, nil
}
`
		}
		return "type Postgres struct{}\n"
	}())
	writeTestFile(t, filepath.Join(root, "server", "server.go"), `package server

import (
	"context"
	"net/http"

	"github.com/dexidp/dex/storage"
)

type Config struct {
	Issuer string
	Storage storage.Storage
	Signer any
`+func() string {
		if outboundHTTP {
			return "\tConnectorHTTPClients map[string]*http.Client\n"
		}
		return ""
	}()+`}

type Server struct{}

func NewServer(context.Context, Config) (*Server, error) { return &Server{}, nil }

func (*Server) ServeHTTP(http.ResponseWriter, *http.Request) {}
`+func() string {
		if workerJoin {
			return "\nfunc (*Server) Done() <-chan struct{} { return make(chan struct{}) }\n"
		}
		return ""
	}())
	writeTestFile(t, filepath.Join(root, "server", "signer", "signer.go"), `package signer

import "context"

type Signer interface {
`+func() string {
		if workerJoin {
			return "\tStart(context.Context) <-chan struct{}\n"
		}
		return "\tStart(context.Context)\n"
	}()+`}
`)
	if gitMetadata {
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
			t.Fatalf("create Git metadata: %v", err)
		}
	}
	return root
}

func writeTestFile(t *testing.T, name, contents string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}
