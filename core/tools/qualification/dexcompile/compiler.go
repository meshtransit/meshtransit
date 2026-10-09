package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	maximumCompilerOutputBytes    = 8 << 20
	maximumModuleFileBytes        = 1 << 20
	dexModulePath                 = "github.com/dexidp/dex"
	dexAPIModulePath              = "github.com/dexidp/dex/api/v2"
	expectedMissingAuthTime       = "unknown field AuthTime in struct literal"
	expectedMissingServerDone     = "missing method Done"
	expectedSignerStartMismatch   = "wrong type for method Start"
	expectedMissingPreparedOpen   = "has no field or method OpenWithPreparedSchema"
	expectedMissingHTTPClientMap  = "unknown field ConnectorHTTPClients"
	expectedMissingOIDCClientOpen = "has no field or method OpenWithHTTPClient"
)

var (
	errCompileVerification = errors.New("dex compile verifier: verification failed")
	errCompilerOutputLimit = errors.New("dex compile verifier: compiler output limit exceeded")
)

type sourceSet struct {
	upstream  string
	candidate string
}

type compileRequest struct {
	sourcePath            string
	requireAuthTime       bool
	requireServerDone     bool
	requireSignerJoin     bool
	requirePreparedOpen   bool
	requireHTTPClientMap  bool
	requireOIDCClientOpen bool
}

type compileResult struct {
	compiled   bool
	diagnostic string
}

type contractCompiler func(context.Context, compileRequest) (compileResult, error)

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return 0, errCompilerOutputLimit
	}
	if len(data) > remaining {
		_, _ = buffer.buffer.Write(data[:remaining])
		buffer.exceeded = true
		return remaining, errCompilerOutputLimit
	}
	return buffer.buffer.Write(data)
}

type goCompiler struct {
	executable  string
	environment []string
}

func verifyCompileContract(ctx context.Context, options rawOptions) (verificationReport, error) {
	if ctx == nil {
		return verificationReport{}, errCompileVerification
	}

	sources, err := validateSources(options)
	if err != nil {
		return verificationReport{}, errCompileVerification
	}
	compiler, err := newGoCompiler()
	if err != nil {
		return verificationReport{}, errCompileVerification
	}
	return verifyContracts(ctx, sources, compiler.compile)
}

func verifyContracts(
	ctx context.Context,
	sources sourceSet,
	compile contractCompiler,
) (verificationReport, error) {
	if ctx == nil || sources.upstream == "" || sources.candidate == "" || compile == nil {
		return verificationReport{}, errCompileVerification
	}

	base, err := compile(ctx, compileRequest{sourcePath: sources.upstream})
	if err != nil || !base.compiled {
		return verificationReport{}, errCompileVerification
	}

	unmodified, err := compile(ctx, compileRequest{
		sourcePath:      sources.upstream,
		requireAuthTime: true,
	})
	if err != nil || unmodified.compiled || !strings.Contains(unmodified.diagnostic, expectedMissingAuthTime) {
		return verificationReport{}, errCompileVerification
	}

	serverJoin, err := compile(ctx, compileRequest{
		sourcePath:        sources.upstream,
		requireServerDone: true,
	})
	if err != nil || serverJoin.compiled ||
		!strings.Contains(serverJoin.diagnostic, expectedMissingServerDone) {
		return verificationReport{}, errCompileVerification
	}

	signerJoin, err := compile(ctx, compileRequest{
		sourcePath:        sources.upstream,
		requireSignerJoin: true,
	})
	if err != nil || signerJoin.compiled ||
		!strings.Contains(signerJoin.diagnostic, expectedSignerStartMismatch) {
		return verificationReport{}, errCompileVerification
	}

	preparedOpen, err := compile(ctx, compileRequest{
		sourcePath:          sources.upstream,
		requirePreparedOpen: true,
	})
	if err != nil || preparedOpen.compiled ||
		!strings.Contains(preparedOpen.diagnostic, expectedMissingPreparedOpen) {
		return verificationReport{}, errCompileVerification
	}

	httpClientMap, err := compile(ctx, compileRequest{
		sourcePath:           sources.upstream,
		requireHTTPClientMap: true,
	})
	if err != nil || httpClientMap.compiled ||
		!strings.Contains(httpClientMap.diagnostic, expectedMissingHTTPClientMap) {
		return verificationReport{}, errCompileVerification
	}

	oidcClientOpen, err := compile(ctx, compileRequest{
		sourcePath:            sources.upstream,
		requireOIDCClientOpen: true,
	})
	if err != nil || oidcClientOpen.compiled ||
		!strings.Contains(oidcClientOpen.diagnostic, expectedMissingOIDCClientOpen) {
		return verificationReport{}, errCompileVerification
	}

	candidate, err := compile(ctx, compileRequest{
		sourcePath:            sources.candidate,
		requireAuthTime:       true,
		requireServerDone:     true,
		requireSignerJoin:     true,
		requirePreparedOpen:   true,
		requireHTTPClientMap:  true,
		requireOIDCClientOpen: true,
	})
	if err != nil || !candidate.compiled {
		return verificationReport{}, errCompileVerification
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
}

func validateSources(options rawOptions) (sourceSet, error) {
	upstream, err := validateDexSource(options.upstreamSourcePath, true)
	if err != nil {
		return sourceSet{}, errCompileVerification
	}
	candidate, err := validateDexSource(options.candidateSourcePath, false)
	if err != nil || upstream == candidate {
		return sourceSet{}, errCompileVerification
	}
	return sourceSet{upstream: upstream, candidate: candidate}, nil
}

func validateDexSource(name string, requireGitMetadata bool) (string, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return "", errCompileVerification
	}
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errCompileVerification
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errCompileVerification
	}
	if err := verifyModuleFile(filepath.Join(resolved, "go.mod"), dexModulePath); err != nil {
		return "", errCompileVerification
	}
	if err := verifyModuleFile(filepath.Join(resolved, "api", "v2", "go.mod"), dexAPIModulePath); err != nil {
		return "", errCompileVerification
	}

	gitInfo, gitErr := os.Lstat(filepath.Join(resolved, ".git"))
	if requireGitMetadata {
		if gitErr != nil || gitInfo.Mode()&os.ModeSymlink != 0 ||
			(!gitInfo.IsDir() && !gitInfo.Mode().IsRegular()) {
			return "", errCompileVerification
		}
	} else if gitErr == nil || !os.IsNotExist(gitErr) {
		return "", errCompileVerification
	}

	return resolved, nil
}

func verifyModuleFile(name, expectedModule string) error {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumModuleFileBytes {
		return errCompileVerification
	}
	file, err := os.Open(name) // #nosec G304 -- name is rooted in a validated local source directory.
	if err != nil {
		return errCompileVerification
	}
	defer func() { _ = file.Close() }()

	contents, err := io.ReadAll(io.LimitReader(file, maximumModuleFileBytes+1))
	if err != nil || len(contents) > maximumModuleFileBytes {
		return errCompileVerification
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if strings.TrimSpace(line) == "module "+expectedModule {
			return nil
		}
	}
	return errCompileVerification
}

func newGoCompiler() (goCompiler, error) {
	executable, err := exec.LookPath("go")
	if err != nil {
		return goCompiler{}, errCompileVerification
	}

	environment := make([]string, 0, 24)
	for _, key := range [...]string{
		"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT",
		"GOCACHE", "GOMODCACHE", "GOPATH", "GOPROXY", "GOSUMDB",
		"GONOSUMDB", "GONOPROXY", "GOPRIVATE", "GOVCS",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
	} {
		if value, found := os.LookupEnv(key); found {
			environment = append(environment, key+"="+value)
		}
	}
	environment = append(environment,
		"CGO_ENABLED=0",
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"LANG=C",
		"LC_ALL=C",
	)
	return goCompiler{executable: executable, environment: environment}, nil
}

func (compiler goCompiler) compile(ctx context.Context, request compileRequest) (compileResult, error) {
	if ctx == nil || compiler.executable == "" || request.sourcePath == "" {
		return compileResult{}, errCompileVerification
	}

	root, err := os.MkdirTemp("", "meshtransit-dex-compile-")
	if err != nil {
		return compileResult{}, errCompileVerification
	}
	defer func() { _ = os.RemoveAll(root) }()

	if err := os.Symlink(request.sourcePath, filepath.Join(root, "dex-source")); err != nil {
		return compileResult{}, errCompileVerification
	}
	if err := os.Symlink(
		filepath.Join(request.sourcePath, "api", "v2"),
		filepath.Join(root, "dex-api-v2"),
	); err != nil {
		return compileResult{}, errCompileVerification
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(contractModule), 0o600); err != nil {
		return compileResult{}, errCompileVerification
	}
	if err := os.WriteFile(
		filepath.Join(root, "contract.go"),
		[]byte(contractSource(request)),
		0o600,
	); err != nil {
		return compileResult{}, errCompileVerification
	}

	command := exec.CommandContext( // #nosec G204 -- executable is locally resolved and arguments are constant.
		ctx,
		compiler.executable,
		"test", "-mod=mod", "-buildvcs=false", "-c", "-o", filepath.Join(root, "contract.test"), ".",
	)
	command.Dir = root
	command.Env = compiler.environment
	stdout := &boundedBuffer{limit: maximumCompilerOutputBytes}
	stderr := &boundedBuffer{limit: maximumCompilerOutputBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	if ctx.Err() != nil || stdout.exceeded || stderr.exceeded {
		return compileResult{}, errCompileVerification
	}
	if err == nil {
		return compileResult{compiled: true}, nil
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return compileResult{}, errCompileVerification
	}
	return compileResult{
		diagnostic: stdout.buffer.String() + stderr.buffer.String(),
	}, nil
}

const contractModule = `module github.com/meshtransit/dexcompilecontract

go 1.26.0

require (
	github.com/dexidp/dex v0.0.0
	github.com/dexidp/dex/api/v2 v2.4.0
)

replace github.com/dexidp/dex => ./dex-source

replace github.com/dexidp/dex/api/v2 => ./dex-api-v2
`

func contractSource(request compileRequest) string {
	claims := `storage.Claims{UserID: "compile-contract"}`
	if request.requireAuthTime {
		claims = `storage.Claims{UserID: "compile-contract", AuthTime: 1}`
	}
	serverDoneContract := ""
	if request.requireServerDone {
		serverDoneContract = "var _ interface{ Done() <-chan struct{} } = (*server.Server)(nil)\n"
	}
	signerJoinContract := ""
	if request.requireSignerJoin {
		signerJoinContract = `var _ interface {
	Start(context.Context) <-chan struct{}
} = (signer.Signer)(nil)
`
	}
	preparedOpenContract := ""
	if request.requirePreparedOpen {
		preparedOpenContract = `var _ func(context.Context, *slog.Logger) (dexsql.PreparedPostgresStorage, error) =
	(&dexsql.Postgres{}).OpenWithPreparedSchema
`
	}
	httpClientMapContract := ""
	if request.requireHTTPClientMap {
		httpClientMapContract = "\tConnectorHTTPClients: map[string]*http.Client{},\n"
	}
	oidcClientOpenContract := ""
	if request.requireOIDCClientOpen {
		oidcClientOpenContract = `var _ func(string, *slog.Logger, *http.Client) (connector.Connector, error) =
	(&dexoidc.Config{}).OpenWithHTTPClient
`
	}
	return fmt.Sprintf(`package contract

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/dexidp/dex/connector"
	dexoidc "github.com/dexidp/dex/connector/oidc"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/storage"
	dexsql "github.com/dexidp/dex/storage/sql"
)

var _ http.Handler = (*server.Server)(nil)
var _ connector.Connector
var _ func(context.Context, server.Config) (*server.Server, error) = server.NewServer
var _ signer.Signer
var _ = slog.Default
var _ = (*dexoidc.Config)(nil)
var _ = (*dexsql.Postgres)(nil)
%s%s%svar _ = server.Config{
	Issuer:  "https://issuer.invalid/dex",
	Storage: nil,
	Signer:  nil,
%s}
%svar _ = %s
`, serverDoneContract, signerJoinContract, preparedOpenContract, httpClientMapContract, oidcClientOpenContract, claims)
}
