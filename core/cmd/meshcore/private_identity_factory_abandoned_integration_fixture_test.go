//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"meshtransit.net/core/internal/adapter/oidc"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/platform/config"
)

const privateFactoryAbandonedDatabase = "meshtransit_private_factory_abandoned"
const privateFactoryAbandonedInputLimit = 8192

// Test-only private IPC, never a product input, log value or stdout protocol.
type privateFactoryAbandonedInput struct {
	ProviderOrigin string   `json:"provider_origin"`
	Cookies        []string `json:"cookies"`
	CSRF           string   `json:"csrf"`
}

func decodePrivateFactoryAbandonedInput(reader io.Reader) (privateFactoryAbandonedInput, error) {
	invalid := errors.New("invalid private fixture input")
	data, err := io.ReadAll(io.LimitReader(reader, privateFactoryAbandonedInputLimit+1))
	defer clear(data)
	if err != nil || len(data) > privateFactoryAbandonedInputLimit {
		return privateFactoryAbandonedInput{}, invalid
	}
	var input privateFactoryAbandonedInput
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		return privateFactoryAbandonedInput{}, invalid
	}
	canonical, err := json.Marshal(input)
	defer clear(canonical)
	// Exact canonical bytes also reject duplicate fields and trailing values.
	if err != nil || !bytes.Equal(data, canonical) {
		return privateFactoryAbandonedInput{}, invalid
	}
	origin, err := url.Parse(input.ProviderOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() != "127.0.0.1" ||
		origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || origin.Opaque != "" || origin.String() != input.ProviderOrigin {
		return privateFactoryAbandonedInput{}, invalid
	}
	host, port, err := net.SplitHostPort(origin.Host)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || number == 0 || host != "127.0.0.1" ||
		input.CSRF == "" || len(input.Cookies) == 0 || len(input.Cookies) > 4 {
		return privateFactoryAbandonedInput{}, invalid
	}
	return input, nil
}

// Explicit runtime-only profile: no host environment, migrator/admin/worker
// credentials, query material or Basic secret is inherited by the child.
func privateFactoryAbandonedEnvironment(t *testing.T) []string {
	t.Helper()
	environment := []string{"MESHTRANSIT_ROLE=api", "MESHTRANSIT_PRIVATE_FACTORY_ABANDONED_CHILD=1"}
	for _, name := range []string{
		"MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"MESHTRANSIT_POSTGRES_ADDRESS", "MESHTRANSIT_POSTGRES_DATABASE", "MESHTRANSIT_POSTGRES_CA_FILE",
		"MESHTRANSIT_POSTGRES_RUNTIME_USER", "MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE",
		"MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS", "MESHTRANSIT_REDIS_ADDRESS",
		"MESHTRANSIT_REDIS_USERNAME", "MESHTRANSIT_REDIS_PASSWORD_FILE", "MESHTRANSIT_REDIS_CA_FILE",
		"MESHTRANSIT_REDIS_POOL_SIZE", "MESHTRANSIT_API_TLS_CERTIFICATE_FILE", "MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE",
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID", "MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE",
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID", "MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE",
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID", "MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE",
	} {
		value, present := os.LookupEnv(name)
		if !present || value == "" {
			t.Fatal("missing explicit owned child profile")
		}
		environment = append(environment, name+"="+value)
	}
	return environment
}

func attachPrivateFactoryAbandonedRuntime(t *testing.T) *privateFactoryIntegrationStorage {
	t.Helper()
	process, err := config.Load(os.LookupEnv)
	if err != nil || process.Storage == nil || process.Storage.PostgreSQL.Runtime == nil {
		t.Fatal("load owned child runtime profile")
	}
	pg := process.Storage.PostgreSQL
	cache := process.Storage.Redis
	owned := pg.Database == privateFactoryAbandonedDatabase && pg.Address == "meshtransit-postgres:5432" &&
		pg.Runtime.User == "mesh_runtime" && pg.Runtime.MaxConnections == 2 && pg.Worker == nil &&
		cache.Address == "meshtransit-redis:6379" && cache.Username == "mesh_worker" && cache.PoolSize == 1
	if !owned {
		t.Fatal("refuse unowned child runtime attachment")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pool, err := openPostgresRolePool(ctx, postgresadapter.PoolRoleRuntime, pg, *pg.Runtime, 5*time.Second)
	if err != nil {
		t.Fatal("open owned child runtime pool")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		if pool.Shutdown(cleanup) != nil {
			t.Error("close owned child runtime pool")
		}
	})
	if pool.Check(ctx) != nil {
		t.Fatal("check migrated child runtime schema and role")
	}
	return &privateFactoryIntegrationStorage{runtime: pool, redis: cache}
}

type privateFactoryAbandonedChild struct {
	command     *exec.Cmd
	phaseReader *os.File
	done        chan struct{}
	err         error // Written only by Wait owner; read only after done closes.
}

func composePrivateFactoryAbandoned(
	t *testing.T,
	fixture *privateIdentityFixture,
	storage *privateFactoryIntegrationStorage,
	cache *redisadapter.Client,
	secret oidc.BasicSecret,
) *privateIdentityFactory {
	t.Helper()
	factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, privateIdentityFactoryOptions{
		Application: fixture.options,
		Discovery:   oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
		Token:       privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
	}, privateIdentityFactoryDependencies{
		Runtime: storage.runtime, Redis: cache, Secret: secret, Logger: discardCompositionLogger(),
	})
	if err != nil || factory == nil {
		t.Fatal("compose actual process-abandoned factory")
	}
	t.Cleanup(factory.Close)
	return factory
}

func startPrivateFactoryAbandonedChild(
	t *testing.T,
	input privateFactoryAbandonedInput,
	credential string,
	barrier *privateFactoryTokenBarrier,
) *privateFactoryAbandonedChild {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("resolve exact owned test executable")
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > privateFactoryAbandonedInputLimit || len(credential) == 0 || len(credential) > 128 {
		t.Fatal("encode bounded private fixture input")
	}
	defer clear(data)
	environment := privateFactoryAbandonedEnvironment(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("open owned private fixture pipe")
	}
	defer func() {
		for _, file := range []*os.File{reader, writer} {
			if closeErr := file.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
				t.Error("close owned private fixture pipe")
			}
		}
	}()
	credentialReader, credentialWriter, err := os.Pipe()
	if err != nil {
		t.Fatal("open owned private credential pipe")
	}
	defer func() {
		for _, file := range []*os.File{credentialReader, credentialWriter} {
			if closeErr := file.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
				t.Error("close owned private credential pipe")
			}
		}
	}()
	phaseReader, phaseWriter, err := os.Pipe()
	if err != nil {
		t.Fatal("open owned redacted helper phase pipe")
	}
	defer func() {
		if closeErr := phaseWriter.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			t.Error("close owned helper phase writer")
		}
	}()
	// OS-resolved current executable, exact helper-only arguments, no shell or
	// secret argv. fd3 carries bounded syntax, fd4 only the synthetic credential.
	child := &privateFactoryAbandonedChild{
		command: &exec.Cmd{
			Path: executable,
			Args: []string{executable, "-test.run=^TestPrivateIdentityFactoryAbandonedChild$", "-test.timeout=30s"},
			Env:  environment, ExtraFiles: []*os.File{reader, credentialReader, phaseWriter},
			Stdout: io.Discard, Stderr: io.Discard,
		},
		done: make(chan struct{}), phaseReader: phaseReader,
	}
	hasStarted := false
	t.Cleanup(func() {
		defer func() {
			if phaseReader.Close() != nil {
				t.Error("close owned helper phase reader")
			}
		}()
		if !hasStarted {
			return
		}
		select {
		case <-child.done:
		default:
			if killErr := child.command.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
				t.Error("kill exact owned child during cleanup")
			}
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		if child.join(cleanup) != nil {
			t.Error("join exact owned child during cleanup")
		}
		barrier.unblock()
		if barrier.accepted.Load() {
			select {
			case <-barrier.exited:
			case <-cleanup.Done():
				t.Error("join accepted provider handler during child cleanup")
			}
		}
	})
	if child.command.Start() != nil {
		t.Fatal("start exact owned test child")
	}
	hasStarted = true
	go func() {
		defer close(child.done)
		child.err = child.command.Wait()
	}()
	if phaseWriter.Close() != nil {
		t.Fatal("release parent helper phase writer after inheritance")
	}
	if reader.Close() != nil || writer.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
		t.Fatal("bound owned private fixture pipe write")
	}
	written, writeErr := writer.Write(data)
	if writeErr != nil || written != len(data) || writer.Close() != nil {
		t.Fatal("complete owned private fixture pipe transfer")
	}
	if credentialReader.Close() != nil || credentialWriter.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
		t.Fatal("bound owned private credential transfer")
	}
	material := []byte(credential)
	defer clear(material)
	written, writeErr = credentialWriter.Write(material)
	if writeErr != nil || written != len(material) || credentialWriter.Close() != nil {
		t.Fatal("complete owned private credential transfer")
	}
	return child
}

func (child *privateFactoryAbandonedChild) join(ctx context.Context) error {
	select {
	case <-child.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (child *privateFactoryAbandonedChild) lastPhase(t *testing.T) int {
	t.Helper()
	// Call only after Wait joins, so the child owns no remaining write endpoint.
	if child.phaseReader.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("bound redacted helper phase read")
	}
	data, err := io.ReadAll(io.LimitReader(child.phaseReader, 9))
	if err != nil || len(data) > 8 {
		t.Fatal("invalid bounded redacted helper phase status")
	}
	for index, phase := range data {
		if phase != byte(index+1) {
			t.Fatal("invalid closed helper phase ordering")
		}
	}
	return len(data)
}

func privateFactoryInheritedPipe(t *testing.T, descriptor int, name string) *os.File {
	t.Helper()
	if descriptor < 3 || descriptor > 5 {
		t.Fatal("refuse descriptor outside closed owned helper protocol")
	}
	// exec calls File.Fd, which restores blocking mode. NewFile must observe
	// nonblocking mode to register the inherited pipe with runtime polling.
	if syscall.SetNonblock(descriptor, true) != nil {
		t.Fatal("restore owned inherited pipe polling")
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		t.Fatal("missing owned inherited descriptor")
	}
	t.Cleanup(func() {
		if file.Close() != nil {
			t.Error("close owned inherited descriptor")
		}
	})
	return file
}

func privateFactoryReportPhase(t *testing.T, writer *os.File, phase byte) {
	t.Helper()
	if writer.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("bound redacted helper phase write")
	}
	count, err := writer.Write([]byte{phase})
	if err != nil || count != 1 {
		t.Fatal("write closed redacted helper phase")
	}
}

func (child *privateFactoryAbandonedChild) killAndJoin(t *testing.T, barrier *privateFactoryTokenBarrier) {
	t.Helper()
	select {
	case <-child.done:
		t.Fatal("owned child exited before crash signal")
	default:
	}
	if child.command.Process.Kill() != nil {
		t.Fatal("kill exact owned child PID")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	if child.join(ctx) != nil {
		t.Fatal("join killed owned child")
	}
	if child.command.ProcessState == nil {
		t.Fatal("missing owned child wait status")
	}
	var exit *exec.ExitError
	status, hasStatus := child.command.ProcessState.Sys().(syscall.WaitStatus)
	if !errors.As(child.err, &exit) || !hasStatus || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("owned child did not exit by checked SIGKILL")
	}
	select {
	case <-barrier.exited:
	case <-ctx.Done():
		t.Fatal("join accepted provider disconnect after process death")
	}
	if barrier.disconnected.Load() != 1 {
		t.Fatal("process death did not cancel exactly one accepted token handler")
	}
}
