//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc/qualification"
)

const (
	dexBinaryEnvironment  = "MESHTRANSIT_TEST_DEX_BINARY"
	dexReleaseEnvironment = "MESHTRANSIT_TEST_DEX_RELEASE"
)

// TestDexBrokerCompatibilityGate is SSO-BROKER-000. The conformance client is
// deliberately independent of the Dex Go API; a future release is qualified by
// supplying its binary and release string to this unchanged test.
func TestDexBrokerCompatibilityGate(t *testing.T) {
	binary := os.Getenv(dexBinaryEnvironment)
	if binary == "" {
		t.Skip("set MESHTRANSIT_TEST_DEX_BINARY to an exact pinned Dex artifact")
	}
	binary = validatedDexBinary(t, binary)
	release := os.Getenv(dexReleaseEnvironment)
	if release == "" {
		t.Fatal("set MESHTRANSIT_TEST_DEX_RELEASE to the exact artifact release")
	}
	assertDexVersion(t, binary, release)
	artifactDigest := fileSHA256(t, binary)

	address := reserveDexQualificationAddress(t)
	issuer := "http://" + address + "/dex"
	clientSecret := qualificationSecret(t)
	redirectURI := "http://127.0.0.1:1/qualification/callback"
	configFile := writeDexQualificationConfig(t, dexQualificationConfig{
		Issuer: issuer, Address: address, ClientID: "meshtransit-qualification",
		ClientSecret: clientSecret, RedirectURI: redirectURI, ConnectorID: "qualification",
	})
	process := startDexQualificationProcess(t, binary, configFile)
	waitForDexDiscovery(t, process, issuer)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	report, err := qualification.Run(ctx, qualification.Options{
		Issuer: issuer, ClientID: "meshtransit-qualification", ClientSecret: clientSecret,
		RedirectURI: redirectURI, ConnectorID: "qualification", Timeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf(
			"SSO-BROKER-000 release %q artifact sha256 %s execution error = %v",
			release,
			artifactDigest,
			err,
		)
	}
	if !report.Passed() {
		t.Fatalf(
			"SSO-BROKER-000 release %q artifact sha256 %s missing requirements: %v",
			release,
			artifactDigest,
			report.Missing(),
		)
	}
}

func assertDexVersion(t *testing.T, binary, release string) {
	t.Helper()

	if len(release) > 64 || !strings.HasPrefix(release, "v") || strings.ContainsAny(release, " \t\r\n") {
		t.Fatal("Dex release must be one bounded canonical version token")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// G702: executing the explicitly selected, validated artifact is the purpose
	// of this opt-in qualification test; arguments never pass through a shell.
	//nolint:gosec
	output, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil {
		t.Fatalf("Dex version command error = %v", err)
	}
	expected := "Dex Version: " + release
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] != expected {
		t.Fatalf("Dex artifact version line did not equal %q", expected)
	}
}

func validatedDexBinary(t *testing.T, name string) string {
	t.Helper()

	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		t.Fatal("Dex artifact path must be absolute and canonical")
	}
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		t.Fatal("Dex artifact path cannot be resolved canonically")
	}
	// G703: resolved is absolute, cleaned and returned by EvalSymlinks before use.
	//nolint:gosec
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 ||
		info.Size() <= 0 || info.Size() > 512*1024*1024 {
		t.Fatal("Dex artifact must be one bounded executable regular file")
	}
	return resolved
}

func fileSHA256(t *testing.T, name string) string {
	t.Helper()

	// G304: name is the canonical regular file returned by validatedDexBinary.
	//nolint:gosec
	file, err := os.Open(name)
	if err != nil {
		t.Fatalf("open Dex artifact: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close Dex artifact: %v", err)
		}
	}()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 512*1024*1024 {
		t.Fatal("Dex artifact size is unavailable or outside the qualification bound")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatalf("hash Dex artifact: %v", err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func reserveDexQualificationAddress(t *testing.T) string {
	t.Helper()

	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Dex qualification address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release Dex qualification address: %v", err)
	}
	return address
}

func qualificationSecret(t *testing.T) string {
	t.Helper()

	material := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		t.Fatalf("generate qualification client secret: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(material)
}

type dexQualificationConfig struct {
	Issuer, Address, ClientID, ClientSecret, RedirectURI, ConnectorID string
}

func writeDexQualificationConfig(t *testing.T, input dexQualificationConfig) string {
	t.Helper()

	config := map[string]any{
		"issuer":  input.Issuer,
		"storage": map[string]any{"type": "memory"},
		"web":     map[string]any{"http": input.Address},
		"oauth2": map[string]any{
			"grantTypes": []string{"authorization_code"}, "responseTypes": []string{"code"},
			"skipApprovalScreen": true,
		},
		"staticClients": []map[string]any{{
			"id": input.ClientID, "name": "MeshTransit qualification",
			"secret": input.ClientSecret, "redirectURIs": []string{input.RedirectURI},
		}},
		"connectors": []map[string]any{{
			"type": "mockCallback", "id": input.ConnectorID,
			"name": "Qualification connector", "config": map[string]any{},
		}},
		"logger": map[string]any{"level": "error", "format": "json"},
	}
	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("marshal Dex qualification config: %v", err)
	}
	name := filepath.Join(t.TempDir(), "dex-qualification.json")
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatalf("write Dex qualification config: %v", err)
	}
	return name
}

type qualificationProcess struct {
	command *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	waitErr error
}

func startDexQualificationProcess(t *testing.T, binary, configFile string) *qualificationProcess {
	t.Helper()

	logFile, err := os.OpenFile(
		filepath.Join(t.TempDir(), "dex.log"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0o600,
	)
	if err != nil {
		t.Fatalf("create Dex qualification log: %v", err)
	}
	// G204: binary is the canonical artifact returned by validatedDexBinary;
	// configFile is a test-owned 0600 file and no argument is shell interpreted.
	//nolint:gosec
	command := exec.CommandContext(t.Context(), binary, "serve", configFile)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start Dex qualification process: %v", err)
	}
	if err := logFile.Close(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("close parent Dex log handle: %v", err)
	}
	process := &qualificationProcess{command: command, done: make(chan struct{})}
	go func() {
		waitErr := command.Wait()
		process.mu.Lock()
		process.waitErr = waitErr
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() { process.stop(t) })
	return process
}

func (process *qualificationProcess) stop(t *testing.T) {
	t.Helper()

	select {
	case <-process.done:
		return
	default:
	}
	if err := process.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("interrupt Dex qualification process: %v", err)
	}
	select {
	case <-process.done:
		return
	case <-time.After(5 * time.Second):
	}
	if err := process.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("kill Dex qualification process: %v", err)
	}
	select {
	case <-process.done:
	case <-time.After(5 * time.Second):
		t.Error("Dex qualification process did not terminate")
	}
}

func (process *qualificationProcess) exited() (bool, error) {
	select {
	case <-process.done:
		process.mu.Lock()
		defer process.mu.Unlock()
		return true, process.waitErr
	default:
		return false, nil
	}
}

func waitForDexDiscovery(t *testing.T, process *qualificationProcess, issuer string) {
	t.Helper()

	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	endpoint := issuer + "/.well-known/openid-configuration"
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatalf("construct Dex discovery probe: %v", err)
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		if exited, waitErr := process.exited(); exited {
			t.Fatalf("Dex qualification process exited before readiness: %v", waitErr)
		}
		select {
		case <-t.Context().Done():
			t.Fatalf("Dex discovery readiness canceled: %v", context.Cause(t.Context()))
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("Dex discovery did not become ready: %v", context.DeadlineExceeded)
}
