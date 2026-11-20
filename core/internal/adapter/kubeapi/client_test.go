package kubeapi

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeAPI keeps Secrets and ConfigMaps of one namespace in memory.
type fakeAPI struct {
	mu         sync.Mutex
	secrets    map[string]json.RawMessage
	configMaps map[string]map[string]any
	version    int
	tokens     []string
}

func (api *fakeAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.tokens = append(api.tokens, request.Header.Get("Authorization"))
	path := strings.TrimPrefix(request.URL.Path, "/api/v1/namespaces/mesh/")
	kind, name, _ := strings.Cut(path, "/")
	body, _ := io.ReadAll(request.Body)
	switch {
	case kind == "redirect":
		http.Redirect(response, request, "https://elsewhere.example/", http.StatusFound)
	case request.Method == http.MethodGet && kind == "secrets":
		stored, ok := api.secrets[name]
		if !ok {
			http.Error(response, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		_, _ = response.Write(stored)
	case request.Method == http.MethodPost && kind == "secrets":
		var object struct {
			Metadata Metadata `json:"metadata"`
		}
		_ = json.Unmarshal(body, &object)
		if _, ok := api.secrets[object.Metadata.Name]; ok {
			http.Error(response, `{"reason":"AlreadyExists","message":"exists"}`, http.StatusConflict)
			return
		}
		api.secrets[object.Metadata.Name] = body
		response.WriteHeader(http.StatusCreated)
	case request.Method == http.MethodGet && kind == "configmaps":
		stored, ok := api.configMaps[name]
		if !ok {
			http.Error(response, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(response).Encode(stored)
	case kind == "configmaps" && (request.Method == http.MethodPost || request.Method == http.MethodPut):
		var object map[string]any
		_ = json.Unmarshal(body, &object)
		metadata, _ := object["metadata"].(map[string]any)
		objectName, _ := metadata["name"].(string)
		existing, exists := api.configMaps[objectName]
		if request.Method == http.MethodPost && exists {
			http.Error(response, `{"reason":"AlreadyExists"}`, http.StatusConflict)
			return
		}
		if request.Method == http.MethodPut {
			current, _ := existing["metadata"].(map[string]any)
			if !exists || metadata["resourceVersion"] != current["resourceVersion"] {
				http.Error(response, `{"reason":"Conflict"}`, http.StatusConflict)
				return
			}
		}
		api.version++
		metadata["resourceVersion"] = strconv.Itoa(api.version)
		api.configMaps[objectName] = object
		if request.Method == http.MethodPut {
			response.WriteHeader(http.StatusOK)
			return
		}
		response.WriteHeader(http.StatusCreated)
	default:
		http.Error(response, `{"reason":"Forbidden","message":"`+strings.Repeat("x", 500)+`"}`, http.StatusForbidden)
	}
}

func newClient(t *testing.T) (*Client, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{secrets: map[string]json.RawMessage{}, configMaps: map[string]map[string]any{}}
	server := httptest.NewTLSServer(api)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{Server: server.URL, CAFile: caFile, TokenFile: tokenFile, Namespace: "mesh",
		Timeout: DefaultTimeout})
	if err != nil {
		t.Fatal(err)
	}
	return client, api
}

// A Secret is created once and never changed by a second create.
func TestCreateSecretIfAbsentNeverOverwrites(t *testing.T) {
	t.Parallel()
	client, api := newClient(t)
	first := Secret{Metadata: Metadata{Name: "core-noise", Labels: map[string]string{"a": "b"}},
		Data: map[string][]byte{"noise.key": []byte("first")}}
	created, err := client.CreateSecretIfAbsent(t.Context(), first)
	if err != nil || !created {
		t.Fatalf("first create = %v, %v", created, err)
	}
	second := Secret{Metadata: Metadata{Name: "core-noise"}, Data: map[string][]byte{"noise.key": []byte("second")}}
	created, err = client.CreateSecretIfAbsent(t.Context(), second)
	if err != nil || created {
		t.Fatalf("second create = %v, %v; want kept", created, err)
	}
	got, found, err := client.GetSecret(t.Context(), "core-noise")
	if err != nil || !found || string(got.Data["noise.key"]) != "first" || got.Metadata.Labels["a"] != "b" {
		t.Fatalf("GetSecret() = %+v %v %v", got, found, err)
	}
	if _, found, err := client.GetSecret(t.Context(), "absent"); err != nil || found {
		t.Fatalf("absent Secret: %v %v", found, err)
	}
	for _, header := range api.tokens {
		if header != "Bearer sa-token" {
			t.Fatalf("Authorization = %q", header)
		}
	}
}

// A ConfigMap update carries the version it read; a stale one conflicts.
func TestConfigMapCreateAndUpdate(t *testing.T) {
	t.Parallel()
	client, _ := newClient(t)
	created, err := client.CreateConfigMapIfAbsent(t.Context(),
		ConfigMap{Metadata: Metadata{Name: "core-install"}, Data: map[string]string{"deployment": "one"}})
	if err != nil || !created {
		t.Fatalf("create = %v, %v", created, err)
	}
	if created, err := client.CreateConfigMapIfAbsent(t.Context(),
		ConfigMap{Metadata: Metadata{Name: "core-install"}, Data: map[string]string{"deployment": "two"}}); err != nil || created {
		t.Fatalf("second create = %v, %v", created, err)
	}
	current, found, err := client.GetConfigMap(t.Context(), "core-install")
	if err != nil || !found || current.Data["deployment"] != "one" {
		t.Fatalf("GetConfigMap() = %+v %v %v", current, found, err)
	}
	stale := current
	current.Data = map[string]string{"deployment": "one", "public": "key"}
	if err := client.UpdateConfigMap(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateConfigMap(t.Context(), stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update = %v, want ErrConflict", err)
	}
}

// The token never follows a redirect, and errors stay short.
func TestClientRefusesRedirectsAndBoundsErrors(t *testing.T) {
	t.Parallel()
	client, _ := newClient(t)
	code, _, err := client.do(t.Context(), http.MethodGet, client.base+"/redirect/x", nil)
	if err != nil || code != http.StatusFound {
		t.Fatalf("redirect: %d %v", code, err)
	}
	if _, found, err := client.GetConfigMap(t.Context(), "x"); err != nil || found {
		t.Fatalf("absent ConfigMap: %v %v", found, err)
	}
	_, err = client.CreateSecretIfAbsent(t.Context(), Secret{Metadata: Metadata{Name: "Bad_Name"}})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("invalid name = %v", err)
	}
	if err := statusError("x", 403, []byte(`{"reason":"Forbidden","message":"`+strings.Repeat("y", 500)+`"}`)); len(err.Error()) > 260 {
		t.Fatalf("error not bounded: %d", len(err.Error()))
	}
}

func TestNewRefusesInvalidConfig(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]Config{
		"http":      {Server: "http://api", CAFile: "x", TokenFile: "t", Namespace: "mesh", Timeout: 1},
		"namespace": {Server: "https://api", CAFile: "x", TokenFile: "t", Namespace: "Bad", Timeout: 1},
		"no ca":     {Server: "https://api", CAFile: filepath.Join(t.TempDir(), "none"), TokenFile: "t", Namespace: "mesh", Timeout: 1},
	} {
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: New() = %v", name, err)
		}
	}
	if _, err := inCluster(func(string) string { return "" }, t.TempDir()); !errors.Is(err, ErrConfig) {
		t.Fatalf("outside a pod: %v", err)
	}
}
