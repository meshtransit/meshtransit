package k8sstate

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	testNamespace = "mt-kube-api"
	testSecret    = "meshgw-state-0" //nolint:gosec // G101: a Secret name, not a credential
	testToken     = "token-one"
	testUID       = "6f1c1c3e-0000-4000-8000-000000000001"
)

// fakeAPI is the slice of the Kubernetes API the mirror uses: GET and PUT of
// one Secret with resourceVersion checks. Faults are queued per request.
type fakeAPI struct {
	t      *testing.T
	server *httptest.Server

	mu          sync.Mutex
	token       string
	version     int
	uid         string
	data        map[string][]byte
	labels      map[string]string
	extra       map[string]json.RawMessage
	exists      bool
	puts        int
	conflicts   int
	putFaults   []putFault
	getFailures int
	getKind     string
}

// faultKind says how one PUT is answered.
type faultKind int

const (
	// faultApplyThen500 applies the write, then answers 500.
	faultApplyThen500 faultKind = iota + 1
	// fault500 answers 500 without applying.
	fault500
	// faultForbidden answers 403 without applying.
	faultForbidden
	// faultNotFound answers 404 without applying.
	faultNotFound
	// faultTooMany answers 429 with Retry-After: 1 without applying.
	faultTooMany
	// faultHold waits for its release, then applies the write if its
	// version still matches, as a request stuck in the API server would.
	faultHold
	// faultHoldAnswer applies the write at once, then holds the answer
	// until its release, as a reply lost on the way back would.
	faultHoldAnswer
)

type putFault struct {
	kind    faultKind
	release chan struct{}
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	api := &fakeAPI{
		t:       t,
		token:   testToken,
		version: 100,
		uid:     testUID,
		data:    map[string][]byte{},
		labels:  map[string]string{"app.kubernetes.io/name": "meshgw"},
		extra:   map[string]json.RawMessage{"immutable": json.RawMessage("false")},
		exists:  true,
		getKind: "Secret",
	}
	api.server = httptest.NewTLSServer(http.HandlerFunc(api.serve))
	t.Cleanup(api.server.Close)
	return api
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	path := "/api/v1/namespaces/" + testNamespace + "/secrets/" + testSecret
	if r.URL.Path != path {
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		return
	}
	a.mu.Lock()
	token := a.token
	a.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+token {
		writeStatus(w, http.StatusUnauthorized, "Unauthorized", "unauthorized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.serveGet(w)
	case http.MethodPut:
		a.servePut(w, r)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (a *fakeAPI) serveGet(w http.ResponseWriter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.getFailures > 0 {
		a.getFailures--
		writeStatus(w, http.StatusServiceUnavailable, "ServiceUnavailable", "unavailable")
		return
	}
	if !a.exists {
		writeStatus(w, http.StatusNotFound, "NotFound", `secrets "`+testSecret+`" not found`)
		return
	}
	body := a.bodyLocked()
	body["kind"] = json.RawMessage(strconv.Quote(a.getKind))
	writeJSON(w, http.StatusOK, body)
}

func (a *fakeAPI) servePut(w http.ResponseWriter, r *http.Request) {
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
	}
	var data map[string][]byte
	if json.Unmarshal(body["metadata"], &metadata) != nil || json.Unmarshal(body["data"], &data) != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	a.puts++
	var fault putFault
	if len(a.putFaults) > 0 {
		fault = a.putFaults[0]
		a.putFaults = a.putFaults[1:]
	}
	a.mu.Unlock()
	switch fault.kind {
	case fault500:
		writeStatus(w, http.StatusInternalServerError, "InternalError", "internal")
		return
	case faultForbidden:
		writeStatus(w, http.StatusForbidden, "Forbidden", "secrets is forbidden")
		return
	case faultNotFound:
		writeStatus(w, http.StatusNotFound, "NotFound", "not found")
		return
	case faultTooMany:
		w.Header().Set("Retry-After", "1")
		writeStatus(w, http.StatusTooManyRequests, "TooManyRequests", "slow down")
		return
	case faultHold:
		<-fault.release
	}

	a.mu.Lock()
	if metadata.ResourceVersion != strconv.Itoa(a.version) || metadata.UID != a.uid {
		a.conflicts++
		a.mu.Unlock()
		writeStatus(w, http.StatusConflict, "Conflict", "the object has been modified")
		return
	}
	if metadata.Name != testSecret || metadata.Namespace != testNamespace || string(body["type"]) != `"Opaque"` {
		a.mu.Unlock()
		writeStatus(w, http.StatusUnprocessableEntity, "Invalid", "bad metadata")
		return
	}
	a.version++
	a.data = maps.Clone(data)
	if a.data == nil {
		a.data = map[string][]byte{}
	}
	a.labels = maps.Clone(metadata.Labels)
	for key := range a.extra {
		a.extra[key] = body[key]
	}
	reply := a.bodyLocked()
	a.mu.Unlock()
	switch fault.kind {
	case faultApplyThen500:
		writeStatus(w, http.StatusInternalServerError, "InternalError", "internal")
		return
	case faultHoldAnswer:
		<-fault.release
	}
	writeJSON(w, http.StatusOK, reply)
}

// bodyLocked is the Secret as the API server sends it, with managed fields
// the mirror must not send back.
func (a *fakeAPI) bodyLocked() map[string]json.RawMessage {
	metadata, _ := json.Marshal(map[string]any{
		"name":            testSecret,
		"namespace":       testNamespace,
		"uid":             a.uid,
		"resourceVersion": strconv.Itoa(a.version),
		"labels":          a.labels,
		"managedFields":   []map[string]string{{"manager": "kubectl"}},
	})
	data, _ := json.Marshal(a.data)
	body := map[string]json.RawMessage{
		"apiVersion": json.RawMessage(`"v1"`),
		"kind":       json.RawMessage(`"Secret"`),
		"type":       json.RawMessage(`"Opaque"`),
		"metadata":   metadata,
		"data":       data,
	}
	maps.Copy(body, a.extra)
	return body
}

// writeForeign changes the Secret as another writer would.
func (a *fakeAPI) writeForeign(key string, value []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version++
	a.data[key] = bytes.Clone(value)
}

func (a *fakeAPI) deleteForeign(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version++
	delete(a.data, key)
}

func (a *fakeAPI) relabelForeign() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version++
	a.labels = maps.Clone(a.labels)
	a.labels["team"] = "platform"
}

// recreate deletes the Secret and creates it again empty, as kubectl
// replace or a GitOps prune would.
func (a *fakeAPI) recreate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version++
	a.uid = "6f1c1c3e-0000-4000-8000-000000000002"
	a.data = map[string][]byte{}
}

func (a *fakeAPI) value(key string) ([]byte, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	value, ok := a.data[key]
	return bytes.Clone(value), ok
}

func (a *fakeAPI) queue(kinds ...faultKind) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, kind := range kinds {
		a.putFaults = append(a.putFaults, putFault{kind: kind})
	}
}

// hold queues a PUT that waits in the server until the returned function is
// called. The test's end releases it too.
func (a *fakeAPI) hold() (release func()) { return a.gate(faultHold) }

// holdAnswer queues a PUT that lands at once but whose answer waits until
// the returned function is called.
func (a *fakeAPI) holdAnswer() (release func()) { return a.gate(faultHoldAnswer) }

func (a *fakeAPI) gate(kind faultKind) (release func()) {
	gate := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	a.t.Cleanup(release)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.putFaults = append(a.putFaults, putFault{kind: kind, release: gate})
	return release
}

func (a *fakeAPI) failGets(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.getFailures = n
}

func (a *fakeAPI) setToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = token
}

func (a *fakeAPI) counts() (puts, conflicts int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.puts, a.conflicts
}

// waitForPuts waits until the server has taken n PUTs, landed or not.
func (a *fakeAPI) waitForPuts(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if puts, _ := a.counts(); puts >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server took fewer than %d PUTs", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForValue waits until a released write has landed.
func (a *fakeAPI) waitForValue(t *testing.T, key, value string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, ok := a.value(key); ok && string(got) == value {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Secret[%s] never became %q", key, value)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// config points a mirror at the fake server, with the server's certificate
// as the cluster CA and a token file the test can rewrite.
func (a *fakeAPI) config(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatalf("WriteFile(ca) error = %v", err)
	}
	tokenFile := filepath.Join(dir, "token")
	writeToken(t, tokenFile, testToken)
	return Config{
		Server:     a.server.URL,
		CAFile:     caFile,
		TokenFile:  tokenFile,
		Namespace:  testNamespace,
		SecretName: testSecret,
		Timeout:    5 * time.Second,
	}
}

func writeToken(t *testing.T, path, token string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token) error = %v", err)
	}
}

func writeStatus(w http.ResponseWriter, code int, reason, message string) {
	writeJSON(w, code, map[string]any{
		"kind": "Status", "apiVersion": "v1", "status": "Failure",
		"reason": reason, "message": message, "code": code,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
