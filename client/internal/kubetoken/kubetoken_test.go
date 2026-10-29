package kubetoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI answers TokenRequests: each a new token whose jti counts up,
// unless answer says otherwise. With hold set, answers wait for it to
// close; entered then receives each request as it arrives.
type fakeAPI struct {
	server   *httptest.Server
	requests atomic.Int64
	entered  chan struct{}
	mu       sync.Mutex
	bodies   []tokenRequest
	paths    []string
	auth     []string
	answer   func(n int64, w http.ResponseWriter) bool // true: answered
	hold     chan struct{}
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	api := &fakeAPI{entered: make(chan struct{}, 64)}
	api.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := api.requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		var decoded tokenRequest
		_ = json.Unmarshal(body, &decoded)
		api.mu.Lock()
		api.bodies, api.paths = append(api.bodies, decoded), append(api.paths, r.Method+" "+r.URL.Path)
		api.auth = append(api.auth, r.Header.Get("Authorization"))
		answer, hold := api.answer, api.hold
		api.mu.Unlock()
		select {
		case api.entered <- struct{}{}:
		default:
		}
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		if answer != nil && answer(n, w) {
			return
		}
		claims, _ := json.Marshal(map[string]any{"jti": fmt.Sprintf("01890f00-0000-7000-8000-%012d", n)})
		token := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"kind":"TokenRequest","status":{"token":%q,"expirationTimestamp":%q}}`, token,
			time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(api.server.Close)
	return api
}

func (api *fakeAPI) set(change func(*fakeAPI)) {
	api.mu.Lock()
	defer api.mu.Unlock()
	change(api)
}

func (api *fakeAPI) await(t *testing.T) {
	t.Helper()
	select {
	case <-api.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no TokenRequest")
	}
}

func testOptions(t *testing.T, api *fakeAPI) Options {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	certificate := api.server.Certificate()
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("gateway-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := DefaultOptions()
	options.Server, options.CAFile, options.TokenFile = api.server.URL, ca, token
	options.Namespace, options.PodName, options.PodUID = "meshtransit", "meshgw-0", "uid-0"
	return options
}

func newMinter(t *testing.T, options Options) *Minter {
	t.Helper()
	minter, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	return minter
}

// A token is minted for the group's service account, bound to the pod, with
// the gateway's own token; it is kept for its key and carries its jti.
func TestMinterMintsAndKeeps(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	minter := newMinter(t, testOptions(t, api))
	first, err := minter.For(t.Context(), "device-a", "owner-1", "view")
	if err != nil {
		t.Fatal(err)
	}
	again, err := minter.For(t.Context(), "device-a", "owner-1", "view")
	if err != nil || again.Value() != first.Value() || api.requests.Load() != 1 {
		t.Fatalf("again: %v, %d requests", err, api.requests.Load())
	}
	for _, other := range [][2]string{{"device-b", "owner-1"}, {"device-a", "owner-2"}} {
		token, err := minter.For(t.Context(), other[0], other[1], "view")
		if err != nil || token.Value() == first.Value() {
			t.Fatalf("%v: %v", other, err)
		}
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	body := api.bodies[0]
	if api.paths[0] != "POST /api/v1/namespaces/meshtransit/serviceaccounts/mt-view/token" ||
		api.auth[0] != "Bearer gateway-token" || body.Kind != "TokenRequest" ||
		body.Spec.ExpirationSeconds != 600 || body.Spec.BoundObjectRef.Kind != "Pod" ||
		body.Spec.BoundObjectRef.Name != "meshgw-0" || body.Spec.BoundObjectRef.UID != "uid-0" ||
		len(body.Spec.Audiences) != 0 {
		t.Fatalf("request %s %s %+v", api.paths[0], api.auth[0], body)
	}
	if len(first.ID()) != 16 || first.Expires().Before(time.Now().Add(9*time.Minute)) {
		t.Fatalf("token id %x expires %v", first.ID(), first.Expires())
	}
}

// From its refresh time the kept token is still handed out while a new one
// is minted in the background (review b3 H1).
func TestMinterRefreshesInTheBackground(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	options := testOptions(t, api)
	now := time.Now()
	var clock atomic.Pointer[time.Time]
	clock.Store(&now)
	options.Now = func() time.Time { return *clock.Load() }
	minter := newMinter(t, options)
	first, err := minter.For(t.Context(), "a", "o", "view")
	if err != nil {
		t.Fatal(err)
	}
	api.await(t)
	before := now.Add(10*time.Minute - 4*time.Minute - time.Second)
	clock.Store(&before)
	if token, _ := minter.For(t.Context(), "a", "o", "view"); token.Value() != first.Value() || api.requests.Load() != 1 {
		t.Fatalf("before the window: %d requests", api.requests.Load())
	}
	hold := make(chan struct{})
	api.set(func(api *fakeAPI) { api.hold = hold })
	inWindow := now.Add(10*time.Minute - 2*time.Minute + time.Second)
	clock.Store(&inWindow)
	if token, err := minter.For(t.Context(), "a", "o", "view"); err != nil || token.Value() != first.Value() {
		t.Fatalf("in the window: %v", err)
	}
	api.await(t) // the refresh runs while the old token serves
	close(hold)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if token, _ := minter.For(t.Context(), "a", "o", "view"); token.Value() != first.Value() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background refresh never landed")
		}
	}
	// Past the usable margin, a caller waits for a new token.
	expired := now.Add(30 * time.Minute)
	clock.Store(&expired)
	token, err := minter.For(t.Context(), "a", "o", "view")
	if err != nil || token.Value() == first.Value() || api.requests.Load() != 3 {
		t.Fatalf("past expiry: %v, %d requests", err, api.requests.Load())
	}
}

// Callers of one key share one mint; the first caller giving up fails no
// one else.
func TestMinterSharesOneMint(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	hold := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-hold:
		default:
			close(hold)
		}
	})
	api.set(func(api *fakeAPI) { api.hold = hold })
	minter := newMinter(t, testOptions(t, api))
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() {
		_, err := minter.For(ctx, "a", "o", "view")
		first <- err
	}()
	api.await(t)
	results := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := minter.For(t.Context(), "a", "o", "view")
			results <- err
		}()
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled caller: %v", err)
	}
	minter.mu.Lock()
	flights := len(minter.flights)
	minter.mu.Unlock()
	if flights != 1 {
		t.Fatalf("%d flights", flights)
	}
	close(hold)
	for range 3 {
		if err := <-results; err != nil {
			t.Fatalf("a follower failed: %v", err)
		}
	}
	if n := api.requests.Load(); n != 1 {
		t.Fatalf("%d mints", n)
	}
}

// Past the mint rate a mint waits its turn when it fits in QueueWait, and
// fails at once when it does not (review b3 M3).
func TestMinterQueuesMints(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	options := testOptions(t, api)
	options.Rate, options.Burst, options.QueueWait = 20, 1, time.Second
	minter := newMinter(t, options)
	for _, device := range []string{"a", "b"} {
		if _, err := minter.For(t.Context(), device, "o", "view"); err != nil {
			t.Fatalf("%s: %v", device, err)
		}
	}
	options.Rate, options.QueueWait = 0.5, 100*time.Millisecond
	slow := newMinter(t, options)
	if _, err := slow.For(t.Context(), "a", "o", "view"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := slow.For(t.Context(), "b", "o", "view"); !errors.Is(err, ErrLimited) ||
		time.Since(started) > 50*time.Millisecond {
		t.Fatalf("over the queue: %v after %v", err, time.Since(started))
	}
}

// A refusal is a MintError with its status, cleaned reason and wait; the
// key then backs off; it is never kept as a token.
func TestMinterRefusals(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	api.set(func(api *fakeAPI) {
		api.answer = func(_ int64, w http.ResponseWriter) bool {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"kind":"Status","reason":"TooManyRequests\nX","message":"secret stuff"}`)
			return true
		}
	})
	options := testOptions(t, api)
	options.QueueWait = time.Second
	minter := newMinter(t, options)
	_, err := minter.For(t.Context(), "a", "o", "view")
	var refused *MintError
	if !errors.As(err, &refused) || refused.Status != 429 || refused.Reason != "TooManyRequestsX" ||
		refused.RetryAfter != 3*time.Second || strings.Contains(err.Error(), "secret") {
		t.Fatalf("refusal: %v", err)
	}
	api.set(func(api *fakeAPI) { api.answer = nil })
	if _, err := minter.For(t.Context(), "a", "o", "view"); !errors.As(err, &refused) || api.requests.Load() != 1 {
		t.Fatalf("backing off: %v, %d requests", err, api.requests.Load())
	}
	// A 429 holds the whole gateway for its wait: another key fails at once
	// when the wait is past QueueWait.
	if _, err := minter.For(t.Context(), "b", "o", "view"); !errors.Is(err, ErrLimited) || api.requests.Load() != 1 {
		t.Fatalf("another key while held: %v", err)
	}
}

// Answers out of form, or a token too short-lived, give no token.
func TestMinterRefusesAnswersOutOfForm(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"not JSON":       `{`,
		"no token":       `{"status":{"expirationTimestamp":"2099-01-01T00:00:00Z"}}`,
		"no expiry":      `{"status":{"token":"a.e30.c"}}`,
		"bad characters": `{"status":{"token":"a.e30.c\r\nX: y","expirationTimestamp":"2099-01-01T00:00:00Z"}}`,
		"expired":        `{"status":{"token":"a.e30.c","expirationTimestamp":"2000-01-01T00:00:00Z"}}`,
		"short claims":   `{"status":{"token":"a.` + base64.RawURLEncoding.EncodeToString([]byte(`{"iat":100,"exp":130}`)) + `.c","expirationTimestamp":"2099-01-01T00:00:00Z"}}`,
		"over the size":  `{"status":{"token":"` + strings.Repeat("a", maxResponse) + `"}}`,
	} {
		api := newFakeAPI(t)
		api.set(func(api *fakeAPI) {
			api.answer = func(_ int64, w http.ResponseWriter) bool {
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, body)
				return true
			}
		})
		minter := newMinter(t, testOptions(t, api))
		if token, err := minter.For(t.Context(), "a", "o", "view"); err == nil {
			t.Errorf("%s: a token %v", name, token)
		}
	}
}

// A token's life is measured on the minter's clock: a clock far off the
// API server's keeps tokens all the same (review b3 M2).
func TestMinterLivesByItsOwnClock(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	options := testOptions(t, api)
	ahead := time.Now().Add(2 * time.Hour)
	options.Now = func() time.Time { return ahead }
	minter := newMinter(t, options)
	token, err := minter.For(t.Context(), "a", "o", "view")
	if err != nil || token.Expires().Sub(ahead) < 9*time.Minute {
		t.Fatalf("token %v, %v", token, err)
	}
	if _, err := minter.For(t.Context(), "a", "o", "view"); err != nil || api.requests.Load() != 1 {
		t.Fatalf("not kept: %d requests", api.requests.Load())
	}
}

// Close answers callers waiting on a mint, refuses new ones and waits for
// mints to end.
func TestMinterClose(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	hold := make(chan struct{})
	api.set(func(api *fakeAPI) { api.hold = hold })
	minter, err := New(testOptions(t, api))
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() {
		_, err := minter.For(t.Context(), "a", "o", "view")
		waiting <- err
	}()
	api.await(t)
	closed := make(chan struct{})
	go func() {
		minter.Close()
		close(closed)
	}()
	if err := <-waiting; !errors.Is(err, ErrClosed) {
		t.Fatalf("a waiting caller: %v", err)
	}
	<-closed
	close(hold)
	if _, err := minter.For(t.Context(), "b", "o", "view"); !errors.Is(err, ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
}

// Forget drops a token the API server refused, but not one minted since.
func TestMinterForgets(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	minter := newMinter(t, testOptions(t, api))
	refused, _ := minter.For(t.Context(), "a", "o", "view")
	minter.Forget("a", "o", "view", refused)
	fresh, err := minter.For(t.Context(), "a", "o", "view")
	if err != nil || fresh.Value() == refused.Value() {
		t.Fatalf("after Forget: %v", err)
	}
	minter.Forget("a", "o", "view", refused) // an older token: the fresh one stays
	if kept, _ := minter.For(t.Context(), "a", "o", "view"); kept.Value() != fresh.Value() {
		t.Fatal("Forget of an old token dropped the fresh one")
	}
}

// Past its capacity the least recently used token is dropped.
func TestMinterEvictsTheLeastRecentlyUsed(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	options := testOptions(t, api)
	options.Capacity = 2
	minter := newMinter(t, options)
	for _, device := range []string{"a", "b", "a", "c", "a"} {
		if _, err := minter.For(t.Context(), device, "o", "view"); err != nil {
			t.Fatal(err)
		}
	}
	if n := api.requests.Load(); n != 3 {
		t.Fatalf("%d mints, want a, b and c once", n)
	}
	if _, err := minter.For(t.Context(), "b", "o", "view"); err != nil || api.requests.Load() != 4 {
		t.Fatal("b was kept past the capacity")
	}
}

// A token's value never formats, alone or inside a struct, exported field
// or not, through fmt or either slog handler (review b3 M1).
func TestTokenRedacts(t *testing.T) {
	t.Parallel()
	token := Token{held: &secret{value: "secret-value", id: []byte{1}}}
	type inner struct {
		device string
		token  Token
	}
	type outer struct {
		Device string
		Token  Token
	}
	texts := []string{
		fmt.Sprint(token), fmt.Sprintf("%#v", token), fmt.Sprintf("%+v", token),
		fmt.Sprintf("%+v", inner{device: "d", token: token}), fmt.Sprintf("%#v", inner{token: token}),
		fmt.Sprintf("%+v", outer{Token: token}), fmt.Sprintf("%v", []Token{token}),
	}
	for _, handler := range []func(io.Writer) slog.Handler{
		func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
		func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		var out bytes.Buffer
		slog.New(handler(&out)).Info("m", "token", token, "inner", inner{token: token}, "outer", outer{Token: token})
		texts = append(texts, out.String())
	}
	for _, text := range texts {
		if strings.Contains(text, "secret-value") {
			t.Fatalf("formatted: %s", text)
		}
	}
}

// Keys and options out of form are refused before any request.
func TestMinterRefusesBadKeysAndOptions(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	minter := newMinter(t, testOptions(t, api))
	for _, id := range [][3]string{
		{"", "o", "view"}, {"a", "", "view"}, {"a", "o", ""}, {"a", "o", "View"}, {"a", "o", "a/b"},
		{"a", "o", "../x"}, {"a", "o", strings.Repeat("a", 64)},
	} {
		if _, err := minter.For(t.Context(), id[0], id[1], id[2]); err == nil {
			t.Errorf("%q taken", id)
		}
	}
	if api.requests.Load() != 0 {
		t.Fatal("a bad key reached the API server")
	}
	for name, change := range map[string]func(*Options){
		"http":       func(options *Options) { options.Server = "http://a" },
		"userinfo":   func(options *Options) { options.Server = "https://u:p@a" },
		"query":      func(options *Options) { options.Server = "https://a?x=1" },
		"no pod UID": func(options *Options) { options.PodUID = "" },
		"short life": func(options *Options) { options.ExpirationSeconds = 300 },
	} {
		options := testOptions(t, api)
		change(&options)
		if _, err := New(options); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// A token's ID is its jti: a UUID's 16 bytes, else the first 16 bytes of
// the jti's SHA-256; none without a jti.
func TestTokenID(t *testing.T) {
	t.Parallel()
	encode := func(claims string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"
	}
	if id := tokenID(encode(`{"jti":"01890f00-0000-7000-8000-000000000001"}`)); len(id) != 16 || id[15] != 1 {
		t.Fatalf("UUID jti: %x", id)
	}
	if id := tokenID(encode(`{"jti":"not-a-uuid"}`)); len(id) != 16 {
		t.Fatalf("other jti: %x", id)
	}
	for _, token := range []string{encode(`{}`), "garbage", encode(`not json`), "a.b"} {
		if id := tokenID(token); id != nil {
			t.Fatalf("%q: %x", token, id)
		}
	}
}
