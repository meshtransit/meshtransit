package k8sstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	keyA       = "identity.0000000000000000000000000000000a.json"
	keyB       = "identity.0000000000000000000000000000000b.json"
	keyProfile = "profile.profiles.json"
)

func openMirror(t *testing.T, api *fakeAPI) *Mirror {
	t.Helper()
	return openMirrorWith(t, api.config(t))
}

func openMirrorWith(t *testing.T, cfg Config) *Mirror {
	t.Helper()
	mirror, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(mirror.Close)
	return mirror
}

// putBriefly writes with a 200 ms deadline, for writes whose PUTs the
// server holds.
func putBriefly(t *testing.T, mirror *Mirror, key, value string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	return mirror.Put(ctx, key, []byte(value))
}

func put(t *testing.T, mirror *Mirror, key, value string) error {
	t.Helper()
	return mirror.Put(t.Context(), key, []byte(value))
}

func mustPut(t *testing.T, mirror *Mirror, key, value string) {
	t.Helper()
	if err := put(t, mirror, key, value); err != nil {
		t.Fatalf("Put(%s, %q) error = %v", key, value, err)
	}
}

func wantStored(t *testing.T, api *fakeAPI, key, value string) {
	t.Helper()
	got, ok := api.value(key)
	if !ok || string(got) != value {
		t.Fatalf("Secret[%s] = %q (present %v), want %q", key, got, ok, value)
	}
}

func wantPuts(t *testing.T, api *fakeAPI, want int) {
	t.Helper()
	if puts, _ := api.counts(); puts != want {
		t.Fatalf("puts = %d, want %d", puts, want)
	}
}

// Open reads the Secret as it is, and each write lands in it under the
// resourceVersion the mirror last saw, keeping the other keys, the labels
// and top-level fields it does not know.
func TestMirrorWritesOverTheVersionItLastSaw(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	api.writeForeign(keyProfile, []byte("before"))
	mirror := openMirror(t, api)

	if got := mirror.Data()[keyProfile]; string(got) != "before" {
		t.Fatalf("Data() = %q, want the Secret's", got)
	}
	mustPut(t, mirror, keyA, "one")
	mustPut(t, mirror, keyA, "two")
	wantStored(t, api, keyA, "two")
	wantStored(t, api, keyProfile, "before")
	wantPuts(t, api, 2)
	api.mu.Lock()
	label, immutable := api.labels["app.kubernetes.io/name"], string(api.extra["immutable"])
	api.mu.Unlock()
	if label != "meshgw" || immutable != "false" {
		t.Fatalf("a write dropped metadata: label %q, immutable %q", label, immutable)
	}
}

// Writing what the Secret already holds sends nothing.
func TestMirrorSkipsAnUnchangedValue(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	mustPut(t, mirror, keyA, "one")
	mustPut(t, mirror, keyA, "one")
	wantPuts(t, api, 1)
}

// The service account token is read for every request, since the kubelet
// rotates it.
func TestMirrorRereadsTheToken(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	cfg := api.config(t)
	mirror := openMirrorWith(t, cfg)
	api.setToken("token-two")
	writeToken(t, cfg.TokenFile, "token-two")
	mustPut(t, mirror, keyA, "one")
}

// A 5xx after the write is settled by reading the Secret back: it holds the
// value, so the write succeeded without a second PUT.
func TestMirrorSettlesAWriteThatLanded(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	api.queue(faultApplyThen500)
	mustPut(t, mirror, keyA, "one")
	wantStored(t, api, keyA, "one")
	wantPuts(t, api, 1)
	mustPut(t, mirror, keyA, "two")
	wantStored(t, api, keyA, "two")
}

// A 5xx that did not apply the write is retried over the same version.
func TestMirrorRetriesAWriteThatDidNotLand(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	api.queue(fault500)
	mustPut(t, mirror, keyA, "one")
	wantStored(t, api, keyA, "one")
	wantPuts(t, api, 2)
}

// A write that runs out of time while its PUT is still in the API server
// fails, and the PUT may land later. The next write then meets a conflict
// and must take the late value as the mirror's own, not as another writer's.
func TestMirrorAcceptsALateLanding(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	release := api.hold()
	api.queue(fault500, fault500)
	if err := putBriefly(t, mirror, keyA, "one"); err == nil {
		t.Fatal("Put() with its PUT held succeeded")
	}
	release()
	api.waitForValue(t, keyA, "one")

	mustPut(t, mirror, keyProfile, "p")
	wantStored(t, api, keyA, "one")
	wantStored(t, api, keyProfile, "p")
}

// Every value sent for a key at one version may land, not only the last.
func TestMirrorRemembersEveryUncertainValue(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	mustPut(t, mirror, keyA, "v0")
	release := api.hold()
	api.queue(fault500, fault500)
	if err := putBriefly(t, mirror, keyA, "v1"); err == nil {
		t.Fatal("Put(v1) with its PUT held succeeded")
	}
	// v2 is sent at the same version while v1 is still held, and ends the
	// same way, so the mirror has two values of one key in flight.
	api.hold()
	api.queue(fault500, fault500)
	if err := putBriefly(t, mirror, keyA, "v2"); err == nil {
		t.Fatal("Put(v2) with its PUT held succeeded")
	}
	release()
	api.waitForValue(t, keyA, "v1")

	mustPut(t, mirror, keyProfile, "p")
	wantStored(t, api, keyProfile, "p")
}

// After a write whose outcome is unknown, writing the old value again is a
// real write: the Secret may hold the newer one.
func TestMirrorRewritesAfterAnUncertainValue(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	mustPut(t, mirror, keyA, "v0")
	api.queue(faultApplyThen500)
	api.failGets(1)
	if err := put(t, mirror, keyA, "v1"); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("Put(v1) error = %v, want a plain failure", err)
	}
	wantStored(t, api, keyA, "v1")
	mustPut(t, mirror, keyA, "v0")
	wantStored(t, api, keyA, "v0")
}

// A write with no answer whose read back fails too is reported as failed;
// the next write settles it.
func TestMirrorSettlesAnUnknownOutcomeLater(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	api.queue(faultApplyThen500)
	api.failGets(1)
	if err := put(t, mirror, keyA, "one"); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("Put() error = %v, want a plain failure", err)
	}
	mustPut(t, mirror, keyProfile, "p")
	wantStored(t, api, keyA, "one")
	wantStored(t, api, keyProfile, "p")
}

// Any data change the mirror did not make means a second writer, such as a
// cloned replica: the mirror stops for good rather than overwrite it.
func TestMirrorStopsOnAForeignWrite(t *testing.T) {
	t.Parallel()
	changes := map[string]func(*fakeAPI){
		"the same key":       func(api *fakeAPI) { api.writeForeign(keyA, []byte("theirs")) },
		"another key":        func(api *fakeAPI) { api.writeForeign(keyB, []byte("theirs")) },
		"a deleted key":      func(api *fakeAPI) { api.deleteForeign(keyA) },
		"a recreated Secret": func(api *fakeAPI) { api.recreate() },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api := newFakeAPI(t)
			mirror := openMirror(t, api)
			mustPut(t, mirror, keyA, "one")
			change(api)
			if err := put(t, mirror, keyA, "two"); !errors.Is(err, ErrConflict) {
				t.Fatalf("Put() error = %v, want ErrConflict", err)
			}
			if err := put(t, mirror, keyB, "three"); !errors.Is(err, ErrConflict) {
				t.Fatalf("Put() after a conflict error = %v, want ErrConflict", err)
			}
		})
	}
}

// A change to the labels alone moves the version but not the data: the write
// goes through over the new version.
func TestMirrorWritesOverALabelChange(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	mustPut(t, mirror, keyA, "one")
	api.relabelForeign()
	mustPut(t, mirror, keyA, "two")
	wantStored(t, api, keyA, "two")
	api.mu.Lock()
	team := api.labels["team"]
	api.mu.Unlock()
	if team != "platform" {
		t.Fatalf("the write dropped the new label: %q", team)
	}
}

// A refusal fails the write without retry or conflict, and leaves nothing
// unsettled: the same value is sent again next time.
func TestMirrorFailsOnARefusal(t *testing.T) {
	t.Parallel()
	for name, kind := range map[string]faultKind{"403": faultForbidden, "404": faultNotFound} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api := newFakeAPI(t)
			mirror := openMirror(t, api)
			api.queue(kind)
			err := put(t, mirror, keyA, "one")
			if err == nil || errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), name) {
				t.Fatalf("Put() error = %v, want a plain %s failure", err, name)
			}
			if _, ok := api.value(keyA); ok {
				t.Fatal("a refused write reached the Secret")
			}
			mustPut(t, mirror, keyA, "one")
			wantPuts(t, api, 2)
		})
	}
}

// 429 means the API server did not run the request: the write waits as told
// and tries again within its budget.
func TestMirrorWaitsOutTooManyRequests(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	api.queue(faultTooMany)
	started := time.Now()
	mustPut(t, mirror, keyA, "one")
	if waited := time.Since(started); waited < time.Second {
		t.Fatalf("retried after %s, before Retry-After", waited)
	}
	wantStored(t, api, keyA, "one")
	wantPuts(t, api, 2)
}

// One write takes at most its budget, however the API server behaves, since
// the stores call it under their locks.
func TestMirrorBoundsAWrite(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	api.hold()
	api.hold()
	api.hold()
	started := time.Now()
	if err := putBriefly(t, mirror, keyA, "one"); err == nil {
		t.Fatal("Put() with its PUT held succeeded")
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("Put() took %s, over its 200 ms deadline", took)
	}
}

// A writer waiting for the mirror gives up with its context.
func TestMirrorLockHonoursTheContext(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	release := api.hold()
	first := make(chan error, 1)
	go func() { first <- put(t, mirror, keyA, "one") }()
	api.waitForPuts(t, 1)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := mirror.Put(ctx, keyB, []byte("two")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting Put() error = %v, want its deadline", err)
	}
	release()
	if err := <-first; err != nil {
		t.Fatalf("held Put() error = %v", err)
	}
}

// A context already done sends nothing.
func TestMirrorHonoursACancelledContext(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := mirror.Put(ctx, keyA, []byte("one")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put() error = %v, want context.Canceled", err)
	}
	wantPuts(t, api, 0)
}

// The identity and profile stores write under their own locks, so their
// hooks run at once; one lock keeps their PUTs from racing each other.
func TestMirrorSerializesConcurrentWrites(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	identityHook := mirror.Hook(IdentityKeyPrefix)
	profileHook := mirror.Hook(ProfileKeyPrefix)

	var writers sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 20 {
		writers.Add(2)
		go func() {
			defer writers.Done()
			errs <- identityHook(t.Context(), "0000000000000000000000000000000a.json", []byte(fmt.Sprint("identity ", i)))
		}()
		go func() {
			defer writers.Done()
			errs <- profileHook(t.Context(), "profiles.json", []byte(fmt.Sprint("profile ", i)))
		}()
	}
	writers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("hook error = %v", err)
		}
	}
	if _, conflicts := api.counts(); conflicts != 0 {
		t.Fatalf("conflicts = %d, want none", conflicts)
	}
	if _, ok := api.value(keyA); !ok {
		t.Fatal("identity key missing")
	}
	if _, ok := api.value(keyProfile); !ok {
		t.Fatal("profile key missing")
	}
}

// The hook does not keep the caller's slice, which the identity store zeroes
// after the write.
func TestMirrorHookCopiesTheValue(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	value := []byte("secret record")
	if err := mirror.Hook(IdentityKeyPrefix)(t.Context(), "0000000000000000000000000000000a.json", value); err != nil {
		t.Fatalf("hook error = %v", err)
	}
	clear(value)
	if got := mirror.Data()[keyA]; string(got) != "secret record" {
		t.Fatalf("Data() = %q after the caller cleared its slice", got)
	}
	mustPut(t, mirror, keyA, "secret record")
	wantPuts(t, api, 1)
}

// A key Restore would refuse never reaches the Secret, so a write cannot
// leave a pod that fails to start.
func TestMirrorRefusesAKeyRestoreWouldRefuse(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	for _, key := range []string{"exit-pins.json", "identity.../profiles.json", "profile.other.json", "identity.A.json"} {
		if err := put(t, mirror, key, "x"); err == nil {
			t.Errorf("Put(%q) error = nil, want a refusal", key)
		}
	}
	wantPuts(t, api, 0)
}

// A write that would push the Secret past its size limit fails before it is
// sent.
func TestMirrorRefusesAnOversizedSecret(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	err := mirror.Put(t.Context(), keyA, bytes.Repeat([]byte{'x'}, maxSecretBytes))
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("Put() error = %v, want a size limit error", err)
	}
	wantPuts(t, api, 0)
}

// Open needs the Secret to exist, as the manifest creates it: RBAC cannot
// scope create to one name. It also refuses an answer that is not a Secret.
func TestOpenNeedsTheSecret(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	api.mu.Lock()
	api.exists = false
	api.mu.Unlock()
	if _, err := Open(t.Context(), api.config(t)); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("Open() error = %v, want a not-found error", err)
	}

	other := newFakeAPI(t)
	other.mu.Lock()
	other.getKind = "ConfigMap"
	other.mu.Unlock()
	if _, err := Open(t.Context(), other.config(t)); err == nil || !strings.Contains(err.Error(), "ConfigMap") {
		t.Fatalf("Open() error = %v, want a wrong-kind error", err)
	}
}

// A PUT that takes too long gives up early enough that the read back still
// fits in the budget, so a write that landed is reported as done.
func TestMirrorReadsBackAfterASlowPUT(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	cfg := api.config(t)
	cfg.Timeout = time.Second
	mirror := openMirrorWith(t, cfg)
	api.holdAnswer()
	if err := put(t, mirror, keyA, "one"); err != nil {
		t.Fatalf("Put() error = %v, want the read back to find the value", err)
	}
	wantStored(t, api, keyA, "one")
	wantPuts(t, api, 1)
}
