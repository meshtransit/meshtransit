package k8sstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	// maxSecretBytes bounds the data the mirror keeps, under the API server's
	// 1 MiB limit on a Secret's values with room for its metadata.
	maxSecretBytes = 768 << 10
	// maxAttempts bounds the PUTs one write makes.
	maxAttempts = 3
	// putShare is the share of a write's budget one PUT may take, so a read
	// back still fits after a PUT that timed out.
	putShare = 0.6
)

// valueHash identifies a sent value without keeping its bytes.
type valueHash [sha256.Size]byte

// ErrConflict means someone other than this mirror changed the Secret's data,
// such as a cloned replica writing the same identity. The mirror refuses
// every write after it: two processes must never share one Device.
var ErrConflict = errors.New("k8sstate: the Secret was changed by another writer")

// Mirror keeps one Secret equal to the state a gateway's stores write.
//
// All writes take one lock, so the identity and profile stores, which write
// under their own locks, never race each other's PUTs. Each write has one
// budget, Config.Timeout, for waiting on the lock and every request it makes,
// since the stores hold their locks while it runs.
//
// A write whose PUT gets no clear answer may still land later, so the mirror
// remembers every value it sent at the current version. A later read back
// takes any of them as its own; anything else is another writer's. A value
// skipped as unchanged is not checked against the Secret, so a foreign change
// that happens to equal it is caught only by the next real write.
//
// The mirror never deletes keys: the stores never remove files. It carries
// keys it does not know through every write, for a newer version's sake.
type Mirror struct {
	api     *apiClient
	timeout time.Duration
	lock    chan struct{}

	// The fields below are guarded by lock.
	current secret
	// sent holds, per key, the hash of every value PUT over the current
	// version that the API server may still apply. A new version ends them.
	sent   map[string][]valueHash
	broken error
}

// Open reads the Secret, which must exist: the manifest creates it, since
// RBAC cannot scope create to one name.
func Open(ctx context.Context, cfg Config) (*Mirror, error) {
	api, err := newAPIClient(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	current, err := api.get(ctx)
	if err != nil {
		api.close()
		return nil, fmt.Errorf("k8sstate: reading the state Secret: %w", err)
	}
	return &Mirror{api: api, timeout: cfg.Timeout, lock: make(chan struct{}, 1), current: current}, nil
}

// Close releases idle connections to the API server.
func (m *Mirror) Close() { m.api.close() }

// UID is the Secret's UID: tokens the gateway mints are bound to it.
func (m *Mirror) UID() string {
	m.lock <- struct{}{}
	defer func() { <-m.lock }()
	var uid string
	_ = json.Unmarshal(m.current.metadata["uid"], &uid)
	return uid
}

// Data returns a copy of the Secret's data as last seen.
func (m *Mirror) Data() map[string][]byte {
	m.lock <- struct{}{}
	defer func() { <-m.lock }()
	return cloneData(m.current.data)
}

// Hook returns a persist hook for a store whose file names go under prefix.
// Its type fits both identity.PersistHook and profile.PersistHook.
func (m *Mirror) Hook(prefix string) func(context.Context, string, []byte) error {
	return func(ctx context.Context, name string, data []byte) error {
		return m.Put(ctx, prefix+name, data)
	}
}

// Put stores value under key. It returns nil only once the Secret holds the
// value. On any other error the Secret may or may not hold it, which the
// stores allow: the mirror may run ahead of the directory, never behind.
func (m *Mirror) Put(ctx context.Context, key string, value []byte) error {
	if _, known, err := parseKey(key); err != nil || !known {
		return errors.Join(fmt.Errorf("k8sstate: %q is not a key of the state", key), err)
	}
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	select {
	case m.lock <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("k8sstate: writing %s: waiting for the mirror: %w", key, ctx.Err())
	}
	defer func() { <-m.lock }()
	if m.broken != nil {
		return m.broken
	}
	// Skipping is safe only when no other value of key may still land.
	if current, ok := m.current.data[key]; ok && bytes.Equal(current, value) && len(m.sent[key]) == 0 {
		return nil
	}
	deadline, _ := ctx.Deadline()
	putTimeout := time.Duration(float64(time.Until(deadline)) * putShare)
	hash := sha256.Sum256(value)

	for range maxAttempts {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("k8sstate: writing %s: %w", key, err)
		}
		next := withValue(cloneData(m.current.data), key, value)
		if size := dataSize(next); size > maxSecretBytes {
			return fmt.Errorf("k8sstate: the state would be %d bytes, over the %d-byte limit", size, maxSecretBytes)
		}
		if m.sent == nil {
			m.sent = map[string][]valueHash{}
		}
		m.sent[key] = append(m.sent[key], hash)
		putCtx, cancelPut := context.WithTimeout(ctx, putTimeout)
		written, err := m.api.put(putCtx, m.current, next)
		cancelPut()
		if err == nil {
			m.adopt(written)
			return nil
		}
		if notRun(err) {
			m.forget(key, hash)
			wait, retry := tooMany(err)
			if !retry {
				return fmt.Errorf("k8sstate: writing %s: %w", key, err)
			}
			if err := sleep(ctx, wait); err != nil {
				return fmt.Errorf("k8sstate: writing %s: waiting out a 429: %w", key, err)
			}
			continue
		}
		landed, err := m.settle(ctx, key, value)
		if err != nil || landed {
			return err
		}
	}
	return fmt.Errorf("k8sstate: writing %s: gave up after %d attempts", key, maxAttempts)
}

// settle reads the Secret back after a PUT that conflicted or got no clear
// answer, and reports whether it holds value under key. Any data that
// differs from what the mirror last saw must be a value the mirror sent;
// anything else is another writer's.
func (m *Mirror) settle(ctx context.Context, key string, value []byte) (bool, error) {
	current, err := m.api.get(ctx)
	if err != nil {
		// The value stays in sent, so a later read back still knows it.
		return false, fmt.Errorf("k8sstate: writing %s: the outcome is unknown: %w", key, err)
	}
	names := cloneData(current.data)
	for name := range m.current.data {
		names[name] = nil
	}
	names[key] = nil
	landed := true
	for name := range names {
		got, present := current.data[name]
		if name == key && present && bytes.Equal(got, value) {
			continue
		}
		unchanged := sameValue(current.data, m.current.data, name)
		ours := present && slices.Contains(m.sent[name], sha256.Sum256(got))
		switch {
		case !unchanged && !ours:
			m.broken = fmt.Errorf("%w: key %s", ErrConflict, name)
			return false, m.broken
		case name == key:
			landed = false
		}
	}
	m.adopt(current)
	return landed, nil
}

// adopt takes current as the Secret last seen. Once the version moves on, no
// value sent before can land: the API server refuses its older version.
func (m *Mirror) adopt(current secret) {
	if current.version != m.current.version {
		m.sent = nil
	}
	m.current = current
}

// forget drops one sent value the API server certainly did not apply.
func (m *Mirror) forget(key string, hash valueHash) {
	values := m.sent[key]
	if i := slices.Index(values, hash); i >= 0 {
		values = slices.Delete(values, i, i+1)
	}
	if len(values) == 0 {
		delete(m.sent, key)
		return
	}
	m.sent[key] = values
}

// sleep waits for d or until ctx ends, whichever comes first; it fails at
// once when ctx would end before d.
func sleep(ctx context.Context, d time.Duration) error {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < d {
		return context.DeadlineExceeded
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func sameValue(a, b map[string][]byte, key string) bool {
	x, inA := a[key]
	y, inB := b[key]
	return inA == inB && bytes.Equal(x, y)
}

func withValue(data map[string][]byte, key string, value []byte) map[string][]byte {
	data[key] = bytes.Clone(value)
	return data
}

func cloneData(data map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(data))
	for key, value := range data {
		cloned[key] = bytes.Clone(value)
	}
	return cloned
}

func dataSize(data map[string][]byte) int {
	size := 0
	for key, value := range data {
		size += len(key) + len(value)
	}
	return size
}
