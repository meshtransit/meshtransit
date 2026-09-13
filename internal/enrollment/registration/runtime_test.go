package registration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestExponentialBackoffValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		initial time.Duration
		maximum time.Duration
		entropy io.Reader
	}{
		{name: "zero initial", maximum: time.Second, entropy: bytes.NewReader(make([]byte, 8))},
		{name: "maximum below initial", initial: time.Second, maximum: time.Millisecond, entropy: bytes.NewReader(make([]byte, 8))},
		{name: "maximum too large", initial: time.Second, maximum: maxRetryDelay + time.Second, entropy: bytes.NewReader(make([]byte, 8))},
		{name: "missing entropy", initial: time.Second, maximum: time.Second},
	}
	for _, test := range tests {
		if _, err := newExponentialBackoff(test.initial, test.maximum, test.entropy); !errors.Is(err, ErrInvalidBackoff) {
			t.Fatalf("newExponentialBackoff(%s) error = %v, want ErrInvalidBackoff", test.name, err)
		}
	}
}

func TestExponentialBackoffWait(t *testing.T) {
	t.Parallel()

	backoff, err := newExponentialBackoff(time.Nanosecond, 4*time.Nanosecond, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("newExponentialBackoff() error = %v", err)
	}
	if err := backoff.Wait(t.Context(), 3); err != nil {
		t.Fatalf("ExponentialBackoff.Wait() error = %v", err)
	}
	if err := backoff.Wait(t.Context(), 0); !errors.Is(err, ErrInvalidBackoff) {
		t.Fatalf("ExponentialBackoff.Wait(0) error = %v, want ErrInvalidBackoff", err)
	}
	if err := (*ExponentialBackoff)(nil).Wait(t.Context(), 1); !errors.Is(err, ErrInvalidBackoff) {
		t.Fatalf("nil ExponentialBackoff.Wait() error = %v, want ErrInvalidBackoff", err)
	}
}

func TestExponentialBackoffHonorsCancellationAndEntropyFailure(t *testing.T) {
	t.Parallel()

	backoff, err := newExponentialBackoff(time.Second, time.Second, bytes.NewReader(make([]byte, 8)))
	if err != nil {
		t.Fatalf("newExponentialBackoff() error = %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := backoff.Wait(canceled, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("ExponentialBackoff.Wait(canceled) error = %v, want context.Canceled", err)
	}

	wantErr := errors.New("entropy unavailable")
	backoff, err = newExponentialBackoff(time.Second, time.Second, failingEntropy{err: wantErr})
	if err != nil {
		t.Fatalf("newExponentialBackoff(failing entropy) error = %v", err)
	}
	if err := backoff.Wait(t.Context(), 1); !errors.Is(err, wantErr) {
		t.Fatalf("ExponentialBackoff.Wait(failing entropy) error = %v, want wrapped error", err)
	}
}

func TestRuntimeDefaultsProduceValidValues(t *testing.T) {
	t.Parallel()

	if now := (SystemClock{}).Now(); now.IsZero() || now.Location() != time.UTC {
		t.Fatalf("SystemClock.Now() = %v, want non-zero UTC", now)
	}
	nodeID, err := (PublicNodeIDGenerator{}).NewNodeID()
	if err != nil {
		t.Fatalf("PublicNodeIDGenerator.NewNodeID() error = %v", err)
	}
	if !nodeID.IsValid() {
		t.Fatal("PublicNodeIDGenerator.NewNodeID() returned invalid ID")
	}
	if _, err := NewExponentialBackoff(time.Millisecond, time.Second); err != nil {
		t.Fatalf("NewExponentialBackoff() error = %v", err)
	}
}

type failingEntropy struct {
	err error
}

func (reader failingEntropy) Read([]byte) (int, error) { return 0, reader.err }
