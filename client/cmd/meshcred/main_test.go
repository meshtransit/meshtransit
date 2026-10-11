//go:build !darwin

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRejectsUnsupportedArguments(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"unknown"}, {"rotate", "extra"}} {
		stderr := &bytes.Buffer{}
		if code := run(args, stderr); code != 2 {
			t.Fatalf("run(%v) = %d, want 2", args, code)
		}
		if !strings.HasPrefix(stderr.String(), "usage: meshcred ") {
			t.Fatalf("run(%v) stderr = %q, want usage", args, stderr.String())
		}
	}
}

func TestRunOfflineRequiresOperation(t *testing.T) {
	t.Parallel()

	if err := runOffline(t.Context(), nil); err == nil {
		t.Fatal("runOffline(nil) error = nil")
	}
}

func TestDaemonStoppedStates(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		state    string
		expected bool
	}{
		{state: "inactive\n", expected: true},
		{state: "failed\n", expected: true},
		{state: "active\n", expected: false},
		{state: "activating\n", expected: false},
		{state: "deactivating\n", expected: false},
		{state: "", expected: false},
	} {
		if actual := isDaemonStopped([]byte(test.state)); actual != test.expected {
			t.Errorf("isDaemonStopped(%q) = %t, want %t", test.state, actual, test.expected)
		}
	}
}
