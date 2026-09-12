package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunRejectsInvalidConfigurationBeforeListening(t *testing.T) {
	t.Parallel()

	lookup := func(key string) (string, bool) {
		if key == "MESHTRANSIT_ROLE" {
			return "unknown", true
		}
		return "", false
	}
	var errorOutput bytes.Buffer

	exitCode := run(context.Background(), lookup, &errorOutput)
	if exitCode != 1 {
		t.Fatalf("run() = %d, want 1", exitCode)
	}
	if !strings.Contains(errorOutput.String(), `"msg":"startup failed"`) {
		t.Fatalf("error output = %q, want structured startup failure", errorOutput.String())
	}
	if strings.Contains(errorOutput.String(), "unknown") {
		t.Fatalf("error output exposed invalid configuration value: %s", errorOutput.String())
	}
}
