package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestBootstrapCommandFailsClosedWithoutConfiguration(t *testing.T) {
	t.Parallel()
	lookup := func(string) (string, bool) { return "", false }
	for _, args := range [][]string{{"bootstrap", "check"}, {"bootstrap", "apply"}} {
		var output, errorOutput bytes.Buffer
		if code := execute(t.Context(), args, lookup, &output, &errorOutput); code != 1 || output.Len() != 0 ||
			!strings.Contains(errorOutput.String(), "invalid_bootstrap_configuration") {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, output.String(), errorOutput.String())
		}
	}
	var output, errorOutput bytes.Buffer
	if code := execute(t.Context(), []string{"bootstrap", "delete"}, lookup, &output, &errorOutput); code != 2 {
		t.Fatalf("unknown bootstrap operation code = %d", code)
	}
}
