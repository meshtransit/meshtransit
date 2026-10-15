package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestAccountCommandFailsClosed(t *testing.T) {
	t.Parallel()
	lookup := func(string) (string, bool) { return "", false }
	const principal = "01890f00-0000-7000-8000-000000000011"
	for _, test := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"account", "quarantine", principal}, 1, "invalid_migration_configuration"},
		{[]string{"account", "revoke-sessions", principal}, 1, "invalid_migration_configuration"},
		{[]string{"account", "release", principal}, 1, "invalid_migration_configuration"},
		{[]string{"account", "release", "not-a-principal"}, 1, "invalid_account_operation"},
		{[]string{"account", "delete", principal}, 2, "Usage:"},
		{[]string{"account", "quarantine"}, 2, "Usage:"},
	} {
		var output, errorOutput bytes.Buffer
		if code := execute(t.Context(), test.args, lookup, &output, &errorOutput); code != test.code ||
			output.Len() != 0 || !strings.Contains(errorOutput.String(), test.want) {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", test.args, code, output.String(), errorOutput.String())
		}
	}
}
