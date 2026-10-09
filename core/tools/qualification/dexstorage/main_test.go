//go:build dexbroker && qualification

package main

import "testing"

func TestParseOptions(t *testing.T) {
	t.Parallel()
	valid := []string{
		"-mode", "verify",
		"-address", "database.example.test:5432",
		"-database", "dex_restore",
		"-user", "dex_runtime",
		"-password-file", "/run/secrets/password",
		"-ca-file", "/run/secrets/ca.pem",
	}
	if _, err := parseOptions(valid); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	for _, candidate := range []struct {
		name string
		args []string
	}{
		{name: "unknown mode", args: replaceOption(valid, "-mode", "open")},
		{name: "zero port", args: replaceOption(valid, "-address", "database.example.test:0")},
		{name: "invalid database", args: replaceOption(valid, "-database", "Dex-Restore")},
		{name: "relative password", args: replaceOption(valid, "-password-file", "password")},
		{name: "trailing argument", args: append(append([]string{}, valid...), "extra")},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseOptions(candidate.args); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
}

func replaceOption(input []string, name, value string) []string {
	result := append([]string{}, input...)
	for index := range len(result) - 1 {
		if result[index] == name {
			result[index+1] = value
			return result
		}
	}
	return result
}
