// Command rolegrants prints, as JSON, which database functions and tables each
// Core role reaches (see analysis.go). Run from the module root:
//
//	go run ./core/tools/rolegrants > core/migrations/role_grants.json
//
// With -evidence it instead compares pg_stat_statements snapshots (role
// isolation S2.0) with the manifest and fails when something ran that the
// manifest misses:
//
//	go run ./core/tools/rolegrants -evidence pgss-*.csv.gz
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	evidence := flag.Bool("evidence", false, "compare pg_stat_statements snapshot files with the manifest")
	manifest := flag.String("manifest", "core/migrations/role_grants.json", "manifest for -evidence")
	flag.Parse()
	if *evidence {
		if flag.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "rolegrants: -evidence needs snapshot files")
			os.Exit(2)
		}
		if err := runEvidence(flag.Args(), *manifest, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "rolegrants:", err)
			os.Exit(1)
		}
		return
	}
	result, err := Analyze(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "rolegrants:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result.Roles); err != nil {
		fmt.Fprintln(os.Stderr, "rolegrants:", err)
		os.Exit(1)
	}
}
