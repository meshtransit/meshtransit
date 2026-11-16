// Command rolegrants prints, as JSON, which database functions and tables each
// Core role reaches (see analysis.go). Run from the module root:
//
//	go run ./core/tools/rolegrants > core/migrations/role_grants.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
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
