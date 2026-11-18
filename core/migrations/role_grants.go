package migrations

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed role_grants.json
var roleGrantsJSON []byte

// RoleUsage is what one serving role's code uses in the database
// (core/tools/rolegrants, make role-grants): functions by name, tables by
// the statements that touch them.
type RoleUsage struct {
	Functions []string `json:"functions"`
	Inserts   []string `json:"inserts"`
	Updates   []string `json:"updates"`
	Deletes   []string `json:"deletes"`
	Locks     []string `json:"locks"`
	Reads     []string `json:"reads"`
}

// RoleGrants returns the role usage manifest, by role ("api", "control",
// "worker"), decoded afresh on each call.
func RoleGrants() (map[string]RoleUsage, error) {
	usage := map[string]RoleUsage{}
	if err := json.Unmarshal(roleGrantsJSON, &usage); err != nil {
		return nil, fmt.Errorf("decode role grants manifest: %w", err)
	}
	return usage, nil
}
