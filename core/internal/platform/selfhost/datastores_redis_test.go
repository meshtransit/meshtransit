package selfhost

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
)

// The bundled Redis's single user runs every role, so it may run every
// command the Redis adapter's "all" role needs, on keys and channels under
// meshtransit:v1: only.
func TestRedisUserCoversTheAllRole(t *testing.T) {
	t.Parallel()
	rules, err := redisadapter.RoleACLRules(redisadapter.ACLRoleAll)
	if err != nil {
		t.Fatal(err)
	}
	granted := map[string]bool{}
	for _, command := range strings.Fields(redisCommands) {
		granted[command] = true
	}
	var tokens []string
	for _, rule := range rules {
		tokens = append(tokens, strings.Fields(strings.Trim(rule, "()"))...)
	}
	for _, rule := range tokens {
		switch {
		case strings.HasPrefix(rule, "+") && rule != "+hello" && rule != "+auth":
			if !granted[rule] {
				t.Errorf("the bundled Redis user lacks %s", rule)
			}
		case strings.HasPrefix(rule, "~"), strings.HasPrefix(rule, "%R~"):
			if !strings.Contains(rule, "~meshtransit:v1:") {
				t.Errorf("key rule %s is outside meshtransit:v1:", rule)
			}
		case strings.HasPrefix(rule, "&"):
			if !strings.HasPrefix(rule, "&meshtransit:v1:") {
				t.Errorf("channel rule %s is outside meshtransit:v1:", rule)
			}
		}
	}
}

// Redis reads its users only at start, so the compose file names the
// command list: a Core that needs more commands recreates Redis on upgrade.
func TestComposeRecreatesRedisWhenItsCommandsChange(t *testing.T) {
	t.Parallel()
	rendered, err := Render(testConfig(t), approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Labels map[string]string `yaml:"labels"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(rendered.Files["compose.yaml"], &compose); err != nil {
		t.Fatal(err)
	}
	label := compose.Services["redis"].Labels["net.meshtransit.redis-acl"]
	if label == "" || label != redisACLRevision() || len(label) != 16 {
		t.Fatalf("redis acl label = %q, want %q", label, redisACLRevision())
	}
	if strings.Contains(string(rendered.Files["compose.yaml"]), redisCommands) {
		t.Fatal("the compose file should carry a digest of the rules, not the rules")
	}
	if digest := sha256.Sum256([]byte(redisUserRules)); label != hex.EncodeToString(digest[:8]) {
		t.Fatal("the label must follow every rule of the user, keys and channels included")
	}
}
