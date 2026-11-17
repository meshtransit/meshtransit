package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/platform/config"
)

// redisACLTestPassword is a fixture, built so it is not a literal.
var redisACLTestPassword = strings.Repeat("Zq8vK2mN", 4)

func redisACLLookup(t *testing.T, overrides map[string]string) config.LookupFunc {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	values := map[string]string{
		"MESHTRANSIT_REDIS_ADDRESS":             "redis.internal:6379",
		"MESHTRANSIT_REDIS_CA_FILE":             write("ca.crt", "not read by the fake"),
		"MESHTRANSIT_REDIS_ADMIN_USERNAME":      "redis_admin",
		"MESHTRANSIT_REDIS_ADMIN_PASSWORD_FILE": write("admin", "admin-secret-not-read-by-the-fake"),
		"MESHTRANSIT_REDIS_ACL_PASSWORD_FILES":  "control=" + write("control", redisACLTestPassword),
	}
	for key, value := range overrides {
		values[key] = value
	}
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestRunRedisACLApplyPassesPasswordsAndReportsUsers(t *testing.T) {
	t.Parallel()
	var got redisadapter.ACLApplyOptions
	apply := func(_ context.Context, options redisadapter.ACLApplyOptions) ([]redisadapter.ACLUserResult, error) {
		got = options
		return []redisadapter.ACLUserResult{{Role: "control", User: "mesh_control", Created: true, PasswordChanged: true}}, nil
	}
	var output, errorOutput bytes.Buffer
	exitCode := runRedisACL(t.Context(), []string{"apply"},
		redisACLLookup(t, map[string]string{"MESHTRANSIT_REDIS_ACL_ROTATE": "true"}), &output, &errorOutput, apply)
	if exitCode != 0 {
		t.Fatalf("exit %d: %s", exitCode, errorOutput.String())
	}
	if string(got.Passwords["control"]) != redisACLTestPassword || len(got.Passwords) != 1 || !got.Rotate ||
		got.Admin.Username != "redis_admin" || got.Admin.PoolSize != 1 || got.Admin.Address != "redis.internal:6379" {
		t.Fatalf("apply options = %+v", got)
	}
	var result redisACLOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("output %q: %v", output.String(), err)
	}
	if result.Operation != "redis acl apply" || len(result.Users) != 1 || result.Users[0].User != "mesh_control" {
		t.Fatalf("result = %+v", result)
	}
	if strings.Contains(output.String()+errorOutput.String(), redisACLTestPassword) {
		t.Fatal("the password reached the output")
	}
}

func TestRunRedisACLRulesConnectsNowhere(t *testing.T) {
	t.Parallel()
	var output, errorOutput bytes.Buffer
	exitCode := runRedisACL(t.Context(), []string{"rules", "worker"}, nil, &output, &errorOutput, nil)
	if exitCode != 0 {
		t.Fatalf("exit %d: %s", exitCode, errorOutput.String())
	}
	var result redisACLOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	want, _ := redisadapter.RoleACLRules("worker")
	if result.User != "mesh_worker" || strings.Join(result.Rules, " ") != strings.Join(want, " ") {
		t.Fatalf("result = %+v", result)
	}
	if exitCode := runRedisACL(t.Context(), []string{"rules", "identity"}, nil, &output, &errorOutput, nil); exitCode != 2 {
		t.Fatalf("unknown role exit = %d", exitCode)
	}
}

func TestRunRedisACLRefusesBadUsageAndConfiguration(t *testing.T) {
	t.Parallel()
	called := false
	apply := func(context.Context, redisadapter.ACLApplyOptions) ([]redisadapter.ACLUserResult, error) {
		called = true
		return nil, nil
	}
	var output, errorOutput bytes.Buffer
	for _, args := range [][]string{{}, {"apply", "--now"}, {"save"}, {"rules"}} {
		if exitCode := runRedisACL(t.Context(), args, redisACLLookup(t, nil), &output, &errorOutput, apply); exitCode != 2 {
			t.Errorf("args %v: exit %d, want 2", args, exitCode)
		}
	}
	if exitCode := runRedisACL(t.Context(), []string{"apply"},
		redisACLLookup(t, map[string]string{"MESHTRANSIT_REDIS_ADMIN_USERNAME": ""}), &output, &errorOutput, apply); exitCode != 1 {
		t.Errorf("missing admin: exit %d, want 1", exitCode)
	}
	if exitCode := runRedisACL(t.Context(), []string{"apply"},
		redisACLLookup(t, map[string]string{"MESHTRANSIT_REDIS_ACL_PASSWORD_FILES": "control=/nonexistent/password"}),
		&output, &errorOutput, apply); exitCode != 1 {
		t.Errorf("unreadable password: exit %d, want 1", exitCode)
	}
	if called {
		t.Fatal("apply ran despite bad usage or configuration")
	}
}

func TestRunRedisACLNamesTheFailure(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		redisadapter.ErrACLPasswordDiffers: "redis_acl_password_differs",
		redisadapter.ErrACLNotPersisted:    "redis_acl_not_persisted",
		redisadapter.ErrACLCheckFailed:     "redis_acl_check_failed",
		errors.New("boom"):                 "redis_acl_apply_failure",
	} {
		apply := func(context.Context, redisadapter.ACLApplyOptions) ([]redisadapter.ACLUserResult, error) {
			return nil, err
		}
		var output, errorOutput bytes.Buffer
		if exitCode := runRedisACL(t.Context(), []string{"apply"}, redisACLLookup(t, nil), &output, &errorOutput, apply); exitCode != 1 {
			t.Errorf("%v: exit %d", err, exitCode)
		}
		if !strings.Contains(errorOutput.String(), code) {
			t.Errorf("%v: log %q lacks %s", err, errorOutput.String(), code)
		}
	}
}
