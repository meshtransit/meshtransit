package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	redisclient "github.com/redis/go-redis/v9"
)

// fakeACLAdmin answers the administrator commands ApplyACL sends.
type fakeACLAdmin struct {
	t       *testing.T
	users   map[string][]string // user -> stored password digests
	rules   map[string][]string // user -> rules after the password
	nopass  map[string]bool     // users flagged nopass
	saveErr error
	denyAll bool // DRYRUN answers a denial for every command
	loaded  bool // ACL LOAD restored the saved users
	calls   [][]any
}

func (admin *fakeACLAdmin) Do(_ context.Context, args ...any) (any, error) {
	admin.calls = append(admin.calls, args)
	switch strings.Join([]string{fmt.Sprint(args[0]), fmt.Sprint(args[1])}, " ") {
	case "ACL GETUSER":
		digests, ok := admin.users[args[2].(string)]
		if !ok {
			return nil, redisclient.Nil
		}
		list := make([]any, 0, len(digests))
		for _, digest := range digests {
			list = append(list, digest)
		}
		flags := []any{"on"}
		if admin.nopass[args[2].(string)] {
			flags = append(flags, "nopass")
		}
		return map[any]any{"flags": flags, "passwords": list}, nil
	case "ACL SETUSER":
		user := args[2].(string)
		var rules []string
		for _, arg := range args[3:] {
			rule := arg.(string)
			switch {
			case strings.HasPrefix(rule, "#"):
				admin.users[user] = []string{strings.TrimPrefix(rule, "#")}
			case rule != "reset" && rule != "on":
				rules = append(rules, rule)
			}
		}
		if admin.rules == nil {
			admin.rules = map[string][]string{}
		}
		admin.rules[user] = rules
		return "OK", nil
	case "ACL LOAD":
		admin.loaded = true
		return "OK", nil
	case "ACL SAVE":
		if admin.saveErr != nil {
			return nil, admin.saveErr
		}
		return "OK", nil
	case "ACL DRYRUN":
		command := make([]string, 0, len(args)-3)
		for _, arg := range args[3:] {
			command = append(command, arg.(string))
		}
		if admin.denyAll || !parseACL(admin.t, admin.rules[args[2].(string)]).permits(command...) {
			return "This user has no permissions to run the '" + command[0] + "' command", nil
		}
		return "OK", nil
	}
	return nil, errors.New("unexpected command")
}

func (*fakeACLAdmin) Close() error { return nil }

func digestOf(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

var (
	apiPassword    = strings.Repeat("a1", 20)
	workerPassword = strings.Repeat("w2", 20)
)

func TestApplyACLCreatesUsersSavesAndChecks(t *testing.T) {
	t.Parallel()
	admin := &fakeACLAdmin{t: t, users: map[string][]string{}}
	results, err := applyACL(context.Background(), admin,
		map[string][]byte{ACLRoleWorker: []byte(workerPassword), ACLRoleAPI: []byte(apiPassword)}, false)
	if err != nil {
		t.Fatalf("applyACL() error = %v", err)
	}
	want := []ACLUserResult{
		{Role: ACLRoleAPI, User: "mesh_api", Created: true, PasswordChanged: true},
		{Role: ACLRoleWorker, User: "mesh_worker", Created: true, PasswordChanged: true},
	}
	if fmt.Sprint(results) != fmt.Sprint(want) {
		t.Fatalf("results = %+v, want %+v", results, want)
	}
	if admin.users["mesh_api"][0] != digestOf(apiPassword) {
		t.Fatal("mesh_api does not keep the digest of its password")
	}
	var setuser []any
	saved := false
	for _, call := range admin.calls {
		for _, arg := range call {
			if text, ok := arg.(string); ok && (strings.Contains(text, apiPassword) || strings.Contains(text, workerPassword)) {
				t.Fatalf("a password reached Redis in %v", call[:2])
			}
		}
		if call[1] == "SETUSER" && call[2] == "mesh_api" {
			setuser = call
		}
		if call[1] == "SAVE" {
			saved = true
		}
		if call[1] == "DRYRUN" && saved {
			t.Fatal("DRYRUN ran after the ACL was saved: unchecked users would be saved")
		}
	}
	rules, _ := RoleACLRules(ACLRoleAPI)
	if len(setuser) != 6+len(rules) || setuser[3] != "reset" || setuser[4] != "on" || fmt.Sprint(setuser[6:]) != fmt.Sprint(rules) {
		t.Fatalf("ACL SETUSER mesh_api = %v", setuser)
	}
}

func TestApplyACLKeepsOrRotatesStoredPasswords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	same := &fakeACLAdmin{t: t, users: map[string][]string{"mesh_api": {digestOf(apiPassword)}}}
	results, err := applyACL(ctx, same, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, false)
	if err != nil || results[0].Created || results[0].PasswordChanged {
		t.Fatalf("same password: %+v, %v", results, err)
	}

	differs := &fakeACLAdmin{t: t, users: map[string][]string{"mesh_api": {digestOf(workerPassword)}}}
	if _, err := applyACL(ctx, differs, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, false); !errors.Is(err, ErrACLPasswordDiffers) {
		t.Fatalf("differing password without rotate: %v", err)
	}
	for _, call := range differs.calls {
		if call[1] == "SETUSER" || call[1] == "SAVE" {
			t.Fatalf("a refused apply still sent %v", call[:2])
		}
	}
	results, err = applyACL(ctx, differs, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, true)
	if err != nil || !results[0].PasswordChanged || differs.users["mesh_api"][0] != digestOf(apiPassword) {
		t.Fatalf("rotation: %+v, %v", results, err)
	}

	// The given password plus another: the other may serve a running pod.
	overlap := &fakeACLAdmin{t: t, users: map[string][]string{"mesh_api": {digestOf(apiPassword), digestOf(workerPassword)}}}
	if _, err := applyACL(ctx, overlap, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, false); !errors.Is(err, ErrACLPasswordDiffers) {
		t.Fatalf("extra stored password without rotate: %v", err)
	}
	results, err = applyACL(ctx, overlap, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, true)
	if err != nil || !results[0].PasswordChanged || len(overlap.users["mesh_api"]) != 1 ||
		overlap.users["mesh_api"][0] != digestOf(apiPassword) {
		t.Fatalf("rotation of an overlap: %+v, %v", results, err)
	}

	passwordless := &fakeACLAdmin{t: t, users: map[string][]string{"mesh_api": {}}}
	results, err = applyACL(ctx, passwordless, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, false)
	if err != nil || !results[0].PasswordChanged {
		t.Fatalf("user without a password: %+v, %v", results, err)
	}
}

func TestApplyACLFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unsaved := &fakeACLAdmin{t: t, users: map[string][]string{}, saveErr: errors.New("ERR no aclfile")}
	if _, err := applyACL(ctx, unsaved, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, false); !errors.Is(err, ErrACLNotPersisted) {
		t.Fatalf("unsaved ACL: %v", err)
	}
	locked := &fakeACLAdmin{t: t, users: map[string][]string{}, denyAll: true}
	if _, err := applyACL(ctx, locked, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, false); !errors.Is(err, ErrACLCheckFailed) {
		t.Fatalf("failed DRYRUN: %v", err)
	}
	if !locked.loaded {
		t.Fatal("a failed check did not reload the saved users")
	}
	for _, call := range locked.calls {
		if call[1] == "SAVE" {
			t.Fatal("users that failed their checks were saved")
		}
	}
	nopass := &fakeACLAdmin{t: t, users: map[string][]string{"mesh_api": {}}, nopass: map[string]bool{"mesh_api": true}}
	if _, err := applyACL(ctx, nopass, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, false); !errors.Is(err, ErrACLPasswordDiffers) {
		t.Fatalf("nopass user without rotate: %v", err)
	}
	if results, err := applyACL(ctx, nopass, map[string][]byte{ACLRoleAPI: []byte(apiPassword)}, true); err != nil || !results[0].PasswordChanged {
		t.Fatalf("nopass user with rotate: %+v, %v", results, err)
	}
	for name, passwords := range map[string]map[string][]byte{
		"short password":  {ACLRoleAPI: []byte("short")},
		"spaced password": {ACLRoleAPI: []byte(strings.Repeat("a", 31) + " ")},
		"unknown role":    {"identity": []byte(apiPassword)},
		"non-ASCII":       {ACLRoleAPI: []byte(strings.Repeat("a", 31) + "é")},
		"too long":        {ACLRoleAPI: []byte(strings.Repeat("a", 257))},
		"one bad of two":  {ACLRoleAPI: []byte(apiPassword), ACLRoleWorker: []byte("short")},
	} {
		admin := &fakeACLAdmin{t: t, users: map[string][]string{}}
		if _, err := applyACL(ctx, admin, passwords, false); err == nil {
			t.Errorf("%s: applyACL() succeeded", name)
		}
		if len(admin.calls) != 0 {
			t.Errorf("%s: sent %d commands before validating every password", name, len(admin.calls))
		}
	}
	if _, err := ApplyACL(ctx, ACLApplyOptions{}); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("ApplyACL without passwords: %v", err)
	}
}

// A refusal for one role changes no role: every user is read and decided
// before any is set.
func TestApplyACLRefusalChangesNothing(t *testing.T) {
	t.Parallel()
	admin := &fakeACLAdmin{t: t, users: map[string][]string{"mesh_worker": {digestOf(apiPassword)}}}
	_, err := applyACL(context.Background(), admin,
		map[string][]byte{ACLRoleAPI: []byte(apiPassword), ACLRoleWorker: []byte(workerPassword)}, false)
	if !errors.Is(err, ErrACLPasswordDiffers) {
		t.Fatalf("applyACL() error = %v, want ErrACLPasswordDiffers", err)
	}
	for _, call := range admin.calls {
		if call[1] != "GETUSER" {
			t.Fatalf("a refused apply sent ACL %v", call[1])
		}
	}
}
