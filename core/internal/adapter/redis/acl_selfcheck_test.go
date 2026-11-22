package redis

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"
)

func TestRoleSelfCheckCoversEveryNeed(t *testing.T) {
	t.Parallel()
	for _, role := range ACLRoles {
		commands, err := RoleSelfCheck(role)
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if len(commands) == 0 {
			t.Fatalf("%s: no self-check commands", role)
		}
		seen := map[string]bool{}
		for _, command := range commands {
			text := fmt.Sprint(command)
			if seen[text] {
				t.Errorf("%s: %s twice", role, text)
			}
			seen[text] = true
			// Probe keys under a prefix, a declared full key name, or one of
			// the role's channels: never a key Core code makes under a prefix.
			for _, argument := range command[1:] {
				value, ok := argument.(string)
				if !ok || !strings.HasPrefix(value, "meshtransit:") || strings.HasSuffix(value, ":acl-probe") ||
					slices.Contains(roleChannels(t, role), value) || slices.Contains(roleFullKeys(t, role), value) {
					continue
				}
				t.Errorf("%s: %s names %s, not a probe key, a declared key or the role's channel", role, text, value)
			}
		}
		// Every command the role's rules allow, but the connection and
		// subscription ones, is checked at least once.
		rules, err := RoleACLRules(role)
		if err != nil {
			t.Fatal(err)
		}
		checked := map[string]bool{}
		for _, command := range commands {
			checked[strings.ToLower(fmt.Sprint(command[0]))] = true
		}
		for _, rule := range rules {
			for _, token := range strings.Fields(strings.Trim(rule, "()")) {
				name, ok := strings.CutPrefix(token, "+")
				if !ok || slices.Contains([]string{"hello", "auth", "subscribe", "unsubscribe", "multi", "discard"}, name) {
					continue
				}
				if !checked[name] {
					t.Errorf("%s: rule +%s is never self-checked", role, name)
				}
			}
		}
	}
}

func roleChannels(t *testing.T, role string) []string {
	t.Helper()
	methods, err := roleMethodSet(role)
	if err != nil {
		t.Fatal(err)
	}
	var channels []string
	for _, method := range methods {
		channels = append(channels, methodNeeds[method].channels...)
	}
	return channels
}

func roleFullKeys(t *testing.T, role string) []string {
	t.Helper()
	methods, err := roleMethodSet(role)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, method := range methods {
		for _, key := range slices.Concat(methodNeeds[method].reads, methodNeeds[method].writes) {
			if !strings.HasSuffix(key, ":") {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// A full key name is probed as itself: its ACL pattern is exact.
func TestSelfCheckProbesFullKeysExactly(t *testing.T) {
	t.Parallel()
	commands, err := RoleSelfCheck(ACLRoleControl)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range commands {
		if len(command) > 1 && command[1] == replicaLoadKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("control: no probe names %s itself", replicaLoadKey)
	}
}

func TestSelfCheckTemplatesCoverEveryDeclaredCommand(t *testing.T) {
	t.Parallel()
	for method, need := range methodNeeds {
		for _, command := range need.commands {
			if selfCheckSkipped[command] || command == "publish" {
				continue
			}
			if _, ok := selfCheckTemplates[command]; !ok {
				t.Errorf("%s: command %s has no self-check template", method, command)
			}
		}
	}
}

// reply is a Redis error reply as go-redis returns it.
type reply string

func (r reply) Error() string { return string(r) }
func (reply) RedisError()     {}

type fakeQueue struct {
	replies map[string]error
	multi   error
}

func (queue *fakeQueue) run(_ context.Context, commands [][]any) (map[int]error, error) {
	if queue.multi != nil {
		return nil, queue.multi
	}
	refused := map[int]error{}
	for index, command := range commands {
		if err, ok := queue.replies[strings.ToLower(fmt.Sprint(command[0]))]; ok {
			refused[index] = err
		}
	}
	return refused, nil
}

func TestCheckACL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	check := func(queue *fakeQueue, role string) error {
		return (&Client{queueCommands: queue.run}).CheckACL(ctx, role)
	}
	if err := check(&fakeQueue{}, ACLRoleAPI); err != nil {
		t.Fatalf("every command queued: %v", err)
	}
	// Redis checks the ACL first: these mean the ACL passed.
	for _, passed := range []error{reply("OOM command not allowed when used memory > 'maxmemory'."),
		reply("READONLY You can't write against a read only replica."), reply("LOADING Redis is loading")} {
		if err := check(&fakeQueue{replies: map[string]error{"hset": passed, "hdel": passed}}, ACLRoleAPI); err != nil {
			t.Errorf("%v: err = %v, want the ACL passed", passed, err)
		}
	}
	err := check(&fakeQueue{replies: map[string]error{
		"hdel":   reply("NOPERM User app-api has no permissions to run the 'hdel' command"),
		"zcount": reply("ERR unknown command 'zcount'")}}, ACLRoleAPI)
	var missing *ACLMissingError
	if !errors.As(err, &missing) || !errors.Is(err, ErrACLMissing) ||
		!slices.Contains(missing.Missing, "HDEL meshtransit:v1:dns-index: (NOPERM)") ||
		!slices.ContainsFunc(missing.Missing, func(entry string) bool {
			return strings.HasPrefix(entry, "ZCOUNT ") && strings.HasSuffix(entry, "(ERR)")
		}) {
		t.Fatalf("refused: err = %v, want HDEL (NOPERM) and ZCOUNT (ERR)", err)
	}
	for multi, want := range map[error]error{
		reply("NOPERM User u has no permissions to run the 'multi' command"):           ErrACLCheckUnavailable,
		reply("ERR unknown command 'MULTI'"):                                           ErrACLCheckUnavailable,
		reply("LOADING Redis is loading the dataset in memory"):                        ErrACLCheckTransient,
		errors.New("dial tcp: connection refused"):                                     ErrACLCheckTransient,
		errors.Join(errConnectionNotReady, reply("ERR max number of clients reached")): ErrACLCheckTransient,
	} {
		if err := check(&fakeQueue{multi: multi}, ACLRoleAPI); !errors.Is(err, want) {
			t.Errorf("MULTI %v: err = %v, want %v", multi, err, want)
		}
	}
	if err := check(&fakeQueue{}, "identity"); !errors.Is(err, ErrUnknownACLRole) {
		t.Fatalf("unknown role: err = %v", err)
	}
}

// Every probe is allowed by the role's own rules, matched as Redis does: a
// keyed command by a selector with that command and a pattern that matches
// the key (a write needs ~, a read %R~ or ~); a key-free one at the root.
// A probe its rules refuse would stop every pod of a correctly made user.
func TestSelfCheckProbesMatchTheRolesRules(t *testing.T) {
	t.Parallel()
	for _, role := range ACLRoles {
		rules, err := RoleACLRules(role)
		if err != nil {
			t.Fatal(err)
		}
		type selector struct {
			commands      map[string]bool
			reads, writes []string
		}
		root := map[string]bool{}
		channels := map[string]bool{}
		var selectors []selector
		for _, rule := range rules {
			switch {
			case strings.HasPrefix(rule, "("):
				current := selector{commands: map[string]bool{}}
				for _, token := range strings.Fields(strings.Trim(rule, "()")) {
					switch {
					case strings.HasPrefix(token, "+"):
						current.commands[token[1:]] = true
					case strings.HasPrefix(token, "%R~"):
						current.reads = append(current.reads, token[3:])
					case strings.HasPrefix(token, "~"):
						current.writes = append(current.writes, token[1:])
					}
				}
				selectors = append(selectors, current)
			case strings.HasPrefix(rule, "+"):
				root[rule[1:]] = true
			case strings.HasPrefix(rule, "&"):
				channels[rule[1:]] = true
			}
		}
		commands, err := RoleSelfCheck(role)
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range commands {
			name := strings.ToLower(fmt.Sprint(command[0]))
			if name == "publish" {
				if !root[name] || !channels[fmt.Sprint(command[1])] {
					t.Errorf("%s: %v is not allowed at the root", role, command)
				}
				continue
			}
			key := ""
			for _, argument := range command[1:] {
				if value, ok := argument.(string); ok && strings.HasPrefix(value, "meshtransit:") {
					key = value
				}
			}
			if key == "" {
				if !root[name] && !slices.ContainsFunc(selectors, func(s selector) bool { return s.commands[name] }) {
					t.Errorf("%s: %v is allowed nowhere", role, command)
				}
				continue
			}
			matches := func(patterns []string) bool {
				return slices.ContainsFunc(patterns, func(pattern string) bool {
					ok, _ := path.Match(pattern, key)
					return ok
				})
			}
			allowed := slices.ContainsFunc(selectors, func(s selector) bool {
				if !s.commands[name] {
					return false
				}
				return matches(s.writes) || !selfCheckWrites[name] && matches(s.reads)
			})
			if !allowed {
				t.Errorf("%s: %v is refused by the role's own rules", role, command)
			}
		}
	}
}

// redisKeyAccess is, independent of selfCheckWrites, how Redis's command
// table flags each command's keys (RW or write: true; RO: false). A command
// added to the templates without an entry here fails, so a write is never
// probed only on a read-only (%R~) pattern.
var redisKeyAccess = map[string]bool{
	"del": true, "set": true, "hdel": true, "hset": true, "pexpire": true, "zadd": true, "zrem": true,
	"zremrangebyscore": true, "eval": true, "evalsha": true,
	"exists": false, "get": false, "hget": false, "hmget": false, "hgetall": false, "hscan": false,
	"zcount": false, "eval_ro": false, "evalsha_ro": false,
}

func TestSelfCheckWritesFollowRedis(t *testing.T) {
	t.Parallel()
	for command, template := range selfCheckTemplates {
		probe := template("meshtransit:v1:x:acl-probe")
		if len(probe) == 1 {
			continue // names no key
		}
		write, known := redisKeyAccess[command]
		if !known {
			t.Errorf("%s: not in redisKeyAccess", command)
			continue
		}
		if write != selfCheckWrites[command] {
			t.Errorf("%s: selfCheckWrites %v, Redis flags its keys write=%v", command, selfCheckWrites[command], write)
		}
	}
}
