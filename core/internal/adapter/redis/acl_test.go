package redis

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every exported Client method declares what it sends to Redis, so a new
// method cannot ship without an ACL decision.
func TestEveryClientMethodDeclaresItsACLNeed(t *testing.T) {
	t.Parallel()
	clientType := reflect.TypeFor[*Client]()
	for index := range clientType.NumMethod() {
		name := clientType.Method(index).Name
		if _, ok := methodNeeds[name]; !ok {
			t.Errorf("Client.%s has no entry in methodNeeds", name)
		}
	}
	for name := range methodNeeds {
		if _, ok := clientType.MethodByName(name); !ok {
			t.Errorf("methodNeeds names %s, which is not an exported Client method", name)
		}
	}
}

func TestRoleMethodsAreDeclared(t *testing.T) {
	t.Parallel()
	for role, methods := range roleMethods {
		for _, method := range slices.Concat(methods, sharedMethods) {
			if _, ok := methodNeeds[method]; !ok {
				t.Errorf("role %s calls %s, which has no declared need", role, method)
			}
		}
	}
}

var (
	luaCommand   = regexp.MustCompile(`redis\.p?call\(\s*'([A-Za-z]+)'`)
	clientCall   = regexp.MustCompile(`\b(?:client|pipe)\.(HDel|HGetAll|HMGet|HScan|Ping|Publish|Subscribe|ZCount|Get|Set|Del|HGet|HSet|Expire|PExpire|Exists|ZAdd|ZRem|Incr|Eval|EvalSha)\(`)
	keyLiteral   = regexp.MustCompile(`"(meshtransit:v1:[^"]*)"`)
	dynamicCall  = regexp.MustCompile(`redis\.p?call\(\s*[a-z_]`)
	dangerousACL = []string{"+flushall", "+flushdb", "+keys", "+config", "+acl", "+debug", "+shutdown", "+script",
		"+module", "+monitor", "+replicaof", "+slaveof", "+cluster", "+migrate", "+restore", "+client", "+function",
		"+@all", "+@dangerous", "+@admin", "allkeys", "allchannels", "~*", "&*"}
)

func adapterSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		content, err := fs.ReadFile(os.DirFS("."), file)
		if err != nil {
			t.Fatal(err)
		}
		sources[file] = string(content)
	}
	return sources
}

func declared() (commands, prefixes, channels map[string]bool) {
	commands, prefixes, channels = map[string]bool{}, map[string]bool{}, map[string]bool{}
	addAll(commands, connectionCommands)
	for _, need := range methodNeeds {
		addAll(commands, need.commands)
		addAll(prefixes, need.reads)
		addAll(prefixes, need.writes)
		addAll(channels, need.channels)
	}
	return commands, prefixes, channels
}

// Every command a Lua script or a direct call sends is allowed to some
// method; scripts never pick the command name at run time.
func TestEveryCommandInTheSourceIsDeclared(t *testing.T) {
	t.Parallel()
	commands, _, _ := declared()
	for file, source := range adapterSources(t) {
		if dynamicCall.MatchString(source) {
			t.Errorf("%s calls redis.call with a computed command name", file)
		}
		for _, match := range luaCommand.FindAllStringSubmatch(source, -1) {
			if !commands[strings.ToLower(match[1])] {
				t.Errorf("%s: Lua command %s is not declared by any method", file, match[1])
			}
		}
		for _, match := range clientCall.FindAllStringSubmatch(source, -1) {
			if !commands[strings.ToLower(match[1])] {
				t.Errorf("%s: client.%s is not declared by any method", file, match[1])
			}
		}
	}
}

// Every key prefix and channel named in the adapter is covered by a declared
// prefix or channel.
func TestEveryKeyAndChannelInTheSourceIsDeclared(t *testing.T) {
	t.Parallel()
	_, prefixes, channels := declared()
	for file, source := range adapterSources(t) {
		for _, match := range keyLiteral.FindAllStringSubmatch(source, -1) {
			literal := match[1]
			if channels[literal] {
				continue
			}
			if !slices.ContainsFunc(sorted(prefixes), func(prefix string) bool {
				return strings.HasPrefix(literal, prefix) || strings.HasPrefix(prefix, literal)
			}) {
				t.Errorf("%s: %q is neither a declared key prefix nor a declared channel", file, literal)
			}
		}
	}
}

// aclModel evaluates ACL rules the way Redis 7 does for the commands the
// probes and tests use: a key-free command by the root, a channel by the
// root's commands and channels, a keyed command by a selector that allows
// the command and every key with the access it needs.
type aclModel struct {
	root      map[string]bool
	channels  map[string]bool
	selectors []aclSelector
}

type aclSelector struct {
	commands      map[string]bool
	reads, writes []string
}

func parseACL(t *testing.T, rules []string) aclModel {
	t.Helper()
	model := aclModel{root: map[string]bool{}, channels: map[string]bool{}}
	for _, rule := range rules {
		switch {
		case strings.HasPrefix(rule, "("):
			selector := aclSelector{commands: map[string]bool{}}
			for _, token := range strings.Fields(strings.Trim(rule, "()")) {
				switch {
				case strings.HasPrefix(token, "+"):
					selector.commands[strings.TrimPrefix(token, "+")] = true
				case strings.HasPrefix(token, "%R~"):
					selector.reads = append(selector.reads, strings.TrimPrefix(token, "%R~"))
				case strings.HasPrefix(token, "~"):
					selector.writes = append(selector.writes, strings.TrimPrefix(token, "~"))
				default:
					t.Fatalf("unexpected selector token %q", token)
				}
			}
			model.selectors = append(model.selectors, selector)
		case strings.HasPrefix(rule, "+"):
			model.root[strings.TrimPrefix(rule, "+")] = true
		case strings.HasPrefix(rule, "&"):
			model.channels[strings.TrimPrefix(rule, "&")] = true
		case slices.Contains([]string{"resetkeys", "resetchannels", "clearselectors", "-@all"}, rule):
		default:
			t.Fatalf("unexpected root rule %q (keys and broad rules belong nowhere at the root)", rule)
		}
	}
	return model
}

var (
	writeCommands = map[string]bool{"hset": true, "hdel": true, "set": true, "del": true, "pexpire": true,
		"zadd": true, "zrem": true, "zremrangebyscore": true, "evalsha": true, "eval": true}
	readCommands = map[string]bool{"get": true, "hget": true, "hmget": true, "hgetall": true, "hscan": true,
		"exists": true, "zcount": true, "evalsha_ro": true, "eval_ro": true}
)

func matches(patterns []string, key string) bool {
	return slices.ContainsFunc(patterns, func(pattern string) bool {
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
			return strings.HasPrefix(key, prefix)
		}
		return pattern == key
	})
}

func (model aclModel) permits(args ...string) bool {
	command := strings.ToLower(args[0])
	switch command {
	case "publish", "subscribe":
		return model.root[command] && model.channels[args[1]]
	}
	var keys []string
	switch {
	case command == "evalsha" || command == "eval" || command == "evalsha_ro" || command == "eval_ro":
		count := 0
		for _, digit := range args[2] {
			count = count*10 + int(digit-'0')
		}
		keys = args[3 : 3+count]
	case writeCommands[command] || readCommands[command]:
		keys = args[1:2]
	}
	if len(keys) == 0 && model.root[command] {
		return true
	}
	for _, selector := range model.selectors {
		if !selector.commands[command] {
			continue
		}
		allowed := true
		for _, key := range keys {
			if !matches(selector.writes, key) && (writeCommands[command] || !matches(selector.reads, key)) {
				allowed = false
			}
		}
		if allowed {
			return true
		}
	}
	return false
}

// Each role's rules pass its own probes (which ApplyACL also runs against
// Redis), keep keys out of the root and never grant administration.
func TestRoleACLRules(t *testing.T) {
	t.Parallel()
	for _, role := range ACLRoles {
		rules, err := RoleACLRules(role)
		if err != nil {
			t.Fatalf("RoleACLRules(%s) error = %v", role, err)
		}
		again, _ := RoleACLRules(role)
		if !slices.Equal(rules, again) {
			t.Fatalf("RoleACLRules(%s) is not deterministic", role)
		}
		if !slices.Equal(rules[:4], []string{"resetkeys", "resetchannels", "clearselectors", "-@all"}) {
			t.Fatalf("RoleACLRules(%s) must start by resetting keys, channels, selectors and commands: %v", role, rules[:4])
		}
		for _, rule := range rules {
			for _, token := range strings.Fields(strings.Trim(rule, "()")) {
				if slices.Contains(dangerousACL, token) {
					t.Errorf("RoleACLRules(%s) grants %s", role, token)
				}
			}
		}
		model := parseACL(t, rules)
		probes, err := RoleACLProbes(role)
		if err != nil {
			t.Fatal(err)
		}
		for _, probe := range probes {
			if got := model.permits(probe.Command...); got != probe.Allowed {
				t.Errorf("%s: %v allowed = %v, want %v", role, probe.Command, got, probe.Allowed)
			}
		}
	}
}

// What one method may do does not leak to another method's keys: the api may
// HDEL and HSCAN the DNS index but not SET it (rate limits need SET), so a
// taken api cannot turn a hash into a string and break control's writes.
func TestSelectorsKeepCommandsOnTheirKeys(t *testing.T) {
	t.Parallel()
	model := func(role string) aclModel {
		rules, err := RoleACLRules(role)
		if err != nil {
			t.Fatal(err)
		}
		return parseACL(t, rules)
	}
	api, control, worker, all := model(ACLRoleAPI), model(ACLRoleControl), model(ACLRoleWorker), model(ACLRoleAll)
	for name, test := range map[string]struct {
		model   aclModel
		args    []string
		allowed bool
	}{
		"api sets a rate limit":            {api, []string{"SET", probeKey(managementRateLimitKeyPrefix), "v"}, true},
		"api cannot set the DNS index":     {api, []string{"SET", probeKey(dnsIndexPrefix), "v"}, false},
		"api cannot set site selection":    {api, []string{"SET", probeKey(siteSelectionPrefix), "v"}, false},
		"api prunes site selection":        {api, []string{"HDEL", probeKey(siteSelectionPrefix), "f"}, true},
		"api cannot HSET site selection":   {api, []string{"HSET", probeKey(siteSelectionPrefix), "f", "v"}, false},
		"api reads delivery":               {api, []string{"HMGET", probeKey(deliveryKeyPrefix), "f"}, true},
		"api cannot write delivery":        {api, []string{"HSET", probeKey(deliveryKeyPrefix), "f", "v"}, false},
		"api cannot run writable scripts":  {api, []string{"EVALSHA", probeScript, "1", probeKey(deliveryKeyPrefix)}, false},
		"worker cannot delete CA marks":    {worker, []string{"DEL", probeKey(kubernetesCAMarksPrefix)}, false},
		"worker raises CA marks":           {worker, []string{"HSET", probeKey(kubernetesCAMarksPrefix), "f", "v"}, true},
		"control cannot SET presence":      {control, []string{"SET", probeKey(presenceKeyPrefix), "v"}, false},
		"control cannot HSET kubeops":      {control, []string{"HSET", probeKey(kubernetesOperationLimitPrefix), "f", "v"}, false},
		"control keeps replica loads":      {control, []string{"HSET", replicaLoadKey, "f", "v"}, true},
		"control has no other replica key": {control, []string{"HSET", replicaLoadKey + ":x", "f", "v"}, false},
		"all cannot set the DNS index":     {all, []string{"SET", probeKey(dnsIndexPrefix), "v"}, false},
		"api subscribes to nothing":        {api, []string{"SUBSCRIBE", connectivityChangedChannel}, false},
		"worker hears alias claims":        {worker, []string{"SUBSCRIBE", deviceAliasClaimedChannel}, true},
		"control hears connectivity":       {control, []string{"SUBSCRIBE", connectivityChangedChannel}, true},
		"worker cannot hear connectivity":  {worker, []string{"SUBSCRIBE", connectivityChangedChannel}, false},
	} {
		if got := test.model.permits(test.args...); got != test.allowed {
			t.Errorf("%s: %v allowed = %v, want %v", name, test.args, got, test.allowed)
		}
	}
	// The role that runs everything allows what any role allows.
	for _, role := range []string{ACLRoleAPI, ACLRoleControl, ACLRoleWorker} {
		probes, _ := RoleACLProbes(role)
		for _, probe := range probes {
			if probe.Allowed && !all.permits(probe.Command...) {
				t.Errorf("role all refuses %v, which %s may run", probe.Command, role)
			}
		}
	}
}

func TestACLUser(t *testing.T) {
	t.Parallel()
	for _, role := range ACLRoles {
		user, err := ACLUser(role)
		if err != nil || user != "mesh_"+role {
			t.Errorf("ACLUser(%s) = %q, %v", role, user, err)
		}
	}
	if _, err := ACLUser("identity"); !errors.Is(err, ErrUnknownACLRole) {
		t.Errorf("ACLUser(identity) error = %v, want ErrUnknownACLRole", err)
	}
	if _, err := RoleACLRules("relay"); !errors.Is(err, ErrUnknownACLRole) {
		t.Errorf("RoleACLRules(relay) error = %v, want ErrUnknownACLRole", err)
	}
}

// Each method's own selector, alone, allows its script on every prefix it
// declares: a method never works only because another method of the same
// role grants more (Redis treats EVAL/EVALSHA keys as read-write, so a
// script that only reads must run as EVALSHA_RO).
func TestEachMethodSelectorAllowsItsOwnScript(t *testing.T) {
	t.Parallel()
	for method, need := range methodNeeds {
		var script string
		switch {
		case slices.Contains(need.commands, "evalsha_ro"):
			script = "EVALSHA_RO"
		case slices.Contains(need.commands, "evalsha"):
			script = "EVALSHA"
		default:
			continue
		}
		root := map[string]bool{}
		selector, err := methodSelector(method, need, root)
		if err != nil || selector == "" {
			t.Fatalf("%s: selector %q, %v", method, selector, err)
		}
		keys := []string{}
		for _, prefix := range slices.Concat(need.reads, need.writes) {
			if keyPattern(prefix) == prefix {
				keys = append(keys, prefix) // an exact key, not a prefix
				continue
			}
			keys = append(keys, probeKey(prefix))
		}
		args := slices.Concat([]string{script, probeScript, fmt.Sprint(len(keys))}, keys)
		if !parseACL(t, []string{selector}).permits(args...) {
			t.Errorf("%s: its selector %s refuses %v", method, selector, args)
		}
	}
}
