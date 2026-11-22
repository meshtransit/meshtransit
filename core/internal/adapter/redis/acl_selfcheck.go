package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	redisclient "github.com/redis/go-redis/v9"
)

// A role checks at start that its Redis user may run what it needs (design
// v1-11-bootstrap §6), whoever made the user: the chart's ACL Job, the
// installer at a provider (providerUsers) or the provider itself (single).
// It queues each command it needs, on a probe key under each prefix it uses
// and on each of its channels, inside MULTI and then DISCARDs: Redis checks
// the ACL when it queues a command, so a missing right answers NOPERM and
// nothing runs. The commands a script calls are queued themselves, since
// Redis checks them only when the script runs.

var (
	// ErrACLMissing reports commands the role needs and its user may not run.
	ErrACLMissing = errors.New("redis acl: the user may not run commands this role needs")
	// ErrACLCheckUnavailable reports a server that refuses MULTI for this
	// user (made before the check, or a proxy without transactions): the
	// check cannot run.
	ErrACLCheckUnavailable = errors.New("redis acl: MULTI refused, so the user's rights are not checked")
	// ErrACLCheckTransient reports a server or network not ready (loading,
	// failing over, unreachable): the check may pass on another try.
	ErrACLCheckTransient = errors.New("redis acl: the check could not run yet")
	// errConnectionNotReady marks a failure before MULTI: dialing, HELLO,
	// AUTH or PING (max clients, a restart, the network).
	errConnectionNotReady = errors.New("redis acl: the check's connection is not ready")
)

// selfCheckSkipped are commands not queued: the connection already ran
// them, or Redis refuses them inside MULTI.
var selfCheckSkipped = map[string]bool{"hello": true, "auth": true, "subscribe": true, "unsubscribe": true,
	"multi": true, "discard": true}

// selfCheckWrites need a key pattern the role may write.
var selfCheckWrites = map[string]bool{"del": true, "set": true, "hdel": true, "hset": true, "pexpire": true,
	"zadd": true, "zrem": true, "zremrangebyscore": true, "eval": true, "evalsha": true}

// selfCheckTemplates build a well-formed command on key ("" for a command
// that names none). Nothing runs: the arguments only pass the arity check.
var selfCheckTemplates = map[string]func(key string) []any{
	"ping":             func(string) []any { return []any{"PING"} },
	"time":             func(string) []any { return []any{"TIME"} },
	"del":              func(key string) []any { return []any{"DEL", key} },
	"exists":           func(key string) []any { return []any{"EXISTS", key} },
	"get":              func(key string) []any { return []any{"GET", key} },
	"set":              func(key string) []any { return []any{"SET", key, "v"} },
	"hdel":             func(key string) []any { return []any{"HDEL", key, "f"} },
	"hget":             func(key string) []any { return []any{"HGET", key, "f"} },
	"hmget":            func(key string) []any { return []any{"HMGET", key, "f"} },
	"hgetall":          func(key string) []any { return []any{"HGETALL", key} },
	"hscan":            func(key string) []any { return []any{"HSCAN", key, "0"} },
	"hset":             func(key string) []any { return []any{"HSET", key, "f", "v"} },
	"pexpire":          func(key string) []any { return []any{"PEXPIRE", key, "1000"} },
	"zadd":             func(key string) []any { return []any{"ZADD", key, "1", "m"} },
	"zrem":             func(key string) []any { return []any{"ZREM", key, "m"} },
	"zremrangebyscore": func(key string) []any { return []any{"ZREMRANGEBYSCORE", key, "0", "1"} },
	"zcount":           func(key string) []any { return []any{"ZCOUNT", key, "0", "1"} },
	"eval":             func(key string) []any { return []any{"EVAL", "return 0", "1", key} },
	"evalsha":          func(key string) []any { return []any{"EVALSHA", probeScript, "1", key} },
	"eval_ro":          func(key string) []any { return []any{"EVAL_RO", "return 0", "1", key} },
	"evalsha_ro":       func(key string) []any { return []any{"EVALSHA_RO", probeScript, "1", key} },
}

// RoleSelfCheck returns the commands a role queues to check its user: each
// command of each method on each key prefix it may use that way, and a
// PUBLISH on each of its channels. Deterministic and without repeats.
func RoleSelfCheck(role string) ([][]any, error) {
	methods, err := roleMethodSet(role)
	if err != nil {
		return nil, err
	}
	var commands [][]any
	seen := map[string]bool{}
	add := func(command []any) {
		if text := fmt.Sprint(command); !seen[text] {
			seen[text] = true
			commands = append(commands, command)
		}
	}
	for _, method := range methods {
		need, ok := methodNeeds[method]
		if !ok {
			return nil, fmt.Errorf("redis acl: method %s has no declared need", method)
		}
		for _, channel := range sortedValues(need.channels) {
			add([]any{"PUBLISH", channel, ""})
		}
		for _, command := range sortedValues(need.commands) {
			if selfCheckSkipped[command] || command == "publish" {
				continue
			}
			template, ok := selfCheckTemplates[command]
			if !ok {
				return nil, fmt.Errorf("redis acl: command %s of %s has no self-check", command, method)
			}
			if rootCommands[command] || command == "time" && len(need.reads)+len(need.writes) == 0 {
				add(template(""))
				continue
			}
			prefixes := need.writes
			if !selfCheckWrites[command] {
				prefixes = slices.Concat(need.reads, need.writes)
			}
			for _, prefix := range sortedValues(prefixes) {
				add(template(selfCheckKey(prefix)))
			}
		}
	}
	return commands, nil
}

// selfCheckKey is the key a probe names: under a prefix (ending in ':') a
// key no Core code uses; a full key name (an exact ACL pattern) itself,
// which is safe because a queued command never runs.
func selfCheckKey(prefix string) string {
	if strings.HasSuffix(prefix, ":") {
		return probeKey(prefix)
	}
	return prefix
}

// selfCheckTimeout bounds one whole check (about sixty round trips).
const selfCheckTimeout = 30 * time.Second

// CheckACL queues the role's self-check (RoleSelfCheck) on one connection
// and reports what the user may not run. Redis checks the ACL before its
// other queue-time checks, so only a permission error (NOPERM) means a
// missing right, and an ERR reply (unknown command, arity) means the role
// cannot run that command either; OOM, READONLY and the like mean the
// ACL passed. Errors:
//   - ErrACLCheckUnavailable: the server refuses MULTI itself (a user made
//     before the check, or a proxy without transactions);
//   - ErrACLCheckTransient: the server or network is not ready; try again;
//   - *ACLMissingError: what is missing.
func (client *Client) CheckACL(ctx context.Context, role string) error {
	commands, err := RoleSelfCheck(role)
	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	refused, err := client.queueCommands(checkCtx, commands)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return err
		case errors.Is(err, errConnectionNotReady):
			return errors.Join(ErrACLCheckTransient, err)
		case redisclient.IsPermissionError(err) || errorReply(err):
			return errors.Join(ErrACLCheckUnavailable, err)
		default:
			return errors.Join(ErrACLCheckTransient, err)
		}
	}
	var missing []string
	for index, command := range commands {
		refusal, ok := refused[index]
		if !ok {
			continue
		}
		switch {
		case redisclient.IsPermissionError(refusal):
			missing = append(missing, describeProbe(command)+" (NOPERM)")
		case errorReply(refusal):
			missing = append(missing, describeProbe(command)+" (ERR)")
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &ACLMissingError{Missing: missing}
}

// errorReply reports a Redis ERR reply (unknown command, wrong arity).
// go-redis's HasErrorPrefix drops a leading "ERR " (for KVRocks), so it
// cannot tell one.
func errorReply(err error) bool {
	var server redisclient.Error
	return errors.As(err, &server) && strings.HasPrefix(server.Error(), "ERR ")
}

// ACLMissingError lists what the role's user may not run: each as the
// command, the key prefix or channel it was checked on, and Redis's error
// class (NOPERM, ERR). No value: safe to log.
type ACLMissingError struct{ Missing []string }

func (missing *ACLMissingError) Error() string {
	return ErrACLMissing.Error() + ": " + strings.Join(missing.Missing, ", ")
}

func (missing *ACLMissingError) Unwrap() error { return ErrACLMissing }

// describeProbe names a probe by its command and the key prefix or channel
// it checks, never a value.
func describeProbe(command []any) string {
	text := fmt.Sprint(command[0])
	if len(command) > 1 {
		for _, argument := range command[1:] {
			if value, ok := argument.(string); ok && strings.HasPrefix(value, "meshtransit:") {
				return text + " " + strings.TrimSuffix(value, "acl-probe")
			}
		}
	}
	return text
}

// queueOnOneConnection is the Client's queueCommands: MULTI, each command
// (a Redis error per command is its refusal), DISCARD. It uses a client of
// its own, closed after, so no connection left inside MULTI (DISCARD
// refused, a broken read) ever returns to the role's pool. A connection
// error ends the check.
func queueOnOneConnection(options *redisclient.Options) func(context.Context, [][]any) (map[int]error, error) {
	return func(ctx context.Context, commands [][]any) (map[int]error, error) {
		single := *options
		single.PoolSize, single.MaxActiveConns, single.MinIdleConns = 1, 1, 0
		client := redisclient.NewClient(&single)
		defer func() { _ = client.Close() }()
		connection := client.Conn()
		defer func() { _ = connection.Close() }()
		// The first command dials (HELLO, AUTH): a refusal there (max
		// clients, a restart) is not MULTI's, so it is told apart.
		if err := connection.Do(ctx, "PING").Err(); err != nil {
			return nil, errors.Join(errConnectionNotReady, err)
		}
		if err := connection.Do(ctx, "MULTI").Err(); err != nil {
			return nil, err
		}
		refused := map[int]error{}
		for index, command := range commands {
			err := connection.Do(ctx, command...).Err()
			var server redisclient.Error
			switch {
			case err == nil:
			case errors.As(err, &server):
				refused[index] = err
			default:
				return nil, err
			}
		}
		if err := connection.Do(ctx, "DISCARD").Err(); err != nil {
			return nil, err
		}
		return refused, nil
	}
}

// ErrorClass names the kind of a Redis failure for a log, never its text:
// the error word of a Redis reply (NOPERM, WRONGPASS, ERR), "timeout",
// "network" or "other".
func ErrorClass(err error) string {
	var server redisclient.Error
	var network net.Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &server):
		if fields := strings.Fields(server.Error()); len(fields) > 0 && strings.ToUpper(fields[0]) == fields[0] {
			return fields[0]
		}
		return "redis"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &network):
		return "network"
	default:
		return "other"
	}
}
