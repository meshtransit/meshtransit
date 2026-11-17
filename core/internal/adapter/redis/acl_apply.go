package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	redisclient "github.com/redis/go-redis/v9"
)

var (
	// ErrInvalidACLPassword reports a role password that is too short, too
	// long or not printable ASCII without spaces.
	ErrInvalidACLPassword = errors.New("invalid redis acl password")
	// ErrACLPasswordDiffers reports a user whose stored password is not the
	// one given: replacing it would cut off the running pods, so it needs an
	// explicit rotation.
	ErrACLPasswordDiffers = errors.New("redis acl user password differs from the stored one")
	// ErrACLNotPersisted reports a Redis that cannot save its ACL: without an
	// aclfile Redis writes, a restart loses every role user.
	ErrACLNotPersisted = errors.New("redis acl could not be saved; redis needs an aclfile it can write")
	// ErrACLCheckFailed reports a user whose applied ACL does not answer as
	// expected (ACL DRYRUN).
	ErrACLCheckFailed = errors.New("redis acl check failed")
)

const (
	minimumACLPasswordLength = 32
	maximumACLPasswordLength = 256
)

// ACLApplyOptions is one "meshcore redis acl apply": the administrator's
// connection and, per role, the password its user keeps.
type ACLApplyOptions struct {
	Admin     Options
	Passwords map[string][]byte
	// Rotate allows replacing a stored password that differs.
	Rotate bool
}

// ACLUserResult is what one apply did to one role's user.
type ACLUserResult struct {
	Role            string `json:"role"`
	User            string `json:"user"`
	Created         bool   `json:"created"`
	PasswordChanged bool   `json:"password_changed"`
}

// aclAdmin is the administrator connection; a seam for tests.
type aclAdmin interface {
	Do(ctx context.Context, args ...any) (any, error)
	Close() error
}

type goRedisACLAdmin struct{ client *redisclient.Client }

func (admin goRedisACLAdmin) Do(ctx context.Context, args ...any) (any, error) {
	return admin.client.Do(ctx, args...).Result()
}

func (admin goRedisACLAdmin) Close() error { return admin.client.Close() }

// ApplyACL keeps the Redis user of each role given a password: its ACL is
// RoleACLRules, its password the given one, stored only as a SHA-256 digest
// (the password itself never reaches Redis). A user whose stored password
// differs is refused unless Rotate is set. The ACL is then saved to the
// aclfile and each user checked with ACL DRYRUN.
func ApplyACL(ctx context.Context, options ACLApplyOptions) ([]ACLUserResult, error) {
	if ctx == nil || len(options.Passwords) == 0 {
		return nil, ErrInvalidOptions
	}
	password, err := options.Admin.PasswordFile.Read()
	if err != nil {
		return nil, errors.Join(ErrOpen, err)
	}
	caPEM, err := options.Admin.CAFile.Read()
	if err != nil {
		return nil, errors.Join(ErrOpen, err)
	}
	admin := options.Admin
	admin.PoolSize = 1
	clientOptions, err := buildClientOptions(admin, password, caPEM)
	if err != nil {
		return nil, err
	}
	connection := goRedisACLAdmin{client: redisclient.NewClient(clientOptions)}
	results, applyErr := applyACL(ctx, connection, options.Passwords, options.Rotate)
	return results, errors.Join(applyErr, connection.Close())
}

// applyACL works in two passes so a refusal changes nothing: it reads every
// user and decides, then sets every user and checks them; only checked
// users are saved, and a failed check reloads the saved ones.
func applyACL(ctx context.Context, admin aclAdmin, passwords map[string][]byte, rotate bool) ([]ACLUserResult, error) {
	for role, password := range passwords {
		if _, err := ACLUser(role); err != nil {
			return nil, err
		}
		if err := validACLPassword(password); err != nil {
			return nil, fmt.Errorf("%w: role %s", err, role)
		}
	}
	type planned struct {
		result ACLUserResult
		args   []any
	}
	var plan []planned
	for _, role := range ACLRoles {
		password, ok := passwords[role]
		if !ok {
			continue
		}
		result, args, err := planRoleACL(ctx, admin, role, password, rotate)
		if err != nil {
			return nil, err
		}
		plan = append(plan, planned{result: result, args: args})
	}
	results := make([]ACLUserResult, 0, len(plan))
	for _, step := range plan {
		// One ACL SETUSER applies atomically: reset, then exactly this state.
		if _, err := admin.Do(ctx, step.args...); err != nil {
			return results, fmt.Errorf("set redis acl user %s: %w", step.result.User, err)
		}
		results = append(results, step.result)
	}
	for _, result := range results {
		if err := checkRoleACL(ctx, admin, result.Role, result.User); err != nil {
			// Back to the saved users: a wrong rule set never stays live.
			// Redis before 7.2 disconnects every client of the reloaded
			// users here, so every Core pod reconnects once; 7.2 and later
			// disconnect only the clients of users that changed.
			if _, loadErr := admin.Do(ctx, "ACL", "LOAD"); loadErr != nil {
				return results, errors.Join(err, fmt.Errorf("restore saved redis acl: %w", loadErr))
			}
			return nil, err
		}
	}
	if _, err := admin.Do(ctx, "ACL", "SAVE"); err != nil {
		return results, errors.Join(ErrACLNotPersisted, err)
	}
	return results, nil
}

// planRoleACL reads a role's user and returns what to do to it. A stored
// password other than the given one is replaced only with rotate: a running
// pod may still use it.
func planRoleACL(ctx context.Context, admin aclAdmin, role string, password []byte, rotate bool) (
	ACLUserResult, []any, error,
) {
	user, err := ACLUser(role)
	if err != nil {
		return ACLUserResult{}, nil, err
	}
	rules, err := RoleACLRules(role)
	if err != nil {
		return ACLUserResult{}, nil, err
	}
	result := ACLUserResult{Role: role, User: user}
	digest := sha256.Sum256(password)
	wanted := hex.EncodeToString(digest[:])
	stored, err := storedACLUser(ctx, admin, user)
	if err != nil {
		return result, nil, err
	}
	others := slices.DeleteFunc(slices.Clone(stored.passwords), func(stored string) bool { return stored == wanted })
	// A nopass user accepts any password: a pod may rely on that too.
	replaces := len(others) != 0 || stored.nopass
	switch {
	case !stored.exists:
		result.Created, result.PasswordChanged = true, true
	case replaces && !rotate:
		return result, nil, fmt.Errorf("%w: %s", ErrACLPasswordDiffers, user)
	case replaces || len(stored.passwords) == 0:
		result.PasswordChanged = true
	}
	args := []any{"ACL", "SETUSER", user, "reset", "on", "#" + wanted}
	for _, rule := range rules {
		args = append(args, rule)
	}
	return result, args, nil
}

// storedUser is what ACL GETUSER says of a user's authentication.
type storedUser struct {
	exists    bool
	nopass    bool
	passwords []string // SHA-256 digests
}

// storedACLUser reads a user's password digests and nopass flag.
func storedACLUser(ctx context.Context, admin aclAdmin, user string) (storedUser, error) {
	reply, err := admin.Do(ctx, "ACL", "GETUSER", user)
	if errors.Is(err, redisclient.Nil) || err == nil && reply == nil {
		return storedUser{}, nil
	}
	if err != nil {
		return storedUser{}, fmt.Errorf("read redis acl user %s: %w", user, err)
	}
	fields := map[string]any{}
	switch typed := reply.(type) {
	case map[any]any:
		for key, value := range typed {
			if name, ok := key.(string); ok {
				fields[name] = value
			}
		}
	case []any:
		for index := 0; index+1 < len(typed); index += 2 {
			if name, ok := typed[index].(string); ok {
				fields[name] = typed[index+1]
			}
		}
	default:
		return storedUser{}, fmt.Errorf("read redis acl user %s: unexpected reply", user)
	}
	list, ok := fields["passwords"].([]any)
	if !ok {
		return storedUser{}, fmt.Errorf("read redis acl user %s: no password list", user)
	}
	stored := storedUser{exists: true}
	for _, value := range list {
		if digest, ok := value.(string); ok {
			stored.passwords = append(stored.passwords, digest)
		}
	}
	flags, _ := fields["flags"].([]any)
	stored.nopass = slices.Contains(flags, any("nopass"))
	return stored, nil
}

// checkRoleACL runs the role's probes with ACL DRYRUN: each must be allowed
// or refused as RoleACLProbes says.
func checkRoleACL(ctx context.Context, admin aclAdmin, role, user string) error {
	probes, err := RoleACLProbes(role)
	if err != nil {
		return err
	}
	for _, probe := range probes {
		args := []any{"ACL", "DRYRUN", user}
		for _, arg := range probe.Command {
			args = append(args, arg)
		}
		reply, err := admin.Do(ctx, args...)
		if err != nil {
			return fmt.Errorf("%w: %s %s: %w", ErrACLCheckFailed, user, probe.Command[0], err)
		}
		if allowed := reply == "OK"; allowed != probe.Allowed {
			return fmt.Errorf("%w: %s %s allowed = %v, want %v", ErrACLCheckFailed, user, probe.Command[0],
				allowed, probe.Allowed)
		}
	}
	return nil
}

func validACLPassword(password []byte) error {
	if len(password) < minimumACLPasswordLength || len(password) > maximumACLPasswordLength {
		return ErrInvalidACLPassword
	}
	for _, character := range password {
		if character <= ' ' || character > '~' {
			return ErrInvalidACLPassword
		}
	}
	return nil
}
