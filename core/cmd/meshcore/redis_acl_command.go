package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

// redisACLApplier applies the role users; a seam for tests.
type redisACLApplier func(context.Context, redisadapter.ACLApplyOptions) ([]redisadapter.ACLUserResult, error)

type redisACLOutput struct {
	Operation string                       `json:"operation"`
	Users     []redisadapter.ACLUserResult `json:"users,omitempty"`
	Role      string                       `json:"role,omitempty"`
	User      string                       `json:"user,omitempty"`
	Rules     []string                     `json:"rules,omitempty"`
}

// runRedisACL runs "meshcore redis acl apply" (keep each role's Redis user,
// as the Redis administrator) and "meshcore redis acl rules <role>" (print a
// role's ACL rules; reads nothing and connects nowhere).
func runRedisACL(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
	apply redisACLApplier,
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	operation, role, ok := redisACLArguments(args)
	if !ok {
		if _, err := io.WriteString(errorOutput, usage); err != nil {
			return 1
		}
		return 2
	}
	if operation == "rules" {
		return printRedisACLRules(ctx, logger, role, output)
	}
	aclConfig, err := config.LoadRedisACL(lookup)
	if err != nil || apply == nil {
		logger.ErrorContext(ctx, "redis acl apply failed", "error_code", "invalid_redis_acl_configuration", "error", err)
		return 1
	}
	passwords := make(map[string][]byte, len(aclConfig.PasswordFiles))
	for role, file := range aclConfig.PasswordFiles {
		password, readErr := file.Read()
		if readErr != nil {
			logger.ErrorContext(ctx, "redis acl apply failed",
				"error_code", "redis_acl_password_unreadable", "role", role)
			return 1
		}
		passwords[role] = []byte(password)
	}
	users, err := apply(ctx, redisadapter.ACLApplyOptions{
		Admin: redisadapter.Options{
			Address:        aclConfig.Address,
			Username:       aclConfig.AdminUsername,
			PasswordFile:   aclConfig.AdminPasswordFile,
			CAFile:         aclConfig.CAFile,
			PoolSize:       1,
			RequestTimeout: aclConfig.RequestTimeout,
		},
		Passwords: passwords,
		Rotate:    aclConfig.Rotate,
	})
	if err != nil {
		logger.ErrorContext(ctx, "redis acl apply failed", "error_code", redisACLErrorCode(err), "error", err)
		return 1
	}
	return writeRedisACLOutput(ctx, logger, output, redisACLOutput{Operation: "redis acl apply", Users: users})
}

// redisACLArguments reads "apply" or "rules <role>".
func redisACLArguments(args []string) (operation, role string, ok bool) {
	switch len(args) {
	case 1:
		return args[0], "", args[0] == "apply"
	case 2:
		return args[0], args[1], args[0] == "rules"
	default:
		return "", "", false
	}
}

func printRedisACLRules(ctx context.Context, logger *slog.Logger, role string, output io.Writer) int {
	user, err := redisadapter.ACLUser(role)
	if err != nil {
		logger.ErrorContext(ctx, "redis acl rules failed", "error_code", "unknown_redis_acl_role")
		return 2
	}
	rules, err := redisadapter.RoleACLRules(role)
	if err != nil {
		logger.ErrorContext(ctx, "redis acl rules failed", "error_code", "redis_acl_rules_failure", "error", err)
		return 1
	}
	return writeRedisACLOutput(ctx, logger, output,
		redisACLOutput{Operation: "redis acl rules", Role: role, User: user, Rules: rules})
}

func writeRedisACLOutput(ctx context.Context, logger *slog.Logger, output io.Writer, result redisACLOutput) int {
	if err := json.NewEncoder(output).Encode(result); err != nil {
		logger.ErrorContext(ctx, "redis acl failed", "error_code", "redis_acl_output_failure")
		return 1
	}
	return 0
}

func redisACLErrorCode(err error) string {
	switch {
	case errors.Is(err, redisadapter.ErrACLPasswordDiffers):
		return "redis_acl_password_differs"
	case errors.Is(err, redisadapter.ErrACLNotPersisted):
		return "redis_acl_not_persisted"
	case errors.Is(err, redisadapter.ErrACLCheckFailed):
		return "redis_acl_check_failed"
	case errors.Is(err, redisadapter.ErrInvalidACLPassword):
		return "redis_acl_invalid_password"
	case errors.Is(err, redisadapter.ErrOpen):
		return "redis_acl_open_failure"
	default:
		return "redis_acl_apply_failure"
	}
}
