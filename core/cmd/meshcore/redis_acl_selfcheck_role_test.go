package main

import (
	"testing"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/platform/app"
)

// serve checks the Redis user with the role's name (Role.String): every
// role that opens Redis must name a role the ACL knows.
func TestRedisRolesHaveSelfChecks(t *testing.T) {
	t.Parallel()
	for _, role := range []app.Role{app.RoleAll, app.RoleAPI, app.RoleControl, app.RoleWorker} {
		if _, err := redisadapter.RoleSelfCheck(role.String()); err != nil {
			t.Errorf("%s: %v", role, err)
		}
	}
}
