package config

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"
)

func validRedisACLValues(overrides map[string]string) map[string]string {
	values := map[string]string{
		envRedisAddress:              "redis.internal:6379",
		envRedisCAFile:               "/run/meshtransit/ca.crt",
		envRedisACLAdminUsername:     "redis_admin",
		envRedisACLAdminPasswordFile: "/run/secrets/redis-admin/password",
		envRedisACLPasswordFiles:     "api=/run/secrets/redis-api/password,worker=/run/secrets/redis-worker/password",
	}
	maps.Copy(values, overrides)
	return values
}

func TestLoadRedisACL(t *testing.T) {
	t.Parallel()

	got, err := LoadRedisACL(mapLookup(validRedisACLValues(nil)))
	if err != nil {
		t.Fatalf("LoadRedisACL() error = %v", err)
	}
	if got.Address != "redis.internal:6379" || got.AdminUsername != "redis_admin" || got.Rotate ||
		got.RequestTimeout != 10*time.Second {
		t.Fatalf("LoadRedisACL() = %+v", got)
	}
	if len(got.PasswordFiles) != 2 || got.PasswordFiles["api"].path != "/run/secrets/redis-api/password" ||
		got.PasswordFiles["worker"].path != "/run/secrets/redis-worker/password" {
		t.Fatalf("password files = %+v", got.PasswordFiles)
	}
	if formatted := fmt.Sprintf("%#v", got); strings.Contains(formatted, "/run/secrets/redis-admin") {
		t.Fatalf("formatted config exposed a file path: %s", formatted)
	}
	rotated, err := LoadRedisACL(mapLookup(validRedisACLValues(map[string]string{
		envRedisACLRotate: "true", envRedisACLRequestTimeout: "30s",
	})))
	if err != nil || !rotated.Rotate || rotated.RequestTimeout != 30*time.Second {
		t.Fatalf("rotate config = %+v, %v", rotated, err)
	}
}

// Unsafe values are refused without echoing them; the serving roles'
// Redis user never stands in for the administrator.
func TestLoadRedisACLRejectsMissingOrUnsafeValues(t *testing.T) {
	t.Parallel()

	for name, overrides := range map[string]map[string]string{
		"no address":          {envRedisAddress: ""},
		"no host":             {envRedisAddress: ":6379"},
		"relative CA":         {envRedisCAFile: "ca.crt"},
		"bad admin name":      {envRedisACLAdminUsername: "redis admin"},
		"no admin password":   {envRedisACLAdminPasswordFile: ""},
		"no role passwords":   {envRedisACLPasswordFiles: ""},
		"unknown role":        {envRedisACLPasswordFiles: "identity=/run/secrets/x"}, //nolint:gosec // G101: file paths in a test, not credentials.
		"duplicate role":      {envRedisACLPasswordFiles: "api=/run/secrets/a,api=/run/secrets/b"},
		"shared file":         {envRedisACLPasswordFiles: "api=/run/secrets/a,worker=/run/secrets/a"},
		"admin file reused":   {envRedisACLPasswordFiles: "api=/run/secrets/redis-admin/password"},
		"relative role file":  {envRedisACLPasswordFiles: "api=secrets/a"},
		"no separator":        {envRedisACLPasswordFiles: "api"},
		"too many roles":      {envRedisACLPasswordFiles: "api=/a,control=/c,worker=/w,all=/l,api=/x"}, //nolint:gosec // G101: file paths in a test, not credentials.
		"rotate not boolean":  {envRedisACLRotate: "yes"},
		"timeout too long":    {envRedisACLRequestTimeout: "3m"},
		"timeout not a value": {envRedisACLRequestTimeout: "soon"},
	} {
		_, err := LoadRedisACL(mapLookup(validRedisACLValues(overrides)))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error = %v, want ErrInvalid", name, err)
			continue
		}
		for _, value := range overrides {
			if value != "" && strings.Contains(err.Error(), value) {
				t.Errorf("%s: error exposed %q: %v", name, value, err)
			}
		}
	}
	values := validRedisACLValues(nil)
	delete(values, envRedisACLAdminUsername)
	values[envRedisUsername] = "mesh_api"
	if _, err := LoadRedisACL(mapLookup(values)); !errors.Is(err, ErrInvalid) {
		t.Errorf("the serving user stood in for the administrator: %v", err)
	}
	if _, err := LoadRedisACL(nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("LoadRedisACL(nil) error = %v", err)
	}
}
