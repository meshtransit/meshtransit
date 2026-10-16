package config

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadEnrollmentConfigForControlRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"all", "control"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole:                            role,
				envEnrollmentDigestPreviousKeyID:   "previous-v1",
				envEnrollmentDigestPreviousKeyFile: "/run/secrets/enrollment-digest-previous-key",
			})))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Enrollment == nil {
				t.Fatal("Enrollment = nil for control-plane role")
			}
			digest := got.Enrollment.CredentialDigest
			if digest.Active.ID.String() != "active-v1" || digest.Previous == nil ||
				digest.Previous.ID.String() != "previous-v1" {
				t.Fatalf("credential digest rotation window = %+v, want active and previous keys", digest)
			}
		})
	}
}

func TestLoadEnrollmentConfigRequiresActiveKeyForControlRoles(t *testing.T) {
	t.Parallel()

	for _, setting := range []string{
		envEnrollmentDigestActiveKeyID,
		envEnrollmentDigestActiveKeyFile,
	} {
		t.Run(setting, func(t *testing.T) {
			t.Parallel()

			values := validProcessValues(map[string]string{envRole: "control"})
			delete(values, setting)
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, setting)
			}
		})
	}
}

func TestLoadEnrollmentConfigRejectsUnsafeRotationWithoutEchoingValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		overrides map[string]string
		setting   string
		rejected  string
	}{
		{
			name:      "active key id",
			overrides: map[string]string{envEnrollmentDigestActiveKeyID: " invalid/key"},
			setting:   envEnrollmentDigestActiveKeyID,
			rejected:  " invalid/key",
		},
		{
			name:      "active key file",
			overrides: map[string]string{envEnrollmentDigestActiveKeyFile: "relative/key"},
			setting:   envEnrollmentDigestActiveKeyFile,
			rejected:  "relative/key",
		},
		{
			name:      "previous id without file",
			overrides: map[string]string{envEnrollmentDigestPreviousKeyID: "previous-v1"},
			setting:   envEnrollmentDigestPreviousKeyFile,
			rejected:  "previous-v1",
		},
		{
			name:      "previous file without id",
			overrides: map[string]string{envEnrollmentDigestPreviousKeyFile: "/run/secrets/previous-key"},
			setting:   envEnrollmentDigestPreviousKeyID,
			rejected:  "/run/secrets/previous-key",
		},
		{
			name: "duplicate id",
			overrides: map[string]string{
				envEnrollmentDigestPreviousKeyID:   "active-v1",
				envEnrollmentDigestPreviousKeyFile: "/run/secrets/previous-key",
			},
			setting:  envEnrollmentDigestPreviousKeyID,
			rejected: "active-v1",
		},
		{
			name: "shared key file",
			overrides: map[string]string{
				envEnrollmentDigestPreviousKeyID:   "previous-v1",
				envEnrollmentDigestPreviousKeyFile: "/run/secrets/enrollment-digest-active-key",
			},
			setting:  envEnrollmentDigestPreviousKeyFile,
			rejected: "/run/secrets/enrollment-digest-active-key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(mapLookup(validProcessValues(test.overrides)))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, test.setting)
			}
			if strings.Contains(err.Error(), test.rejected) {
				t.Fatalf("Load() error exposed rejected value %q: %v", test.rejected, err)
			}
		})
	}
}

func TestLoadIgnoresEnrollmentConfigOutsideControlRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"worker", "relay"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			values := validProcessValues(map[string]string{
				envRole:                            role,
				envEnrollmentDigestActiveKeyID:     "invalid/key",
				envEnrollmentDigestActiveKeyFile:   "relative/key",
				envEnrollmentDigestPreviousKeyID:   "also invalid",
				envEnrollmentDigestPreviousKeyFile: "relative/previous",
				envRegistrationMaxAttempts:         "unbounded",
			})
			got, err := Load(mapLookup(values))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Enrollment != nil {
				t.Fatalf("Enrollment = %+v, want nil for role %s", got.Enrollment, role)
			}
		})
	}
}

// The api role reads only the digest keys, to issue enrollment keys; it
// never loads the registration settings, and without the keys it issues
// none.
func TestLoadEnrollmentKeyDigestForTheAPIRole(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(map[string]string{
		envRole:                            "api",
		envEnrollmentDigestPreviousKeyID:   "previous-v1",
		envEnrollmentDigestPreviousKeyFile: "/run/secrets/enrollment-digest-previous-key",
		envRegistrationMaxAttempts:         "unbounded",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Enrollment != nil || got.EnrollmentKeyDigest == nil ||
		got.EnrollmentKeyDigest.Active.ID.String() != "active-v1" || got.EnrollmentKeyDigest.Previous == nil {
		t.Fatalf("api role Enrollment = %+v, EnrollmentKeyDigest = %+v", got.Enrollment, got.EnrollmentKeyDigest)
	}

	values := validProcessValues(map[string]string{envRole: "api"})
	delete(values, envEnrollmentDigestActiveKeyID)
	delete(values, envEnrollmentDigestActiveKeyFile)
	got, err = Load(mapLookup(values))
	if err != nil || got.EnrollmentKeyDigest != nil {
		t.Fatalf("api role without digest keys: %+v, %v", got.EnrollmentKeyDigest, err)
	}

	_, err = Load(mapLookup(validProcessValues(map[string]string{
		envRole: "api", envEnrollmentDigestActiveKeyID: "invalid/key",
	})))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envEnrollmentDigestActiveKeyID) ||
		strings.Contains(err.Error(), "invalid/key") {
		t.Fatalf("api role with an invalid digest key: %v", err)
	}

	all, err := Load(mapLookup(validProcessValues(map[string]string{envRole: "all"})))
	if err != nil || all.Enrollment == nil || all.EnrollmentKeyDigest != &all.Enrollment.CredentialDigest {
		t.Fatalf("all role digest = %p, want the Enrollment digest; %v", all.EnrollmentKeyDigest, err)
	}
}
