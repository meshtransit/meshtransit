package privatefile

import "testing"

func TestTrustedSIDs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		owner   string
		allowed []string
		want    bool
	}{
		{"system only", sidLocalSystem, []string{sidLocalSystem}, true},
		{"system and administrators", sidAdministrators, []string{sidLocalSystem, sidAdministrators}, true},
		{"user owner", "S-1-5-21-1-2-3-1001", []string{sidLocalSystem}, false},
		{"users group granted", sidLocalSystem, []string{sidLocalSystem, "S-1-5-32-545"}, false},
		{"everyone granted", sidLocalSystem, []string{"S-1-1-0"}, false},
	} {
		if got := trustedSIDs(test.owner, test.allowed); got != test.want {
			t.Errorf("%s: trustedSIDs() = %t, want %t", test.name, got, test.want)
		}
	}
}
