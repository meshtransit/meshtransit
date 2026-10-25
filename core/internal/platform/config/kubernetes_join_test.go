package config

import (
	"errors"
	"testing"
)

func TestLoadKubernetesJoin(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value   string
		present bool
		want    bool
		valid   bool
	}{
		{present: false, want: false, valid: true},
		{value: "true", present: true, want: true, valid: true},
		{value: "false", present: true, want: false, valid: true},
		{value: "1", present: true, valid: false},
		{value: "", present: true, valid: false},
	} {
		lookup := func(key string) (string, bool) {
			if key == envKubernetesJoin {
				return test.value, test.present
			}
			return "", false
		}
		got, err := loadKubernetesJoin(lookup)
		if (err == nil) != test.valid || (err != nil && !errors.Is(err, ErrInvalid)) || got != test.want {
			t.Errorf("loadKubernetesJoin(%q, %v) = %v, %v", test.value, test.present, got, err)
		}
	}
}
