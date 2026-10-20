package config

import (
	"errors"
	"testing"
)

func TestLoadExitNodes(t *testing.T) {
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
		{value: "yes", present: true, valid: false},
		{value: "", present: true, valid: false},
	} {
		lookup := func(key string) (string, bool) {
			if key == envExitNodes {
				return test.value, test.present
			}
			return "", false
		}
		got, err := loadExitNodes(lookup)
		if (err == nil) != test.valid || (err != nil && !errors.Is(err, ErrInvalid)) || got != test.want {
			t.Errorf("loadExitNodes(%q, %v) = %v, %v", test.value, test.present, got, err)
		}
	}
}
