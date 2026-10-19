package config

import (
	"errors"
	"testing"
)

func TestLoadSubnetRoutes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value   string
		present bool
		want    bool
		valid   bool
	}{
		{"", false, false, true},
		{"true", true, true, true},
		{"false", true, false, true},
		{"yes", true, false, false},
		{"", true, false, false},
	} {
		lookup := func(key string) (string, bool) {
			if key == envSubnetRoutes {
				return test.value, test.present
			}
			return "", false
		}
		got, err := loadSubnetRoutes(lookup)
		if (err == nil) != test.valid || (err != nil && !errors.Is(err, ErrInvalid)) || got != test.want {
			t.Errorf("loadSubnetRoutes(%q, %v) = %v, %v", test.value, test.present, got, err)
		}
	}
}
