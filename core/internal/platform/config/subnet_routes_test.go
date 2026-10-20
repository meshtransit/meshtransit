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

func TestLoadSiteDenied(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value   string
		present bool
		want    int
		valid   bool
	}{
		{"", false, 0, true},
		{"203.0.113.10/32,2001:db8::/48", true, 2, true},
		{"0.0.0.0/0", true, 0, false},
		{"203.0.113.10/24", true, 0, false}, // not canonical
		{"not-a-prefix", true, 0, false},
		{"203.0.113.10/32,203.0.113.10/32", true, 0, false},
	} {
		lookup := func(key string) (string, bool) {
			if key == envSiteDenied {
				return test.value, test.present
			}
			return "", false
		}
		got, err := loadSiteDenied(lookup)
		if (err == nil) != test.valid || (err != nil && !errors.Is(err, ErrInvalid)) || len(got) != test.want {
			t.Errorf("loadSiteDenied(%q) = %v, %v", test.value, got, err)
		}
	}
}
