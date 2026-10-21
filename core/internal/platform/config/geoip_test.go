package config

import (
	"errors"
	"testing"
)

func TestLoadGeoIPCountryFile(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value   string
		present bool
		want    string
		valid   bool
	}{
		{present: false, want: "", valid: true},
		{value: "/usr/share/meshtransit/dbip-country-lite.csv.gz", present: true,
			want: "/usr/share/meshtransit/dbip-country-lite.csv.gz", valid: true},
		{value: "", present: true, valid: false},
		{value: "relative.csv", present: true, valid: false},
		{value: "/usr/../etc/x.csv", present: true, valid: false},
	} {
		lookup := func(key string) (string, bool) {
			if key == envGeoIPCountryFile {
				return test.value, test.present
			}
			return "", false
		}
		got, err := loadGeoIPCountryFile(lookup)
		if (err == nil) != test.valid || (err != nil && !errors.Is(err, ErrInvalid)) || got != test.want {
			t.Errorf("loadGeoIPCountryFile(%q, %v) = %q, %v", test.value, test.present, got, err)
		}
	}
}
