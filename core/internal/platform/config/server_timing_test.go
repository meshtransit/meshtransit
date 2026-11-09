package config

import "testing"

func TestServerTimingIsOffUnlessExactlyTrue(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]bool{"": false, "false": false, "true": true} {
		lookup := func(name string) (string, bool) {
			if name == envServerTiming && value != "" {
				return value, true
			}
			return "", false
		}
		got, err := loadServerTiming(lookup)
		if err != nil || got != want {
			t.Fatalf("%q = %v/%v, want %v", value, got, err, want)
		}
	}
	for _, value := range []string{"TRUE", "1", "yes", " true"} {
		lookup := func(name string) (string, bool) { return value, name == envServerTiming }
		if _, err := loadServerTiming(lookup); err == nil {
			t.Fatalf("%q was accepted", value)
		}
	}
}
