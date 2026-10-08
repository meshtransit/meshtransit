package config

import "testing"

func TestLoadSignupConfig(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		values        map[string]string
		wantEnabled   bool
		daily, hourly int
		wantErr       bool
	}{
		{name: "absent"},
		{name: "off", values: map[string]string{envSignupEnabled: "false"}},
		{name: "on with defaults", values: map[string]string{envSignupEnabled: "true"}, wantEnabled: true,
			daily: DefaultSignupSourceDailyLimit, hourly: DefaultSignupHourlyLimit},
		{name: "on with limits", values: map[string]string{envSignupEnabled: "true",
			envSignupSourceDailyLimit: "3", envSignupHourlyLimit: "100"}, wantEnabled: true, daily: 3, hourly: 100},
		{name: "not a boolean", values: map[string]string{envSignupEnabled: "yes"}, wantErr: true},
		{name: "limit without enabling", values: map[string]string{envSignupHourlyLimit: "5"}, wantErr: true},
		{name: "zero limit", values: map[string]string{envSignupEnabled: "true", envSignupSourceDailyLimit: "0"},
			wantErr: true},
		{name: "huge limit", values: map[string]string{envSignupEnabled: "true", envSignupHourlyLimit: "100001"},
			wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lookup := func(key string) (string, bool) {
				value, ok := test.values[key]
				return value, ok
			}
			got, err := loadSignupConfig(lookup)
			if (err != nil) != test.wantErr || (got != nil) != test.wantEnabled {
				t.Fatalf("loadSignupConfig() = %+v, %v", got, err)
			}
			if got != nil && (got.SourceDailyLimit != test.daily || got.HourlyLimit != test.hourly) {
				t.Fatalf("limits = %+v", got)
			}
		})
	}
}
