package config

import "testing"

func TestLoadBrowserRegistrationConfigRequiresCompleteCanonicalProfile(t *testing.T) {
	t.Parallel()
	settings := map[string]string{
		envBrowserRegistrationOrigin:        "https://console.example.test",
		envBrowserRegistrationDeploymentID:  "01890f00-0000-7000-8000-000000000001",
		envBrowserRegistrationRecoveryEpoch: "1",
		envBrowserRegistrationKeyID:         "browser-poc-v1",
		envBrowserRegistrationKeyFile:       "/run/meshtransit/browser/browser-registration.key",
	}
	lookup := func(values map[string]string) LookupFunc {
		return func(key string) (string, bool) {
			value, ok := values[key]
			return value, ok
		}
	}
	profile, err := loadBrowserRegistrationConfig(lookup(settings))
	if err != nil || profile == nil || profile.Origin != settings[envBrowserRegistrationOrigin] ||
		profile.DeploymentID.String() != settings[envBrowserRegistrationDeploymentID] ||
		profile.RecoveryEpoch != 1 {
		t.Fatalf("valid browser profile = (%+v, %v)", profile, err)
	}
	for name, change := range map[string]func(map[string]string){
		"partial": func(values map[string]string) {
			delete(values, envBrowserRegistrationKeyFile)
		},
		"foreign origin": func(values map[string]string) {
			values[envBrowserRegistrationOrigin] = "http://console.example.test"
		},
		"origin path": func(values map[string]string) {
			values[envBrowserRegistrationOrigin] = "https://console.example.test/console"
		},
		"epoch": func(values map[string]string) {
			values[envBrowserRegistrationRecoveryEpoch] = "0"
		},
		"key identifier": func(values map[string]string) {
			values[envBrowserRegistrationKeyID] = "bad key"
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := make(map[string]string, len(settings))
			for key, value := range settings {
				values[key] = value
			}
			change(values)
			if profile, err := loadBrowserRegistrationConfig(lookup(values)); profile != nil || err == nil {
				t.Fatalf("invalid browser profile = (%+v, %v)", profile, err)
			}
		})
	}
}
