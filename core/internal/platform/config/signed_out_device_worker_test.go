package config

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/app"
)

func TestLoadSignedOutDeviceWorkerConfig(t *testing.T) {
	t.Parallel()
	lookup := func(values map[string]string) LookupFunc {
		return func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		}
	}
	if settings, err := loadSignedOutDeviceWorkerConfig(lookup(nil), app.RoleWorker); err != nil || settings != nil {
		t.Fatalf("off by default = %+v, %v", settings, err)
	}
	on := map[string]string{envSignedOutDeviceWorkerEnabled: "true",
		envSignedOutDeviceWorkerDeployment: "01890f00-0000-7000-8000-000000000001"}
	settings, err := loadSignedOutDeviceWorkerConfig(lookup(on), app.RoleWorker)
	if err != nil || settings == nil || settings.PollInterval != time.Minute ||
		settings.OperationTimeout != 30*time.Second {
		t.Fatalf("defaults = %+v, %v", settings, err)
	}
	for name, values := range map[string]map[string]string{
		"api role":           on,
		"off with a setting": {envSignedOutDeviceWorkerPoll: "10s"},
		"bad poll": {envSignedOutDeviceWorkerEnabled: "true",
			envSignedOutDeviceWorkerDeployment: on[envSignedOutDeviceWorkerDeployment], envSignedOutDeviceWorkerPoll: "2h"},
		"no deployment": {envSignedOutDeviceWorkerEnabled: "true"},
	} {
		role := app.RoleWorker
		if name == "api role" {
			role = app.RoleAPI
		}
		if _, err := loadSignedOutDeviceWorkerConfig(lookup(values), role); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
