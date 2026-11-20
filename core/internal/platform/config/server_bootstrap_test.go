package config

import (
	"errors"
	"maps"
	"testing"
)

func serverBootstrapEnvironment() map[string]string {
	return map[string]string{ //nolint:gosec // G101 false positive: setting names and file paths, no secret.
		envBootstrapPostgreSQLAddress:      "db.example.test:5432",
		envBootstrapPostgreSQLUser:         "doadmin",
		envBootstrapPostgreSQLPasswordFile: "/run/secrets/admin",
		envBootstrapPostgreSQLCAFile:       "/run/secrets/ca.crt",
		envBootstrapMarker:                 "meshtransit:01995d00-0000-7000-8000-000000000001",
		envBootstrapLoginPasswordFiles:     "mesh_migrator=/run/secrets/migrator, mesh_runtime=/run/secrets/runtime",
	}
}

func lookupFrom(environment map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		value, ok := environment[key]
		return value, ok
	}
}

func TestLoadServerBootstrapDefaults(t *testing.T) {
	t.Parallel()
	loaded, err := LoadServerBootstrap(lookupFrom(serverBootstrapEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MaintenanceDatabase != "postgres" || loaded.CoreDatabase != "meshtransit" || loaded.IdentityDatabase != "" ||
		loaded.RotateLogins || len(loaded.LoginPasswordFiles) != 2 || loaded.ConnectTimeout <= 0 ||
		loaded.StatementTimeout <= 0 {
		t.Fatalf("loaded = %+v", loaded)
	}
}

func TestLoadServerBootstrapRefuses(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(map[string]string){
		"no address":         func(e map[string]string) { delete(e, envBootstrapPostgreSQLAddress) },
		"no admin password":  func(e map[string]string) { delete(e, envBootstrapPostgreSQLPasswordFile) },
		"relative CA":        func(e map[string]string) { e[envBootstrapPostgreSQLCAFile] = "ca.crt" },
		"marker form":        func(e map[string]string) { e[envBootstrapMarker] = "other:x" },
		"marker quote":       func(e map[string]string) { e[envBootstrapMarker] = "meshtransit:a'b" },
		"no migrator":        func(e map[string]string) { e[envBootstrapLoginPasswordFiles] = "mesh_runtime=/run/secrets/runtime" },
		"duplicate login":    func(e map[string]string) { e[envBootstrapLoginPasswordFiles] += ",mesh_runtime=/run/secrets/b" },
		"pair without path":  func(e map[string]string) { e[envBootstrapLoginPasswordFiles] += ",mesh_worker" },
		"identity no logins": func(e map[string]string) { e[envBootstrapIdentityDatabase] = "identity" },
		"identity is core":   func(e map[string]string) { e[envBootstrapIdentityDatabase] = "meshtransit" },
		"identity logins only": func(e map[string]string) {
			e[envBootstrapLoginPasswordFiles] += ",identity_migrator=/run/secrets/im,identity_runtime=/run/secrets/ir"
		},
		"rotate not boolean":  func(e map[string]string) { e[envBootstrapRotateLogins] = "yes" },
		"statement too long":  func(e map[string]string) { e[envBootstrapStatementTimeout] = "1h" },
		"core database quote": func(e map[string]string) { e[envBootstrapCoreDatabase] = `mesh"t` },
	} {
		environment := serverBootstrapEnvironment()
		change(environment)
		if _, err := LoadServerBootstrap(lookupFrom(environment)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: LoadServerBootstrap() = %v", name, err)
		}
	}
}

func TestLoadKubernetesBootstrap(t *testing.T) {
	t.Parallel()
	environment := serverBootstrapEnvironment()
	delete(environment, envBootstrapLoginPasswordFiles)
	environment[envInstallPlanFile] = "/run/meshtransit/plan/plan.json"
	loaded, err := LoadKubernetesBootstrap(lookupFrom(environment))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PlanFile != "/run/meshtransit/plan/plan.json" || loaded.Database.LoginPasswordFiles != nil ||
		loaded.Database.CoreDatabase != "meshtransit" {
		t.Fatalf("loaded = %+v", loaded)
	}
	for name, change := range map[string]func(map[string]string){
		"no plan":       func(e map[string]string) { delete(e, envInstallPlanFile) },
		"relative plan": func(e map[string]string) { e[envInstallPlanFile] = "plan.json" },
		"login files":   func(e map[string]string) { e[envBootstrapLoginPasswordFiles] = "mesh_migrator=/run/m" },
	} {
		changed := maps.Clone(environment)
		change(changed)
		if _, err := LoadKubernetesBootstrap(lookupFrom(changed)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: LoadKubernetesBootstrap() = %v", name, err)
		}
	}
}
