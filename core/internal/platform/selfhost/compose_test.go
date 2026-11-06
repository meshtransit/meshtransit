package selfhost

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestComposeRunsTheServerFromRenderedFilesOnly(t *testing.T) {
	t.Parallel()
	rendered, err := Render(testConfig(t), approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Image     string            `yaml:"image"`
			User      string            `yaml:"user"`
			Ports     []string          `yaml:"ports"`
			EnvFile   []string          `yaml:"env_file"`
			Env       map[string]string `yaml:"environment"`
			DependsOn map[string]struct {
				Condition string `yaml:"condition"`
			} `yaml:"depends_on"`
			Volumes     []string `yaml:"volumes"`
			CapDrop     []string `yaml:"cap_drop"`
			CapAdd      []string `yaml:"cap_add"`
			SecurityOpt []string `yaml:"security_opt"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(rendered.Files["compose.yaml"], &compose); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"postgres", "redis", "migrate", "meshcore", "console", "caddy", "relay"} {
		service, ok := compose.Services[name]
		if !ok {
			t.Fatalf("no %s service", name)
		}
		// Only the proxy runs as root (it binds 80 and 443), with no other
		// capability; nobody gains privileges later.
		if name != "caddy" && service.User != "65532:65532" || name == "caddy" && service.User != "0:65532" {
			t.Errorf("%s runs as %q", name, service.User)
		}
		wantAdd := ""
		if name == "caddy" || name == "relay" {
			wantAdd = "NET_BIND_SERVICE"
		}
		if strings.Join(service.CapDrop, ",") != "ALL" || strings.Join(service.CapAdd, ",") != wantAdd ||
			strings.Join(service.SecurityOpt, ",") != "no-new-privileges:true" {
			t.Errorf("%s capabilities: drop %v, add %v, %v", name, service.CapDrop, service.CapAdd, service.SecurityOpt)
		}
		for _, value := range service.Env {
			if strings.Contains(value, "PASSWORD") && !strings.HasSuffix(value, "-password") {
				t.Errorf("%s environment holds a value that looks like a secret", name)
			}
		}
	}
	if compose.Services["meshcore"].DependsOn["migrate"].Condition != "service_completed_successfully" {
		t.Error("Core does not wait for setup migrate")
	}
	// Only the proxy and the relay are reachable from outside.
	for name, service := range compose.Services {
		if len(service.Ports) > 0 && name != "caddy" && name != "relay" {
			t.Errorf("%s publishes %v", name, service.Ports)
		}
	}
	if !strings.HasPrefix(compose.Services["postgres"].Image, "postgres:") ||
		!strings.Contains(compose.Services["postgres"].Image, "@sha256:") {
		t.Errorf("postgres image is not pinned: %s", compose.Services["postgres"].Image)
	}
	caddy := string(rendered.Files["Caddyfile"])
	for _, want := range []string{"mesh.example.com {", "id.mesh.example.com {", "@control path /mtcp/v1* /relay/v1*",
		"tls_trust_pool file /var/lib/meshtransit/secrets/ca.crt", "email ops@example.com"} {
		if !strings.Contains(caddy, want) {
			t.Errorf("Caddyfile lacks %q", want)
		}
	}
	hba := string(rendered.Files["pg_hba.conf"])
	if !strings.Contains(hba, "hostssl meshtransit postgres 172.30.0.12/32 scram-sha-256") ||
		strings.Contains(hba, "mesh_observer") || strings.Contains(hba, " all all ") && !strings.Contains(hba, "local all all") ||
		strings.Contains(hba, "trust") || strings.Contains(hba, "\nhost ") || strings.Count(hba, "postgres") != 1 {
		t.Errorf("pg_hba.conf = %s", hba)
	}
	// Each container sees only the files its settings name.
	mounted := func(name string) string { return strings.Join(compose.Services[name].Volumes, "\n") }
	for name := range compose.Services {
		volumes := mounted(name)
		if strings.Contains(volumes, "/ca.key") || strings.Contains(volumes, "/var/lib/meshtransit:") {
			t.Errorf("%s mounts the CA key or the whole state directory", name)
		}
		if name != "migrate" && name != "postgres" && strings.Contains(volumes, "postgres-superuser-password") {
			t.Errorf("%s mounts the superuser's password", name)
		}
	}
	if relay := compose.Services["relay"].Volumes; len(relay) != 1 || !strings.Contains(relay[0], "/relay.key:") {
		t.Errorf("relay mounts %v", relay)
	}
	if strings.Contains(mounted("meshcore"), "postgres-migrator-password") ||
		!strings.Contains(mounted("meshcore"), "/login-subject-active.key:") {
		t.Errorf("meshcore mounts %v", compose.Services["meshcore"].Volumes)
	}
	if !strings.Contains(mounted("migrate"), "/run/bootstrap.env:") || !strings.Contains(mounted("migrate"), "/postgres-superuser-password:") {
		t.Errorf("migrate mounts %v", compose.Services["migrate"].Volumes)
	}
}

func TestCaddyUsesItsOwnCAWithoutAnACMEEmail(t *testing.T) {
	t.Parallel()
	config, err := ParseConfig([]byte(strings.Replace(validConfig, "acme_email: ops@example.com\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(config, approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered.Files["Caddyfile"]), "\tlocal_certs\n") {
		t.Fatal("no local_certs without an ACME email")
	}
}

func TestComposeSizesPostgresForThePools(t *testing.T) {
	t.Parallel()
	command := func(config Config) string {
		rendered, err := Render(config, approvedState(), testKeys, testLayout)
		if err != nil {
			t.Fatal(err)
		}
		var compose struct {
			Services map[string]struct {
				Command []string `yaml:"command"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal(rendered.Files["compose.yaml"], &compose); err != nil {
			t.Fatal(err)
		}
		return strings.Join(compose.Services["postgres"].Command, " ")
	}
	// 4 runtime + 2 worker + 4 broker + 10 reserved.
	base := command(testConfig(t))
	for _, want := range []string{"max_connections=20", "shared_buffers=128MB", "autovacuum_work_mem=32MB"} {
		if !strings.Contains(base, want) {
			t.Errorf("postgres command lacks %s: %s", want, base)
		}
	}
	larger, err := ParseConfig([]byte(validConfig + "advanced:\n  MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS: \"8\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := command(larger); !strings.Contains(got, "max_connections=24") {
		t.Errorf("a larger runtime pool did not raise max_connections: %s", got)
	}
}
