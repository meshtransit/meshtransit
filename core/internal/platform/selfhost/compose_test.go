package selfhost

import (
	"fmt"
	"slices"
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
			Volumes     []any             `yaml:"volumes"`
			CapDrop     []string          `yaml:"cap_drop"`
			CapAdd      []string          `yaml:"cap_add"`
			SecurityOpt []string          `yaml:"security_opt"`
			Labels      map[string]string `yaml:"labels"`
			NetworkMode string            `yaml:"network_mode"`
			Networks    map[string]any    `yaml:"networks"`
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
	// Only the proxy publishes ports; the relay is on the host's network
	// (its UDP and STUN ports, IPv6, the clients' real addresses).
	for name, service := range compose.Services {
		if len(service.Ports) > 0 && name != "caddy" {
			t.Errorf("%s publishes %v", name, service.Ports)
		}
	}
	if relay := compose.Services["relay"]; relay.NetworkMode != "host" || len(relay.Networks) != 0 {
		t.Errorf("relay network mode %q, networks %v", relay.NetworkMode, relay.Networks)
	}
	if !strings.HasPrefix(compose.Services["postgres"].Image, "postgres:") ||
		!strings.Contains(compose.Services["postgres"].Image, "@sha256:") {
		t.Errorf("postgres image is not pinned: %s", compose.Services["postgres"].Image)
	}
	caddy := string(rendered.Files["Caddyfile"])
	for _, want := range []string{"mesh.example.com {", "id.mesh.example.com {", "@control path /mtcp/v1* /relay/v1*",
		"tls_trust_pool file /var/lib/meshtransit/secrets/ca.crt", "email ops@example.com",
		"@relay path /mtrp/v1", "reverse_proxy https://172.30.0.1:8479", "tls_server_name relay.meshtransit.internal",
		"http:// {\n\thandle /generate_204 {\n\t\treverse_proxy http://172.30.0.1:8480", "respond 404"} {
		if !strings.Contains(caddy, want) {
			t.Errorf("Caddyfile lacks %q", want)
		}
	}
	hba := string(rendered.Files["pg_hba.conf"])
	// Compose recreates PostgreSQL when its rules change (single-file mount).
	if label := compose.Services["postgres"].Labels["net.meshtransit.pg-hba"]; label != pgHBARevision() ||
		len(label) != 16 {
		t.Errorf("postgres pg-hba label = %q, want %s", label, pgHBARevision())
	}
	if !strings.Contains(hba, "hostssl meshtransit postgres 172.30.0.12/32 scram-sha-256") ||
		!strings.Contains(hba, "mesh_migrator,mesh_runtime,mesh_worker,mesh_all ") ||
		strings.Contains(hba, "mesh_observer") || strings.Contains(hba, " all all ") && !strings.Contains(hba, "local all all") ||
		strings.Contains(hba, "trust") || strings.Contains(hba, "\nhost ") || strings.Count(hba, "postgres") != 1 {
		t.Errorf("pg_hba.conf = %s", hba)
	}
	// Each container sees only the files its settings name.
	mounted := func(name string) string {
		lines := make([]string, 0, len(compose.Services[name].Volumes))
		for _, volume := range compose.Services[name].Volumes {
			lines = append(lines, fmt.Sprint(volume))
		}
		return strings.Join(lines, "\n")
	}
	for name := range compose.Services {
		volumes := mounted(name)
		if strings.Contains(volumes, "/ca.key") || strings.Contains(volumes, "/var/lib/meshtransit:") {
			t.Errorf("%s mounts the CA key or the whole state directory", name)
		}
		if name != "migrate" && name != "postgres" && strings.Contains(volumes, "postgres-superuser-password") {
			t.Errorf("%s mounts the superuser's password", name)
		}
	}
	if relay := fmt.Sprint(compose.Services["relay"].Volumes); len(compose.Services["relay"].Volumes) != 3 ||
		!strings.Contains(relay, "/relay.key:") || !strings.Contains(relay, "/relay-tls.crt:") ||
		!strings.Contains(relay, "/relay-tls.key:") {
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

func TestRelayRunsBehindTheProxyWithItsFallbacks(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	settings := relaySettings(config, testKeys, testLayout)
	for key, want := range map[string]string{
		"MESHRELAY_UDP": "[::]:3479", "MESHRELAY_STUN": "[::]:3478", "MESHRELAY_STUN_ALT": "[::]:3480",
		"MESHRELAY_TLS": "172.30.0.1:8479", "MESHRELAY_PROBE_HTTP": "172.30.0.1:8480",
		"MESHRELAY_TLS_TRUSTED_PROXIES": "172.30.0.10/32,fd30:6d74:7261::10/128",
		"MESHRELAY_TLS_PROXY_ONLY":      "true",
		"MESHRELAY_TLS_CERT":            "/var/lib/meshtransit/secrets/relay-tls.crt",
	} {
		if settings[key] != want {
			t.Errorf("%s = %q, want %q", key, settings[key], want)
		}
	}
	contents, err := relayMapJSON(config, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"tls_port": 443`) {
		t.Fatalf("relay map has no TLS port: %s", contents)
	}
	// The relay's internal TLS name is issued like every other listener.
	found := false
	for _, leaf := range tlsLeaves {
		if leaf.name == "relay-tls" && slices.Equal(leaf.names(config), []string{"relay.meshtransit.internal"}) {
			found = true
		}
	}
	if !found || leafService["relay-tls"] != "relay" {
		t.Fatal("the relay's TLS leaf is not issued or not tied to the relay service")
	}
}
