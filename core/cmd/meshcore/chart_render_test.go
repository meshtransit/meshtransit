package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/bootstrap"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/installsecrets"
)

// chartRender is one variant of a Helm chart render, as the chart's render
// tests export it.
type chartRender struct {
	Workloads map[string]chartWorkload `json:"workloads"`
	// CertificateSecrets are the Secrets cert-manager writes.
	CertificateSecrets []string `json:"certificateSecrets"`
}

// chartWorkload is one Core container: its args, its env (ConfigMap values
// resolved; a record made at install time as "@<record>/<key>") and the
// files its volumes give.
type chartWorkload struct {
	Args  []string          `json:"args"`
	Env   map[string]string `json:"env"`
	Files []chartFile       `json:"files"`
}

// chartFile is a mounted file: a ConfigMap's content, or a Secret's key
// ("*" for every key of a Secret mounted whole), with its mode.
type chartFile struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	Mode    uint32 `json:"mode"`
	Content string `json:"content"`
}

// chartCheck is what one workload is checked against.
type chartCheck struct {
	name         string
	workload     chartWorkload
	records      map[string]string
	plan         chartPlan
	certificates []string
}

// chartPlan is the bootstrap plan's fullname and the Secret places
// (name/key) of its items.
type chartPlan struct {
	fullname string
	places   map[string]bool
}

const (
	chartMountRoot           = "/run/meshtransit/"
	chartServiceAccountMount = "/var/run/secrets/kubernetes.io/serviceaccount/"
	// chartDirectorySetting is the one setting that names a directory.
	chartDirectorySetting = "SSL_CERT_DIR"
)

// chartCommands must each be in every render: the roles and every Job of a
// clean install.
var chartCommands = []string{
	"serve", "install bootstrap kubernetes", "install bootstrap deployment", "migrate up",
	"migrate operator apply", "redis acl apply", "identity migrate", "identity fingerprint publish",
}

// chartJobFiles are the files a Job that loads a role's settings must have;
// it names the role's other files without mounting them.
var chartJobFiles = map[string][]string{
	"install bootstrap deployment": {
		"MESHTRANSIT_PRIVATE_LOGIN_CONFIG_FILE", "MESHTRANSIT_BOOTSTRAP_PLAN_FILE",
		"MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE", "MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE",
	},
	"identity fingerprint publish": {
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_SECRET_FILE", "MESHTRANSIT_IDENTITY_CORE_CLIENT_SECRET_FILE",
	},
}

var chartPathPattern = regexp.MustCompile(`/run/meshtransit/[^"\s,]+`)

// TestChartRender loads every Core workload of a chart render with Core's
// own settings loaders, so the chart and Core cannot drift apart: each
// file is written where and with the mode the chart mounts it (Core's own
// checks judge the mode), the release's generated Secrets must be the
// bootstrap plan's, and every path a role is given must be mounted. Run it
// with MESHTRANSIT_CHART_RENDER_DIR set to the chart tests' export
// directory.
func TestChartRender(t *testing.T) {
	directory := os.Getenv("MESHTRANSIT_CHART_RENDER_DIR")
	if directory == "" {
		t.Skip("MESHTRANSIT_CHART_RENDER_DIR is not set")
	}
	exports, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil || len(exports) == 0 {
		t.Fatalf("no chart render exports in the directory: %v", err)
	}
	for _, export := range exports {
		raw, err := os.ReadFile(export) //nolint:gosec // G703: the export directory the test is given.
		if err != nil {
			t.Fatal(err)
		}
		var render chartRender
		if err := json.Unmarshal(raw, &render); err != nil {
			t.Fatalf("%s: %v", filepath.Base(export), err)
		}
		variant := strings.TrimSuffix(filepath.Base(export), ".json")
		plan := chartBootstrapPlan(t, variant, render)
		records := chartRecords(t)
		names := make([]string, 0, len(render.Workloads))
		commands := map[string]bool{}
		for name, workload := range render.Workloads {
			names = append(names, name)
			commands[strings.Join(workload.Args, " ")] = true
		}
		for _, command := range chartCommands {
			if !commands[command] {
				t.Errorf("%s: no workload runs %q", variant, command)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			t.Run(variant+"/"+name, func(t *testing.T) {
				checkChartWorkload(t, chartCheck{
					name: name, workload: render.Workloads[name], records: records, plan: plan,
					certificates: render.CertificateSecrets,
				})
			})
		}
	}
}

// chartBootstrapPlan parses and resolves the bootstrap Job's plan file.
func chartBootstrapPlan(t *testing.T, variant string, render chartRender) chartPlan {
	t.Helper()
	for _, workload := range render.Workloads {
		if strings.Join(workload.Args, " ") != "install bootstrap kubernetes" {
			continue
		}
		for _, file := range workload.Files {
			if file.Path != workload.Env["MESHTRANSIT_INSTALL_PLAN_FILE"] {
				continue
			}
			plan, err := installsecrets.ParsePlan([]byte(file.Content))
			if err != nil {
				t.Fatalf("%s: bootstrap plan: %v", variant, err)
			}
			resolved, err := plan.Resolve()
			if err != nil {
				t.Fatalf("%s: bootstrap plan: %v", variant, err)
			}
			places := map[string]bool{}
			for _, item := range resolved {
				places[item.SecretName+"/"+item.SecretKey] = true
				places[item.SecretName+"/*"] = true
			}
			return chartPlan{fullname: plan.Fullname, places: places}
		}
	}
	t.Fatalf("%s: no bootstrap Job with its plan file", variant)
	return chartPlan{}
}

// chartRecords stands in for the records the bootstrap and fingerprint
// Jobs make at install time.
func chartRecords(t *testing.T) map[string]string {
	t.Helper()
	newID := func() string {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		return id.String()
	}
	return map[string]string{
		"@install/deployment-public-id":    newID(),
		"@login-ids/provider-id":           newID(),
		"@login-ids/client-id":             newID(),
		"@login-state/provider-generation": "1",
		"@login-state/recovery-epoch":      "1",
		"@identity/":                       "sha256-v2:" + hex.EncodeToString(chartRandomKey(t)),
	}
}

// checkChartWorkload writes the workload's files under a temporary root,
// with their modes, rewrites the mount paths to it and loads the settings
// its command loads.
func checkChartWorkload(t *testing.T, check chartCheck) {
	root := t.TempDir() + "/"
	env := make(map[string]string, len(check.workload.Env))
	for key, value := range check.workload.Env {
		if strings.HasPrefix(value, "@") {
			resolved, ok := check.records[value]
			if !ok && strings.HasPrefix(value, "@identity/") {
				resolved, ok = check.records["@identity/"], true
			}
			if !ok {
				t.Fatalf("%s names an unknown install record %s", key, value)
			}
			value = resolved
		}
		env[key] = strings.ReplaceAll(value, chartMountRoot, root)
	}
	written := map[string]bool{}
	for _, file := range check.workload.Files {
		checkChartSecretSource(t, check, file)
		// The service account token's mount is Kubernetes's, not Core's.
		if file.Key == "*" || strings.HasPrefix(file.Path, chartServiceAccountMount) {
			continue
		}
		path := chartLocalPath(t, file.Path, root)
		content := strings.ReplaceAll(file.Content, chartMountRoot, root)
		if file.Kind == "Secret" {
			content = base64.RawURLEncoding.EncodeToString(chartRandomKey(t))
		}
		writeChartFile(t, path, content, file.Mode)
		written[path] = true
	}
	command := strings.Join(check.workload.Args, " ")
	checkChartPaths(t, check, command, env, root, written)
	if err := loadChartWorkload(command, env); err != nil {
		t.Fatalf("%s: %v", command, err)
	}
}

// checkChartSecretSource requires a Secret of the release (named after its
// fullname) to be one the bootstrap plan resolves, or cert-manager's.
func checkChartSecretSource(t *testing.T, check chartCheck, file chartFile) {
	t.Helper()
	if file.Kind != "Secret" || !strings.HasPrefix(file.Name, check.plan.fullname+"-") {
		return
	}
	for _, certificate := range check.certificates {
		if file.Name == certificate {
			return
		}
	}
	if !check.plan.places[file.Name+"/"+file.Key] {
		t.Errorf("%s mounts %s/%s, which the bootstrap plan does not make", file.Path, file.Name, file.Key)
	}
}

// checkChartPaths requires every file a role is given (in its settings or
// in a ConfigMap file such as the login profile) to be mounted; for a Job
// that names a role's files without mounting them, the files it reads.
func checkChartPaths(t *testing.T, check chartCheck, command string, env map[string]string, root string,
	written map[string]bool,
) {
	t.Helper()
	var paths []string
	if required, ok := chartJobFiles[command]; ok && !strings.HasPrefix(check.name, "Deployment/") {
		for _, key := range required {
			paths = append(paths, strings.Replace(env[key], root, chartMountRoot, 1))
		}
	} else {
		for key, value := range check.workload.Env {
			if key == chartDirectorySetting {
				if !chartMountedDirectory(written, strings.Replace(value, chartMountRoot, root, 1)) {
					t.Errorf("%s names %s, which holds no mounted file", key, value)
				}
				continue
			}
			paths = append(paths, chartPathPattern.FindAllString(value, -1)...)
		}
		for _, file := range check.workload.Files {
			paths = append(paths, chartPathPattern.FindAllString(file.Content, -1)...)
		}
	}
	for _, path := range paths {
		if !written[strings.Replace(path, chartMountRoot, root, 1)] {
			t.Errorf("%s is named but not mounted", path)
		}
	}
}

// chartMountedDirectory reports whether path is a directory holding a
// mounted file (SSL_CERT_DIR names one).
func chartMountedDirectory(written map[string]bool, path string) bool {
	for file := range written {
		if strings.HasPrefix(file, strings.TrimSuffix(path, "/")+"/") {
			return true
		}
	}
	return false
}

// loadChartWorkload loads what the command loads at start.
func loadChartWorkload(command string, env map[string]string) error {
	lookup := mapLookupFunc(env)
	var err error
	switch command {
	case "serve":
		return checkChartServe(lookup, false)
	case "install bootstrap deployment":
		if err = checkChartServe(lookup, true); err == nil {
			_, err = config.LoadMigration(lookup)
		}
	case "install bootstrap kubernetes":
		_, err = config.LoadKubernetesBootstrap(lookup)
	case "migrate up", "identity migrate":
		_, err = config.LoadMigration(lookup)
	case "migrate operator apply", "migrate operator apply --after-rollout":
		_, err = config.LoadOperatorMigration(lookup)
	case "redis acl apply":
		_, err = config.LoadRedisACL(lookup)
	case "identity fingerprint publish":
		_, err = config.LoadIdentityFingerprintInput(lookup)
	case "install wait-rollout":
		_, err = loadRolloutSettings(lookup, time.Second)
	default:
		return fmt.Errorf("no loader is mapped for this command: add it to the test")
	}
	return err
}

// checkChartServe loads a role's settings; with a login profile, the
// profile and its route, which must carry the install's IDs. For the
// deployment bootstrap, also the active subject key and the accounts file.
func checkChartServe(lookup config.LookupFunc, bootstrapDeployment bool) error {
	loaded, err := config.Load(lookup)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	if loaded.PrivateLogin == nil {
		if bootstrapDeployment {
			return fmt.Errorf("the deployment bootstrap has no login profile")
		}
		return nil
	}
	ctx := context.Background()
	profile, err := loaded.PrivateLogin.Load(ctx, loaded)
	if err != nil {
		return fmt.Errorf("login profile: %w", err)
	}
	deploymentID, _ := lookup("MESHTRANSIT_DEPLOYMENT_PUBLIC_ID")
	providerID, _ := lookup("MESHTRANSIT_LOGIN_PROVIDER_ID")
	route := profile.Route()
	if route.DeploymentID().String() != deploymentID || fmt.Sprint(route.ProviderID()) != providerID {
		return fmt.Errorf("the login route does not carry the install's IDs")
	}
	if !bootstrapDeployment {
		return nil
	}
	material, err := profile.Keys().LoadSubjectActive(ctx)
	if err != nil {
		return fmt.Errorf("active subject key: %w", err)
	}
	subjectKey, err := bootstrapSubjectKey(material)
	clear(material.Bytes[:])
	if err != nil {
		return fmt.Errorf("active subject key: %w", err)
	}
	contents, err := config.LoadBootstrapPlan(lookup)
	if err != nil {
		return fmt.Errorf("accounts file: %w", err)
	}
	if _, err := bootstrap.NewPlan(contents, route, subjectKey); err != nil {
		return fmt.Errorf("accounts file: %w", err)
	}
	return nil
}

// chartLocalPath maps a mount path under the temporary root; any other
// path is refused rather than written on the host.
func chartLocalPath(t *testing.T, path, root string) string {
	t.Helper()
	rest, ok := strings.CutPrefix(path, chartMountRoot)
	if !ok || rest == "" || strings.Contains(rest, "..") {
		t.Fatalf("mount path %s is outside %s", path, chartMountRoot)
	}
	return root + rest
}

// writeChartFile writes a file with the mode the chart mounts it with, so
// Core's own mode checks judge it.
func writeChartFile(t *testing.T, path, content string, mode uint32) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, os.FileMode(mode&0o777)); err != nil {
		t.Fatal(err)
	}
}

// chartRandomKey is 32 random bytes, never all zero.
func chartRandomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	key[0] |= 1
	return key
}
