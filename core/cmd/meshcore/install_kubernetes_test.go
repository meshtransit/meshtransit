package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/adapter/kubeapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/installsecrets"
)

// fakeSecretStore is a namespace in memory. raceOnCreate makes the first
// create of each Secret lose to a concurrent run that wrote another value.
type fakeSecretStore struct {
	secrets      map[string]kubeapi.Secret
	configMaps   map[string]kubeapi.ConfigMap
	creates      int
	updates      int
	raceOnCreate bool
	// conflicts makes that many updates fail as if another run wrote first.
	conflicts int
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{secrets: map[string]kubeapi.Secret{}, configMaps: map[string]kubeapi.ConfigMap{}}
}

func (store *fakeSecretStore) GetSecret(_ context.Context, name string) (kubeapi.Secret, bool, error) {
	secret, ok := store.secrets[name]
	return secret, ok, nil
}

func (store *fakeSecretStore) CreateSecretIfAbsent(_ context.Context, secret kubeapi.Secret) (bool, error) {
	if _, ok := store.secrets[secret.Metadata.Name]; ok {
		return false, nil
	}
	if store.raceOnCreate {
		other := secret
		other.Data = map[string][]byte{}
		for key := range secret.Data {
			other.Data[key] = bytes.Clone(secret.Data[key])
		}
		store.secrets[secret.Metadata.Name] = other
		return false, nil
	}
	store.creates++
	store.secrets[secret.Metadata.Name] = secret
	return true, nil
}

func (store *fakeSecretStore) GetConfigMap(_ context.Context, name string) (kubeapi.ConfigMap, bool, error) {
	configMap, ok := store.configMaps[name]
	return configMap, ok, nil
}

func (store *fakeSecretStore) CreateConfigMapIfAbsent(_ context.Context, configMap kubeapi.ConfigMap) (bool, error) {
	if _, ok := store.configMaps[configMap.Metadata.Name]; ok {
		return false, nil
	}
	store.configMaps[configMap.Metadata.Name] = configMap
	return true, nil
}

func (store *fakeSecretStore) UpdateConfigMap(_ context.Context, configMap kubeapi.ConfigMap) error {
	if store.conflicts > 0 {
		store.conflicts--
		return kubeapi.ErrConflict
	}
	store.updates++
	store.configMaps[configMap.Metadata.Name] = configMap
	return nil
}

type installKubernetesFixture struct {
	store          *fakeSecretStore
	plan           string
	databaseExists bool
	installations  []string
	bootstrapped   *postgresadapter.ServerBootstrapOptions
	environment    map[string]string
}

func newInstallKubernetesFixture(t *testing.T) *installKubernetesFixture {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"admin", "ca.crt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &installKubernetesFixture{
		store:         newFakeSecretStore(),
		plan:          `{"profile":"cloud","release":"rel","fullname":"mt","features":["kubernetesCA","entitlement","connectionLogs"]}`,
		installations: []string{"01995d00-0000-7000-8000-000000000001"},
		environment: map[string]string{
			"MESHTRANSIT_BOOTSTRAP_POSTGRES_ADDRESS":       "db.example.test:5432",
			"MESHTRANSIT_BOOTSTRAP_POSTGRES_USER":          "doadmin",
			"MESHTRANSIT_BOOTSTRAP_POSTGRES_PASSWORD_FILE": filepath.Join(dir, "admin"),
			"MESHTRANSIT_BOOTSTRAP_POSTGRES_CA_FILE":       filepath.Join(dir, "ca.crt"),
			"MESHTRANSIT_BOOTSTRAP_MARKER":                 "meshtransit:test",
			"MESHTRANSIT_INSTALL_PLAN_FILE":                "/run/meshtransit/install/plan.json",
		},
	}
}

func (fixture *installKubernetesFixture) run(t *testing.T) (int, string, string) {
	t.Helper()
	fixture.bootstrapped = nil
	dependencies := installDependencies{
		bootstrap: func(_ context.Context, options postgresadapter.ServerBootstrapOptions) (postgresadapter.ServerBootstrapReport, error) {
			copied := options
			copied.Logins = nil
			for _, login := range options.Logins {
				login.Password = bytes.Clone(login.Password)
				copied.Logins = append(copied.Logins, login)
			}
			fixture.bootstrapped = &copied
			return postgresadapter.ServerBootstrapReport{}, nil
		},
		databaseExists: func(context.Context, postgresadapter.ServerBootstrapOptions, string) (bool, error) {
			return fixture.databaseExists, nil
		},
		installationIDs: func(context.Context, postgresadapter.ServerBootstrapOptions) ([]string, error) {
			return fixture.installations, nil
		},
		loginIdentity: func(context.Context, postgresadapter.ServerBootstrapOptions, postgresadapter.LoginIdentityQuery) (
			postgresadapter.LoginIdentityRecord, bool, error) {
			return postgresadapter.LoginIdentityRecord{}, false, nil
		},
		newID:       func() (string, error) { return "01995d00-0000-7000-8000-0000000000aa", nil },
		secretStore: func() (installSecretStore, error) { return fixture.store, nil },
		readPlan:    func(string) ([]byte, error) { return []byte(fixture.plan), nil },
		random:      rand.Reader,
	}
	var output, errorOutput bytes.Buffer
	lookup := func(name string) (string, bool) {
		value, ok := fixture.environment[name]
		return value, ok
	}
	code := runInstall(context.Background(), []string{"bootstrap", "kubernetes"}, lookup, &output, &errorOutput,
		dependencies)
	return code, output.String(), errorOutput.String()
}

// A first run creates every Secret of the plan and the public keys, and
// hands each login its password; a second run creates nothing.
func TestInstallKubernetesCreatesThenKeeps(t *testing.T) {
	t.Parallel()
	fixture := newInstallKubernetesFixture(t)
	code, output, errorOutput := fixture.run(t)
	if code != 0 {
		t.Fatalf("first run: %d %s", code, errorOutput)
	}
	var report struct {
		Created    []string `json:"secrets_created"`
		PublicKeys string   `json:"public_keys"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatal(err)
	}
	items, _ := installsecrets.Items(installsecrets.ProfileCloud, []installsecrets.Feature{
		installsecrets.FeatureKubernetesCA, installsecrets.FeatureEntitlement, installsecrets.FeatureConnectionLogs})
	if len(report.Created) != len(items) || report.PublicKeys != "created" {
		t.Fatalf("report = %+v", report)
	}
	noise := fixture.store.secrets["mt-control-noise"]
	if noise.Metadata.Labels[installManagedByLabel] != installManagedBy ||
		noise.Metadata.Annotations["meshtransit.net/backup"] != "required" ||
		!strings.HasPrefix(string(noise.Data["noise.key"]), "privkey:") {
		t.Fatalf("noise Secret = %+v", noise.Metadata)
	}
	publicKeys := fixture.store.configMaps["mt-public-keys"].Data
	if len(publicKeys) != 3 || !strings.HasPrefix(publicKeys["relay-signing"], "mtsign:") {
		t.Fatalf("public keys = %v", publicKeys)
	}
	migrator := fixture.store.secrets["mt-login-mesh-migrator"].Data["password"]
	if fixture.bootstrapped == nil || fixture.bootstrapped.Logins[0].Name != "mesh_migrator" ||
		!bytes.Equal(fixture.bootstrapped.Logins[0].Password, migrator) {
		t.Fatal("the database step did not get the migrator's password")
	}
	if strings.Contains(output, string(migrator)) || strings.Contains(errorOutput, string(migrator)) {
		t.Fatal("a password reached the output")
	}

	before := maps.Clone(fixture.store.secrets)
	code, output, errorOutput = fixture.run(t)
	if code != 0 || strings.Contains(output, "secrets_created") || strings.Contains(output, "public_keys") {
		t.Fatalf("second run: %d %s %s", code, output, errorOutput)
	}
	if !maps.EqualFunc(before, fixture.store.secrets, func(a, b kubeapi.Secret) bool {
		return bytes.Equal(a.Data[firstKey(a)], b.Data[firstKey(b)])
	}) || fixture.store.updates != 0 {
		t.Fatal("a second run changed something")
	}
}

func firstKey(secret kubeapi.Secret) string {
	for key := range secret.Data {
		return key
	}
	return ""
}

func TestInstallKubernetesRefuses(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		prepare func(*installKubernetesFixture)
		code    string
	}{
		"BYO missing": {
			prepare: func(fixture *installKubernetesFixture) {
				fixture.plan = `{"profile":"cloud","release":"rel","fullname":"mt","secrets":{"capture":{"existingSecret":"mine","key":"capture.key"}}}`
			},
			code: "install_secret_missing",
		},
		"not ours": {
			prepare: func(fixture *installKubernetesFixture) {
				fixture.store.secrets["mt-login-mesh-control"] = kubeapi.Secret{
					Metadata: kubeapi.Metadata{Name: "mt-login-mesh-control"},
					Data:     map[string][]byte{"password": bytes.Repeat([]byte("a"), 48)},
				}
			},
			code: "install_secret_not_ours",
		},
		"wrong form": {
			prepare: func(fixture *installKubernetesFixture) {
				fixture.plan = `{"profile":"cloud","release":"rel","fullname":"mt","secrets":{"capture":{"existingSecret":"mine","key":"capture.key"}}}`
				fixture.store.secrets["mine"] = kubeapi.Secret{Metadata: kubeapi.Metadata{Name: "mine"},
					Data: map[string][]byte{"capture.key": []byte("short")}}
			},
			code: "install_secret_invalid",
		},
		"retained key lost": {
			prepare: func(fixture *installKubernetesFixture) { fixture.databaseExists = true },
			code:    "install_retained_key_missing",
		},
		"identity without database": {
			prepare: func(fixture *installKubernetesFixture) {
				fixture.plan = `{"profile":"cloud","release":"rel","fullname":"mt","features":["identity"]}`
			},
			code: "invalid_install_plan",
		},
		"public keys not ours": {
			prepare: func(fixture *installKubernetesFixture) {
				fixture.store.configMaps["mt-public-keys"] = kubeapi.ConfigMap{Metadata: kubeapi.Metadata{Name: "mt-public-keys"}}
			},
			code: "install_public_keys_not_ours",
		},
	} {
		fixture := newInstallKubernetesFixture(t)
		test.prepare(fixture)
		code, _, errorOutput := fixture.run(t)
		if code != 1 || !strings.Contains(errorOutput, test.code) {
			t.Errorf("%s: %d %s", name, code, errorOutput)
		}
		if strings.HasPrefix(test.code, "install_secret") && !strings.Contains(errorOutput, `"item":`) {
			t.Errorf("%s: the log does not name the item: %s", name, errorOutput)
		}
		if fixture.bootstrapped != nil {
			t.Errorf("%s: the database step ran", name)
		}
	}
}

// A BYO Secret is used as it is, a hand-made value with its newline is
// accepted, allowNewRetainedKeys lets a retained key be made for an
// existing database, and a create that loses a race uses the winner's value.
func TestInstallKubernetesUsesWhatExists(t *testing.T) {
	t.Parallel()
	fixture := newInstallKubernetesFixture(t)
	fixture.databaseExists = true
	fixture.plan = `{"profile":"cloud","release":"rel","fullname":"mt","features":["kubernetesCA"],"allowNewRetainedKeys":["control-noise","enrollment-digest","relay-signing","subject-active","kube-ca-wrap-key"],
		"secrets":{"login-mesh-runtime":{"existingSecret":"poc-api","key":"core-postgres-password"}}}`
	runtime := bytes.Repeat([]byte("r"), 40)
	fixture.store.secrets["poc-api"] = kubeapi.Secret{Metadata: kubeapi.Metadata{Name: "poc-api"},
		Data: map[string][]byte{"core-postgres-password": append(bytes.Clone(runtime), '\n')}}
	fixture.store.raceOnCreate = true
	code, _, errorOutput := fixture.run(t)
	if code != 0 {
		t.Fatalf("run: %d %s", code, errorOutput)
	}
	for _, login := range fixture.bootstrapped.Logins {
		if login.Name == "mesh_runtime" && !bytes.Equal(login.Password, runtime) {
			t.Fatal("the BYO password was not used without its newline")
		}
	}
	if _, ok := fixture.store.secrets["mt-kube-ca-wrap-key"]; !ok || fixture.store.creates != 0 {
		t.Fatal("the raced Secrets were not taken from the winner")
	}
	if fixture.store.secrets["poc-api"].Metadata.Labels != nil {
		t.Fatal("a BYO Secret was changed")
	}
}

func TestInstallErrorCode(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		err      error
		fallback string
		want     string
	}{
		{name: "unknown takes the step's code", err: errors.New("other"), fallback: "install_login_ids_failure",
			want: "install_login_ids_failure"},
		{name: "denied by the API server", err: errors.Join(kubeapi.ErrDenied, errors.New("HTTP 403")),
			fallback: "install_secrets_failure", want: "install_kubernetes_denied"},
		{name: "timed out", err: fmt.Errorf("read: %w", context.DeadlineExceeded), fallback: "install_secrets_failure",
			want: "install_timeout"},
		{name: "known cause wins", err: fmt.Errorf("x: %w", errInstallLoginIDs), fallback: "install_login_ids_failure",
			want: "install_login_ids_differ"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := installErrorCode(test.err, test.fallback); got != test.want {
				t.Fatalf("code = %s, want %s", got, test.want)
			}
		})
	}
}

// Login and Redis password Secrets an earlier chart's hooks made for this
// release are taken over; one of another release is not.
func TestInstallKubernetesTakesOverLegacyHookSecrets(t *testing.T) {
	t.Parallel()
	hookSecret := func(release, component string) kubeapi.Secret {
		return kubeapi.Secret{
			Metadata: kubeapi.Metadata{Name: "mt-redis-api", Labels: map[string]string{
				"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": release,
				"app.kubernetes.io/component": component,
			}, Annotations: map[string]string{"helm.sh/hook": "pre-install,pre-upgrade"}},
			Data: map[string][]byte{"password": bytes.Repeat([]byte("Z"), 48)},
		}
	}
	fixture := newInstallKubernetesFixture(t)
	fixture.store.secrets["mt-redis-api"] = hookSecret("rel", "redis-acl")
	if code, _, errorOutput := fixture.run(t); code != 0 {
		t.Fatalf("own release: %d %s", code, errorOutput)
	}
	for release, component := range map[string]string{"other": "redis-acl", "rel": "operator"} {
		fixture := newInstallKubernetesFixture(t)
		fixture.store.secrets["mt-redis-api"] = hookSecret(release, component)
		if code, _, errorOutput := fixture.run(t); code != 1 || !strings.Contains(errorOutput, "install_secret_not_ours") {
			t.Fatalf("%s/%s: %d %s", release, component, code, errorOutput)
		}
	}
}

// A changed public half replaces the ConfigMap, once more after a
// conflict; a retained key made for an existing database is reported.
func TestInstallKubernetesUpdatesPublicKeysAndReportsRetained(t *testing.T) {
	t.Parallel()
	fixture := newInstallKubernetesFixture(t)
	if code, _, errorOutput := fixture.run(t); code != 0 {
		t.Fatalf("first run: %d %s", code, errorOutput)
	}
	stale := fixture.store.configMaps["mt-public-keys"]
	stale.Data = map[string]string{"relay-signing": "mtsign:old"}
	fixture.store.configMaps["mt-public-keys"] = stale
	fixture.store.conflicts = 1
	delete(fixture.store.secrets, "mt-kube-ca-wrap-key")
	fixture.databaseExists = true
	fixture.plan = `{"profile":"cloud","release":"rel","fullname":"mt","features":["kubernetesCA","entitlement","connectionLogs"],
		"allowNewRetainedKeys":["kube-ca-wrap-key"]}`
	code, output, errorOutput := fixture.run(t)
	if code != 0 || !strings.Contains(output, `"public_keys":"updated"`) ||
		!strings.Contains(output, `"retained_keys_generated":["kube-ca-wrap-key"]`) ||
		!strings.Contains(errorOutput, "generated retained keys") {
		t.Fatalf("run: %d %s %s", code, output, errorOutput)
	}
	if fixture.store.configMaps["mt-public-keys"].Data["relay-signing"] == "mtsign:old" {
		t.Fatal("the public keys were not replaced")
	}
	if wrap := fixture.store.secrets["mt-kube-ca-wrap-key"]; wrap.Immutable == nil || !*wrap.Immutable {
		t.Fatal("a generated Secret is not immutable")
	}
	// Left in the list once made, the allowance stops the next run.
	code, _, errorOutput = fixture.run(t)
	if code != 1 || !strings.Contains(errorOutput, "install_retained_allow_stale") {
		t.Fatalf("stale allowance: %d %s", code, errorOutput)
	}
}

// The Deployment ID: the database's, the values' and the recorded one must
// agree and one must exist; it is recorded once, immutable.
func TestEnsureInstallationID(t *testing.T) {
	t.Parallel()
	const databaseID, valuesID = "01995d00-0000-7000-8000-000000000001", "01995d00-0000-7000-8000-000000000002"
	for _, test := range []struct {
		name     string
		values   string
		database []string
		recorded string
		race     string // an ID another run records between the read and the create
		want     string
		err      error
	}{
		{name: "from the database", database: []string{databaseID}, want: databaseID},
		{name: "from the values", values: valuesID, want: valuesID},
		{name: "values agree with the database", values: databaseID, database: []string{databaseID}, want: databaseID},
		{name: "values differ from the database", values: valuesID, database: []string{databaseID}, err: errInstallDeploymentID},
		{name: "recorded kept", recorded: valuesID, want: valuesID},
		{name: "recorded differs from the database", recorded: valuesID, database: []string{databaseID}, err: errInstallDeploymentID},
		{name: "two deployments", database: []string{databaseID, valuesID}, err: errInstallDeploymentID},
		{name: "nothing names it", err: errInstallDeploymentIDRequired},
		{name: "recorded but empty", recorded: "-", err: errInstallNotOurs},
		{name: "race, same ID", values: valuesID, race: valuesID, want: valuesID},
		{name: "race, other ID", values: valuesID, race: databaseID, err: errInstallDeploymentID},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeSecretStore()
			ours := map[string]string{installManagedByLabel: installManagedBy}
			if test.recorded != "" {
				store.configMaps["mt-install"] = kubeapi.ConfigMap{Metadata: kubeapi.Metadata{Name: "mt-install", Labels: ours},
					Data: map[string]string{installDeploymentIDKey: strings.Trim(test.recorded, "-")}}
			}
			var kube installSecretStore = store
			if test.race != "" {
				kube = &racingInstallStore{fakeSecretStore: store, id: test.race}
			}
			got, _, err := ensureInstallationID(context.Background(), kube,
				installsecrets.Plan{Fullname: "mt", DeploymentPublicID: test.values}, test.database, nil)
			if !errors.Is(err, test.err) || (test.err == nil && got != test.want) {
				t.Fatalf("%q, %v", got, err)
			}
			if test.err == nil && store.configMaps["mt-install"].Data[installDeploymentIDKey] != test.want {
				t.Fatalf("recorded %+v", store.configMaps["mt-install"])
			}
		})
	}
	t.Run("foreign ConfigMap", func(t *testing.T) {
		t.Parallel()
		store := newFakeSecretStore()
		store.configMaps["mt-install"] = kubeapi.ConfigMap{Metadata: kubeapi.Metadata{Name: "mt-install"},
			Data: map[string]string{installDeploymentIDKey: databaseID}}
		if _, _, err := ensureInstallationID(context.Background(), store, installsecrets.Plan{Fullname: "mt"},
			[]string{databaseID}, nil); !errors.Is(err, errInstallNotOurs) {
			t.Fatalf("foreign: %v", err)
		}
	})
}

// racingInstallStore loses the create to a run that recorded id.
type racingInstallStore struct {
	*fakeSecretStore
	id string
}

func (store *racingInstallStore) CreateConfigMapIfAbsent(_ context.Context, configMap kubeapi.ConfigMap) (bool, error) {
	store.configMaps[configMap.Metadata.Name] = kubeapi.ConfigMap{Metadata: configMap.Metadata,
		Data: map[string]string{installDeploymentIDKey: store.id}}
	return false, nil
}

// A new installation with a version 5 login profile gets a new Deployment
// ID; without one it must name it.
func TestEnsureInstallationIDNewWithLogin(t *testing.T) {
	t.Parallel()
	newID := func() (string, error) { return "01995d00-0000-7000-8000-0000000000bb", nil }
	plan := installsecrets.Plan{Fullname: "mt", Login: &installsecrets.LoginPlan{Issuer: "https://id.example.test", OIDCClientID: "c"}}
	store := newFakeSecretStore()
	id, recorded, err := ensureInstallationID(context.Background(), store, plan, nil, newID)
	if err != nil || !recorded || id != "01995d00-0000-7000-8000-0000000000bb" {
		t.Fatalf("new with login: %q %v %v", id, recorded, err)
	}
	if _, _, err := ensureInstallationID(context.Background(), newFakeSecretStore(), installsecrets.Plan{Fullname: "mt"}, nil,
		newID); !errors.Is(err, errInstallDeploymentIDRequired) {
		t.Fatalf("new without login: %v", err)
	}
}
