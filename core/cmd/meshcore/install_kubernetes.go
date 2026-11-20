package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

	"meshtransit.net/core/internal/adapter/kubeapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/installsecrets"
)

// installSecretStore is the part of the Kubernetes API the bootstrap uses:
// read, create-if-absent, and update its own ConfigMap. It has no update or
// delete for Secrets.
type installSecretStore interface {
	GetSecret(ctx context.Context, name string) (kubeapi.Secret, bool, error)
	CreateSecretIfAbsent(ctx context.Context, secret kubeapi.Secret) (bool, error)
	GetConfigMap(ctx context.Context, name string) (kubeapi.ConfigMap, bool, error)
	CreateConfigMapIfAbsent(ctx context.Context, configMap kubeapi.ConfigMap) (bool, error)
	UpdateConfigMap(ctx context.Context, configMap kubeapi.ConfigMap) error
}

const (
	installManagedByLabel = "app.kubernetes.io/managed-by"
	installManagedBy      = "meshtransit-bootstrap"
	installItemLabel      = "meshtransit.net/install-item"
	maximumInstallPlan    = 64 << 10
)

var (
	errInstallPlan = errors.New("install: invalid plan")
	// errInstallSecretMissing: a Secret or key the installer brings (BYO)
	// is not there.
	errInstallSecretMissing = errors.New("install: the installer's Secret or key is missing")
	// errInstallSecretNotOurs: a Secret has a catalog name but was not made
	// by the bootstrap; it is used only when the plan names it (BYO).
	errInstallSecretNotOurs = errors.New("install: a Secret with a catalog name was not made by the bootstrap")
	// errInstallSecretInvalid: a value does not have its item's form, or
	// the bootstrap's Secret lost its key (it never rewrites one).
	errInstallSecretInvalid = errors.New("install: a Secret value is missing or has the wrong form")
	// errInstallRetainedKeyMissing: a key that must be kept is missing while
	// the database exists; generating a new one would break what the old
	// one protects.
	errInstallRetainedKeyMissing = errors.New("install: a key that must be kept is missing and the database exists; " +
		"restore it from the backup, or set allowNewRetainedKeys")
	errInstallPublicKeysNotOurs = errors.New("install: the public-keys ConfigMap was not made by the bootstrap")
	errInstallSetup             = errors.New("install: the command is not wired")
	// errInstallRetainedAllowStale: allowNewRetainedKeys still names an item
	// whose Secret exists; left there, it would let a later loss pass
	// silently.
	errInstallRetainedAllowStale = errors.New("install: allowNewRetainedKeys names a key that exists; remove it from the list")
)

// legacyHookComponents are the chart components whose hooks made login and
// Redis password Secrets before the bootstrap Job (chart 0.2.x); the
// bootstrap takes those over under the same names.
var legacyHookComponents = map[string]string{"login-": "operator", "redis-": "redis-acl"}

// installItemError says which item and Secret failed; never a value.
type installItemError struct {
	ID, Secret string
	Err        error
}

func (failure *installItemError) Error() string {
	return failure.ID + " (Secret " + failure.Secret + "): " + failure.Err.Error()
}

func (failure *installItemError) Unwrap() error { return failure.Err }

// installSecretsReport names what the Secret step changed; never values.
type installSecretsReport struct {
	Created []string `json:"secrets_created,omitempty"`
	// RetainedGenerated lists retained keys made anew for a database that
	// exists (allowNewRetainedKeys): what pinned the old ones must change.
	RetainedGenerated []string `json:"retained_keys_generated,omitempty"`
	PublicKeys        string   `json:"public_keys,omitempty"`
}

func runInstallKubernetes(ctx context.Context, lookup config.LookupFunc, output io.Writer, logger *slog.Logger,
	dependencies installDependencies,
) int {
	fail := func(code string, err error) int {
		attributes := []any{"error_code", code, "error", err}
		var item *installItemError
		if errors.As(err, &item) {
			// Names only: the log redacts error text, and these say where.
			attributes = append(attributes, "item", item.ID, "secret", item.Secret)
		}
		logger.ErrorContext(ctx, "install bootstrap failed", attributes...)
		return 1
	}
	bootstrapConfig, err := config.LoadKubernetesBootstrap(lookup)
	if err != nil {
		return fail("invalid_bootstrap_configuration", err)
	}
	plan, err := loadInstallPlan(dependencies, bootstrapConfig)
	if errors.Is(err, errInstallSetup) {
		return fail("install_setup_invalid", err)
	}
	if err != nil {
		return fail("invalid_install_plan", err)
	}
	resolved, err := plan.Resolve()
	if err != nil {
		return fail("invalid_install_plan", err)
	}
	store, err := dependencies.secretStore()
	if err != nil {
		return fail("install_kubernetes_unavailable", err)
	}
	connection, err := serverBootstrapOptions(bootstrapConfig.Database, nil)
	if err != nil {
		return fail("invalid_bootstrap_configuration", err)
	}
	run := &installSecretsRun{
		store: store, plan: plan, random: dependencies.random,
		databaseExists: func() (bool, error) {
			return dependencies.databaseExists(ctx, connection, bootstrapConfig.Database.CoreDatabase)
		},
	}
	values, report, err := run.ensure(ctx, resolved)
	defer clearPasswords(values)
	if err != nil {
		return fail(installSecretsErrorCode(err), err)
	}
	if len(report.RetainedGenerated) != 0 {
		logger.WarnContext(ctx, "install bootstrap generated retained keys for an existing database",
			"items", report.RetainedGenerated)
	}
	passwords := map[string][]byte{}
	for _, entry := range resolved {
		if entry.Login != "" {
			passwords[entry.Login] = values[entry.ID]
		}
	}
	options, err := serverBootstrapOptions(bootstrapConfig.Database, passwords)
	if err != nil {
		return fail("bootstrap_unknown_login", err)
	}
	databaseReport, err := dependencies.bootstrap(ctx, options)
	if err != nil {
		return fail(serverBootstrapErrorCode(err), err)
	}
	return writeInstallReport(output, struct {
		Operation string `json:"operation"`
		installSecretsReport
		Postgres postgresadapter.ServerBootstrapReport `json:"postgres"`
	}{Operation: "install bootstrap kubernetes", installSecretsReport: report, Postgres: databaseReport})
}

func loadInstallPlan(dependencies installDependencies, bootstrapConfig config.KubernetesBootstrapConfig,
) (installsecrets.Plan, error) {
	if dependencies.readPlan == nil || dependencies.secretStore == nil || dependencies.databaseExists == nil ||
		dependencies.random == nil {
		return installsecrets.Plan{}, errInstallSetup
	}
	data, err := dependencies.readPlan(bootstrapConfig.PlanFile)
	if err != nil {
		return installsecrets.Plan{}, errors.Join(errInstallPlan, err)
	}
	plan, err := installsecrets.ParsePlan(data)
	if err != nil {
		return installsecrets.Plan{}, err
	}
	// The identity logins and database go together.
	if slices.Contains(plan.Features, installsecrets.FeatureIdentity) != (bootstrapConfig.Database.IdentityDatabase != "") {
		return installsecrets.Plan{}, fmt.Errorf("%w: the identity feature and the identity database differ", errInstallPlan)
	}
	return plan, nil
}

// readInstallPlan reads the plan file the chart mounts, bounded.
func readInstallPlan(path string) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the configured plan path, validated as absolute.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maximumInstallPlan+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximumInstallPlan {
		return nil, errInstallPlan
	}
	return data, nil
}

type installSecretsRun struct {
	store          installSecretStore
	plan           installsecrets.Plan
	random         io.Reader
	databaseExists func() (bool, error)
	exists         *bool
}

// ensure reads or creates every item's Secret, in order, and then the
// public-keys ConfigMap. It returns each item's value (the caller clears
// them) and what it created.
func (run *installSecretsRun) ensure(ctx context.Context, resolved []installsecrets.Resolved,
) (map[string][]byte, installSecretsReport, error) {
	values := map[string][]byte{}
	report := installSecretsReport{}
	for _, entry := range resolved {
		value, created, err := run.ensureItem(ctx, entry)
		if err != nil {
			return values, report, &installItemError{ID: entry.ID, Secret: entry.SecretName, Err: err}
		}
		values[entry.ID] = value
		if created {
			report.Created = append(report.Created, entry.SecretName)
			if entry.Retained && run.exists != nil && *run.exists {
				report.RetainedGenerated = append(report.RetainedGenerated, entry.ID)
			}
		}
	}
	publicKeys, err := run.publish(ctx, resolved, values)
	if err != nil {
		return values, report, err
	}
	report.PublicKeys = publicKeys
	return values, report, nil
}

func (run *installSecretsRun) ensureItem(ctx context.Context, entry installsecrets.Resolved) ([]byte, bool, error) {
	secret, found, err := run.store.GetSecret(ctx, entry.SecretName)
	if err != nil {
		return nil, false, err
	}
	if found {
		if slices.Contains(run.plan.AllowNewRetainedKeys, entry.ID) {
			return nil, false, errInstallRetainedAllowStale
		}
		value, err := run.existingValue(entry, secret)
		return value, false, err
	}
	if entry.BYO {
		return nil, false, errInstallSecretMissing
	}
	if entry.Retained {
		exists, err := run.coreDatabaseExists()
		if err != nil {
			return nil, false, err
		}
		if exists && !slices.Contains(run.plan.AllowNewRetainedKeys, entry.ID) {
			return nil, false, errInstallRetainedKeyMissing
		}
	}
	value, err := installsecrets.Generate(entry.Kind, run.random)
	if err != nil {
		return nil, false, err
	}
	created, err := run.store.CreateSecretIfAbsent(ctx, installSecret(entry, value))
	if err != nil {
		clear(value)
		return nil, false, err
	}
	if created {
		return value, true, nil
	}
	// Another run created it first: use what it wrote.
	clear(value)
	secret, found, err = run.store.GetSecret(ctx, entry.SecretName)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, errInstallSecretMissing
	}
	value, err = run.existingValue(entry, secret)
	return value, false, err
}

// existingValue checks a Secret that exists: the bootstrap's own (its
// labels name this item), one an earlier chart's hook made for this release
// (login and Redis passwords), or the installer's (BYO); its key must hold
// a value Core's reader of the item takes. Whoever may create Secrets in
// the namespace may also forge these labels: that is a namespace
// administrator, trusted with the install anyway.
func (run *installSecretsRun) existingValue(entry installsecrets.Resolved, secret kubeapi.Secret) ([]byte, error) {
	if !entry.BYO && !run.ownSecret(entry, secret.Metadata) && !run.legacyHookSecret(entry, secret.Metadata) {
		return nil, errInstallSecretNotOurs
	}
	raw, ok := secret.Data[entry.SecretKey]
	if !ok {
		if entry.BYO {
			return nil, errInstallSecretMissing
		}
		return nil, errInstallSecretInvalid
	}
	value, err := installsecrets.Normalize(entry.Kind, raw)
	if err != nil {
		return nil, errInstallSecretInvalid
	}
	return bytes.Clone(value), nil
}

func (run *installSecretsRun) ownSecret(entry installsecrets.Resolved, metadata kubeapi.Metadata) bool {
	return metadata.Labels[installManagedByLabel] == installManagedBy && metadata.Labels[installItemLabel] == entry.ID
}

// legacyHookSecret reports a Secret the chart's own operator or redis-acl
// hook made for this release before the bootstrap Job existed.
func (run *installSecretsRun) legacyHookSecret(entry installsecrets.Resolved, metadata kubeapi.Metadata) bool {
	for prefix, component := range legacyHookComponents {
		if strings.HasPrefix(entry.ID, prefix) {
			return metadata.Labels[installManagedByLabel] == "Helm" &&
				metadata.Labels["app.kubernetes.io/instance"] == run.plan.Release &&
				metadata.Labels["app.kubernetes.io/component"] == component &&
				metadata.Annotations["helm.sh/hook"] != ""
		}
	}
	return false
}

func (run *installSecretsRun) coreDatabaseExists() (bool, error) {
	if run.exists == nil {
		exists, err := run.databaseExists()
		if err != nil {
			return false, fmt.Errorf("check the Core database: %w", err)
		}
		run.exists = &exists
	}
	return *run.exists, nil
}

func installSecret(entry installsecrets.Resolved, value []byte) kubeapi.Secret {
	annotations := map[string]string{
		// Argo CD tracks by label: never prune or diff what the Job made.
		"argocd.argoproj.io/compare-options": "IgnoreExtraneous",
		"argocd.argoproj.io/sync-options":    "Prune=false",
	}
	if entry.Retained {
		annotations["meshtransit.net/backup"] = "required"
	}
	immutable := true
	return kubeapi.Secret{
		// Rotation deletes the Secret (the bootstrap then makes a new one);
		// nothing edits a value in place.
		Immutable: &immutable,
		Metadata: kubeapi.Metadata{
			Name: entry.SecretName,
			Labels: map[string]string{
				installManagedByLabel:       installManagedBy,
				"app.kubernetes.io/part-of": "meshtransit",
				installItemLabel:            entry.ID,
			},
			Annotations: annotations,
		},
		// A copy: the caller clears its value after the run.
		Data: map[string][]byte{entry.SecretKey: bytes.Clone(value)},
	}
}

// publish writes the public halves to the public-keys ConfigMap: created
// when absent, replaced when it differs, left alone otherwise. It reports
// "created", "updated" or "".
func (run *installSecretsRun) publish(ctx context.Context, resolved []installsecrets.Resolved,
	values map[string][]byte,
) (string, error) {
	data := map[string]string{}
	for _, entry := range resolved {
		if entry.Public == installsecrets.PublicNone {
			continue
		}
		half, err := installsecrets.PublicHalf(entry.Item, values[entry.ID])
		if err != nil {
			return "", fmt.Errorf("%s: %w", entry.ID, err)
		}
		data[string(entry.Public)] = half
	}
	name := installsecrets.PublicKeysConfigMap(run.plan.Fullname)
	labels := map[string]string{installManagedByLabel: installManagedBy, "app.kubernetes.io/part-of": "meshtransit"}
	existing, found, err := run.store.GetConfigMap(ctx, name)
	if err != nil {
		return "", err
	}
	if !found {
		created, err := run.store.CreateConfigMapIfAbsent(ctx, kubeapi.ConfigMap{
			Metadata: kubeapi.Metadata{Name: name, Labels: labels}, Data: data,
		})
		if err != nil {
			return "", err
		}
		if created {
			return "created", nil
		}
		// Created by another run since: compare with what it wrote.
		if existing, found, err = run.store.GetConfigMap(ctx, name); err != nil || !found {
			return "", errors.Join(errInstallPublicKeysNotOurs, err)
		}
	}
	return run.updatePublicKeys(ctx, name, existing, data)
}

// updatePublicKeys replaces existing's data when it differs; a conflict
// (another run wrote first) is read again once and compared.
func (run *installSecretsRun) updatePublicKeys(ctx context.Context, name string, existing kubeapi.ConfigMap,
	data map[string]string,
) (string, error) {
	for attempt := 0; ; attempt++ {
		if existing.Metadata.Labels[installManagedByLabel] != installManagedBy {
			return "", errInstallPublicKeysNotOurs
		}
		if maps.Equal(existing.Data, data) {
			return "", nil
		}
		existing.Data = data
		err := run.store.UpdateConfigMap(ctx, existing)
		if err == nil {
			return "updated", nil
		}
		if !errors.Is(err, kubeapi.ErrConflict) || attempt > 0 {
			return "", err
		}
		var found bool
		if existing, found, err = run.store.GetConfigMap(ctx, name); err != nil || !found {
			return "", errors.Join(errInstallPublicKeysNotOurs, err)
		}
	}
}

func installSecretsErrorCode(err error) string {
	for _, known := range []struct {
		err  error
		code string
	}{
		{errInstallSecretMissing, "install_secret_missing"},
		{errInstallSecretNotOurs, "install_secret_not_ours"},
		{errInstallSecretInvalid, "install_secret_invalid"},
		{errInstallRetainedKeyMissing, "install_retained_key_missing"},
		{errInstallRetainedAllowStale, "install_retained_allow_stale"},
		{errInstallPublicKeysNotOurs, "install_public_keys_not_ours"},
		{kubeapi.ErrConflict, "install_conflict"},
		{postgresadapter.ErrMigrationOpen, "bootstrap_open_failure"},
	} {
		if errors.Is(err, known.err) {
			return known.code
		}
	}
	return "install_secrets_failure"
}
