package selfhost

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var renewStart = time.Date(2026, 11, 14, 3, 0, 0, 0, time.UTC)

const (
	month = 30 * 24 * time.Hour
	day   = 24 * time.Hour
)

var errInjected = errors.New("injected")

// installedAt runs setup at now and returns its secrets directory.
func installedAt(t *testing.T, now time.Time) string {
	t.Helper()
	dir := secretsDir(t)
	if _, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func renewAt(t *testing.T, dir string, now time.Time) RenewReport {
	t.Helper()
	report, err := RenewTLS(testConfig(t), dir, GenerateOptions{Now: now})
	if err != nil {
		t.Fatalf("RenewTLS() at %s: %v", now.Format(time.DateOnly), err)
	}
	return report
}

// failAt stops a run at point.
func failAt(now time.Time, point string) GenerateOptions {
	return GenerateOptions{Now: now, fault: func(at string) error {
		if at == point {
			return errInjected
		}
		return nil
	}}
}

func leafOf(t *testing.T, dir, name string) *x509.Certificate {
	t.Helper()
	certificate, _, err := readPair(filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func trustOf(t *testing.T, dir string) trust {
	t.Helper()
	current, err := readTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func pendingOf(t *testing.T, dir string) []string {
	t.Helper()
	pending, err := PendingRestart(dir)
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

// restarted plays the host's timer: the services restarted, the file goes.
func restarted(t *testing.T, dir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(restartDir(dir), RestartFile)); err != nil {
		t.Fatal(err)
	}
}

// everyLeafTrusted checks what the running services see: each leaf is
// signed by a CA the bundle holds.
func everyLeafTrusted(t *testing.T, dir string) {
	t.Helper()
	current := trustOf(t, dir)
	for _, leaf := range tlsLeaves {
		if !current.trusts(leafOf(t, dir, leaf.name)) {
			t.Fatalf("%s is signed by no CA of ca.crt", leaf.name)
		}
	}
}

// rollReady installs and takes the roll's first step; the restart is done.
// It returns when the second step may run.
func rollReady(t *testing.T) (string, time.Time) {
	t.Helper()
	dir := installedAt(t, renewStart)
	start := trustOf(t, dir).signing.NotAfter.Add(-caRollBefore + day)
	if first := renewAt(t, dir, start); first.CAStep != CAStepTrustNext {
		t.Fatalf("first run = %+v", first)
	}
	restarted(t, dir)
	return dir, start.Add(2 * day)
}

func TestRenewTLSKeepsLeavesWithMoreThanAThirdOfTheirLife(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	before := leafOf(t, dir, "api")
	report := renewAt(t, dir, renewStart.Add(15*month))
	if len(report.Renewed) != 0 || len(report.Restart) != 0 || report.CAStep != "" {
		t.Fatalf("report = %+v, want nothing renewed", report)
	}
	if !leafOf(t, dir, "api").Equal(before) {
		t.Fatal("api.crt changed")
	}
	if _, err := os.Lstat(filepath.Join(restartDir(dir), RestartFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart file: %v", err)
	}
}

func TestRenewTLSRenewsDueLeavesAndNamesTheirServices(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	oldKey := readFile(t, dir, "postgres.key")
	now := renewStart.Add(17 * month) // a 2-year leaf has less than 8 months left
	report := renewAt(t, dir, now)
	if !slices.Equal(report.Renewed, leafNames()) {
		t.Fatalf("renewed %v, want every leaf", report.Renewed)
	}
	if want := []string{"postgres", "redis", "meshcore", "console"}; !slices.Equal(report.Restart, want) {
		t.Fatalf("restart %v, want %v (a leaf changes no reader of ca.crt alone)", report.Restart, want)
	}
	if got := string(readFile(t, restartDir(dir), RestartFile)); got != "postgres redis meshcore console" {
		t.Fatalf("restart file = %q", got)
	}
	if string(readFile(t, dir, "postgres.key")) == string(oldKey) {
		t.Fatal("the renewed leaf kept its key")
	}
	renewed := leafOf(t, dir, "login")
	if !slices.Equal(renewed.DNSNames, []string{testConfig(t).Domain}) || !renewed.NotBefore.Before(now) ||
		renewed.NotAfter.Sub(now) < leafLifetime-time.Hour {
		t.Fatalf("login.crt names %v, valid %s – %s", renewed.DNSNames, renewed.NotBefore, renewed.NotAfter)
	}
	everyLeafTrusted(t, dir)
	// The next run renews nothing and keeps the restart the host has not
	// done yet.
	again := renewAt(t, dir, now.Add(time.Hour))
	if len(again.Renewed) != 0 || len(again.Restart) != 4 {
		t.Fatalf("second run = %+v", again)
	}
	if _, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: now}); err != nil {
		t.Fatalf("setup accepts the renewed leaves: %v", err)
	}
}

func TestRenewTLSKeepsTheNamesALeafHas(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	// config.yaml names another domain, not applied yet.
	moved, err := ParseConfig([]byte(strings.Replace(validConfig, "mesh.example.com", "vpn.example.com", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenewTLS(moved, dir, GenerateOptions{Now: renewStart.Add(17 * month)}); err != nil {
		t.Fatal(err)
	}
	if names := leafOf(t, dir, "login").DNSNames; !slices.Equal(names, []string{testConfig(t).Domain}) {
		t.Fatalf("login.crt names %v, want the name the running Core uses", names)
	}
}

func TestSetupRenewsADueLeafAndNamesItsService(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	report, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: renewStart.Add(17 * month)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(report.Renewed, leafNames()) || slices.Contains(report.Created, "api.crt") {
		t.Fatalf("renewed %v, created %v: the due leaves are renewed, not created", report.Renewed, report.Created)
	}
	if pending := pendingOf(t, dir); !slices.Equal(pending, []string{"postgres", "redis", "meshcore", "console"}) {
		t.Fatalf("PendingRestart() = %v", pending)
	}
}

// A run stopped half way has already queued every service whose files it
// changed: the restart the host does after it loads them.
func TestRenewTLSQueuesARestartBeforeItChangesAFile(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	report, err := RenewTLS(testConfig(t), dir, failAt(renewStart.Add(17*month), "leaf:api"))
	if !errors.Is(err, errInjected) {
		t.Fatalf("RenewTLS() = %v", err)
	}
	if !slices.Equal(report.Renewed, []string{"postgres", "redis"}) {
		t.Fatalf("renewed %v, want the leaves replaced before the failure", report.Renewed)
	}
	for _, service := range []string{"postgres", "redis"} {
		if !slices.Contains(pendingOf(t, dir), service) || !slices.Contains(report.Restart, service) {
			t.Fatalf("%s changed but is not queued: %v", service, report.Restart)
		}
	}
	// setup apply stopped the same way queues too.
	other := installedAt(t, renewStart)
	if _, err := GenerateSecrets(testConfig(t), other, failAt(renewStart.Add(17*month), "leaf:redis")); !errors.Is(err,
		errInjected) {
		t.Fatalf("GenerateSecrets() = %v", err)
	}
	if !slices.Contains(pendingOf(t, other), "postgres") {
		t.Fatal("setup renewed postgres.crt without queueing postgres")
	}
}

func TestCARollTakesThreeStepsADayApart(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	oldCA := trustOf(t, dir).signing
	start := oldCA.NotAfter.Add(-caRollBefore + day) // the CA has less than two years left

	first := renewAt(t, dir, start)
	if first.CAStep != CAStepTrustNext {
		t.Fatalf("first run = %+v, want %s", first, CAStepTrustNext)
	}
	afterFirst := trustOf(t, dir)
	if !afterFirst.signing.Equal(oldCA) || len(afterFirst.bundle) != 2 {
		t.Fatalf("after trust-next: signing changed or bundle has %d CAs", len(afterFirst.bundle))
	}
	for _, service := range trustReaders {
		if !slices.Contains(first.Restart, service) {
			t.Fatalf("restart %v lacks %s", first.Restart, service)
		}
	}
	everyLeafTrusted(t, dir)

	// While the restart has not happened, the roll waits.
	held := renewAt(t, dir, start.Add(2*day))
	if held.CAStep != "" || held.Waiting != "a restart is pending" {
		t.Fatalf("pending restart: %+v", held)
	}
	restarted(t, dir)
	// Less than a day after the new CA was trusted, the roll waits.
	if early := renewAt(t, dir, start.Add(12*time.Hour)); early.CAStep != "" || early.Waiting == "" {
		t.Fatalf("a day apart: %+v", early)
	}

	second := renewAt(t, dir, start.Add(2*day))
	if second.CAStep != CAStepPromote || !slices.Equal(second.Restart, restartOrder) ||
		!slices.Equal(second.Renewed, leafNames()) {
		t.Fatalf("second run = %+v", second)
	}
	afterSecond := trustOf(t, dir)
	if afterSecond.signing.Equal(oldCA) || !afterSecond.bundle[0].Equal(afterSecond.signing) ||
		!afterSecond.contains(oldCA) {
		t.Fatal("after promote: the new CA must sign and lead the bundle, the old one still trusted")
	}
	for _, leaf := range tlsLeaves {
		if leafOf(t, dir, leaf.name).CheckSignatureFrom(afterSecond.signing) != nil {
			t.Fatalf("%s is not signed by the new CA", leaf.name)
		}
	}
	for _, name := range []string{caNextKeyFile, caNextCertificateFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left behind: %v", name, err)
		}
	}
	// Between the steps setup still accepts every file.
	if _, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: start.Add(2 * day)}); err != nil {
		t.Fatalf("setup between promote and drop-old: %v", err)
	}
	restarted(t, dir)
	if early := renewAt(t, dir, start.Add(2*day+2*time.Hour)); early.CAStep != "" || early.Waiting == "" {
		t.Fatalf("drop-old a day after promote: %+v", early)
	}

	third := renewAt(t, dir, start.Add(3*day+2*time.Hour))
	if third.CAStep != CAStepDropOld || !slices.Equal(third.Restart, trustReaders) {
		t.Fatalf("third run = %+v", third)
	}
	final := trustOf(t, dir)
	if len(final.bundle) != 1 || !final.signing.Equal(afterSecond.signing) {
		t.Fatal("after drop-old the bundle holds the new CA alone")
	}
	everyLeafTrusted(t, dir)
	restarted(t, dir)
	if done := renewAt(t, dir, start.Add(4*day)); done.CAStep != "" || done.Waiting != "" || len(done.Renewed) != 0 {
		t.Fatalf("after the roll: %+v", done)
	}
	if _, err := GenerateSecrets(testConfig(t), dir, GenerateOptions{Now: start.Add(4 * day)}); err != nil {
		t.Fatalf("setup after the roll: %v", err)
	}
}

// A promotion killed after the key moved: the leaves are the new CA's and
// every service was queued before; recovery finishes it, and the old CA
// stays trusted until the queued restart happened.
func TestPromotionStoppedAfterTheKeyFinishesAndHoldsTheLastStep(t *testing.T) {
	t.Parallel()
	dir, now := rollReady(t)
	if _, err := RenewTLS(testConfig(t), dir, failAt(now, "promote:key")); !errors.Is(err, errInjected) {
		t.Fatalf("RenewTLS() = %v", err)
	}
	if pending := pendingOf(t, dir); !slices.Equal(pending, restartOrder) {
		t.Fatalf("pending %v, want every service", pending)
	}
	// Two days on, the restart has not happened: no drop-old.
	held := renewAt(t, dir, now.Add(2*day))
	current := trustOf(t, dir)
	if held.CAStep != "" || held.Waiting != "a restart is pending" || len(current.bundle) != 2 ||
		!current.bundle[0].Equal(current.signing) {
		t.Fatalf("held = %+v, bundle %d", held, len(current.bundle))
	}
	if _, err := os.Lstat(filepath.Join(dir, caNextCertificateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ca-next.crt: %v", err)
	}
	everyLeafTrusted(t, dir)
	restarted(t, dir)
	if last := renewAt(t, dir, now.Add(2*day)); last.CAStep != CAStepDropOld {
		t.Fatalf("after the restart: %+v", last)
	}
}

func TestTrustNextStoppedBeforeTheBundleFinishes(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	next, keyPEM, err := newCA(renewStart)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		caNextKeyFile: keyPEM, caNextCertificateFile: encodeCertificates([]*x509.Certificate{next}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report := renewAt(t, dir, renewStart.Add(time.Hour))
	if report.CAStep != CAStepTrustNext || !slices.Equal(report.Restart, trustReaders) ||
		!trustOf(t, dir).contains(next) {
		t.Fatalf("report = %+v", report)
	}
}

func TestRenewTLSFinishesOrUndoesAnInterruptedRun(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	current := trustOf(t, dir)
	stage := func(name string) {
		t.Helper()
		leaf := tlsLeaves[slices.IndexFunc(tlsLeaves, func(leaf tlsLeaf) bool { return leaf.name == name })]
		certificate, key, err := issueLeaf(current.signing, current.key, leaf.names(testConfig(t)), renewStart)
		if err != nil {
			t.Fatal(err)
		}
		for file, contents := range map[string][]byte{name + ".crt.next": certificate, name + ".key.next": key} {
			if err := os.WriteFile(filepath.Join(dir, file), contents, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Stopped after the key was renamed in: the new certificate follows it,
	// and the restart that loads both is queued.
	stage("api")
	if err := os.Rename(filepath.Join(dir, "api.key.next"), filepath.Join(dir, "api.key")); err != nil {
		t.Fatal(err)
	}
	// Stopped before any rename: the staged pair goes, the pair in place stays.
	before := leafOf(t, dir, "redis")
	stage("redis")
	// A certificate staged for a key that is not in place goes too.
	stage("console")
	if err := os.Remove(filepath.Join(dir, "console.key.next")); err != nil {
		t.Fatal(err)
	}
	// Stopped after the new CA's key only: it goes.
	_, keyPEM, err := newCA(renewStart)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caNextKeyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	report := renewAt(t, dir, renewStart.Add(time.Hour))
	leafOf(t, dir, "api") // the pair matches again
	if !leafOf(t, dir, "redis").Equal(before) {
		t.Fatal("redis.crt changed")
	}
	if !slices.Equal(report.Restart, []string{"meshcore"}) {
		t.Fatalf("restart %v, want the service of the recovered api pair", report.Restart)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".next") || strings.HasPrefix(entry.Name(), "ca-next") {
			t.Fatalf("%s left behind", entry.Name())
		}
	}
}

func TestRestartFileNamesOnlyKnownServices(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	if err := os.MkdirAll(restartDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restartDir(dir), RestartFile), []byte("meshcore; rm -rf /\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RenewTLS(testConfig(t), dir, GenerateOptions{Now: renewStart}); !errors.Is(err, ErrSecrets) {
		t.Fatalf("RenewTLS() with an unknown service = %v", err)
	}
}

func TestEveryLeafHasAServiceToRestart(t *testing.T) {
	t.Parallel()
	for _, leaf := range tlsLeaves {
		if !slices.Contains(restartOrder, leafService[leaf.name]) {
			t.Errorf("%s has no service in the restart order", leaf.name)
		}
	}
	for _, service := range trustReaders {
		if !slices.Contains(restartOrder, service) {
			t.Errorf("trust reader %s is not in the restart order", service)
		}
	}
}

func TestPrepareRenewDirRefusesALink(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	if err := os.Symlink(t.TempDir(), restartDir(dir)); err != nil {
		t.Fatal(err)
	}
	if err := PrepareRenewDir(dir); !errors.Is(err, ErrSecrets) {
		t.Fatalf("PrepareRenewDir() over a link = %v", err)
	}
}

func TestLeafNeverOutlivesItsCA(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	current := trustOf(t, dir)
	certificatePEM, _, err := issueLeaf(current.signing, current.key, []string{"api." + internalDomain},
		current.signing.NotAfter.Add(-month))
	if err != nil {
		t.Fatal(err)
	}
	if leaf := parseCertificate(t, certificatePEM); leaf.NotAfter.After(current.signing.NotAfter) {
		t.Fatalf("leaf ends %s after its CA %s", leaf.NotAfter, current.signing.NotAfter)
	}
}

func TestRenewStatusKeepsTheLastSuccess(t *testing.T) {
	t.Parallel()
	dir := installedAt(t, renewStart)
	if err := WriteRenewStatus(dir, renewStart, RenewReport{Renewed: []string{"api"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteRenewStatus(dir, renewStart.Add(day), RenewReport{}, errors.New("no config")); err != nil {
		t.Fatal(err)
	}
	status, err := readRenewStatus(restartDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if status.Result != "error" || status.Error != "no config" || !status.LastSuccess.Equal(renewStart) ||
		!status.LastRun.Equal(renewStart.Add(day)) || status.EarliestLeafNotAfter.IsZero() || status.CANotAfter.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestRenderedTimerRestartsOnlyKnownServices(t *testing.T) {
	t.Parallel()
	rendered, err := Render(testConfig(t), approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	service := string(rendered.Files[renewServiceUnit])
	for _, want := range []string{
		"ExecStart=docker compose -f " + testLayout.RunDir + "/compose.yaml --profile maintenance run --rm --no-TTY renew-tls",
		"ExecStopPost=flock /var/lib/meshtransit/.setup.lock /bin/sh -c '",
		"f=" + filepath.Join(filepath.Dir(testLayout.SecretsDir), RenewDir, RestartFile),
		`case "$$s" in postgres|redis|meshcore|console|caddy) ;;`,
		`up -d --no-deps --no-recreate --wait "$$s" || exit 1; done; rm -f -- "$$f"`,
		"TimeoutStartSec=15min", "TimeoutStopSec=15min",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("service unit lacks %q:\n%s", want, service)
		}
	}
	// systemd would expand a single $ itself.
	if strings.Count(service, "$") != 2*strings.Count(service, "$$") {
		t.Errorf("service unit has an unescaped $:\n%s", service)
	}
	timer := string(rendered.Files[renewTimerUnit])
	for _, want := range []string{"OnCalendar=*-*-* 03:00:00", "OnBootSec=5min", "Persistent=true",
		"WantedBy=timers.target"} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer lacks %q", want)
		}
	}

	var compose struct {
		Services map[string]struct {
			User        string   `yaml:"user"`
			Profiles    []string `yaml:"profiles"`
			NetworkMode string   `yaml:"network_mode"`
			CapAdd      []string `yaml:"cap_add"`
			CapDrop     []string `yaml:"cap_drop"`
			Volumes     []any    `yaml:"volumes"`
			Command     []string `yaml:"command"`
			Networks    any      `yaml:"networks"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(rendered.Files["compose.yaml"], &compose); err != nil {
		t.Fatal(err)
	}
	renew := compose.Services[renewService]
	stateDir := filepath.Dir(testLayout.SecretsDir)
	if renew.User != "0:0" || !slices.Equal(renew.Profiles, []string{"maintenance"}) || renew.NetworkMode != "none" ||
		renew.Networks != nil || !slices.Equal(renew.CapAdd, []string{"CHOWN", "DAC_OVERRIDE"}) ||
		!slices.Equal(renew.CapDrop, []string{"ALL"}) ||
		!slices.Equal(renew.Command, []string{"setup", "renew-tls", "--state-dir=" + stateDir}) {
		t.Fatalf("renew-tls = %+v", renew)
	}
	var mounts []string
	for _, entry := range renew.Volumes {
		volume, _ := entry.(map[string]any)
		bind, _ := volume["bind"].(map[string]any)
		if volume["type"] != "bind" || volume["source"] != volume["target"] || bind["create_host_path"] != false {
			t.Fatalf("renew-tls mount %v may create its source", volume)
		}
		mounts = append(mounts, fmt.Sprintf("%v:%v", volume["source"], volume["read_only"]))
	}
	want := []string{testLayout.SecretsDir + ":false", stateDir + "/.setup.lock:false", stateDir + "/renew:false",
		OperatorDir + ":true"}
	if !slices.Equal(mounts, want) {
		t.Fatalf("renew-tls mounts %v, want %v", mounts, want)
	}
}

// restartScript is the shell the service unit runs after renewal, as the
// shell receives it.
func restartScript(t *testing.T, layout Layout) string {
	t.Helper()
	service := string(renewUnits(layout)[renewServiceUnit])
	start := strings.Index(service, "/bin/sh -c '") + len("/bin/sh -c '")
	end := strings.LastIndex(service, "'")
	return strings.ReplaceAll(service[start:end], "$$", "$")
}

func TestRestartScriptRestartsInOrderAndKeepsTheFileOnFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	layout := Layout{SecretsDir: filepath.Join(root, "secrets"), RunDir: filepath.Join(root, "run")}
	bin, log := filepath.Join(root, "bin"), filepath.Join(root, "docker.log")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// A docker that logs its arguments and fails to restart FAIL_SERVICE.
	fake := "#!/bin/sh\necho \"$*\" >> " + log + "\n[ \"$5\" = \"$FAIL_SERVICE\" ] && exit 1\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fake), 0o700); err != nil { // #nosec G306 -- a test executable.
		t.Fatal(err)
	}
	restartFile := filepath.Join(restartDir(layout.SecretsDir), RestartFile)
	run := func(contents, fail string) (string, error) {
		t.Helper()
		_ = os.Remove(log)
		if err := os.MkdirAll(filepath.Dir(restartFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(restartFile, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), "/bin/sh", "-c", restartScript(t, layout)) // #nosec G204 -- the rendered script.
		command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "FAIL_SERVICE=" + fail}
		err := command.Run()
		logged, _ := os.ReadFile(log) // #nosec G304 -- a test file.
		return string(logged), err
	}
	compose := "compose -f " + filepath.Join(layout.RunDir, "compose.yaml")
	restart := func(service string) string {
		return compose + " restart " + service + "\n" + compose + " up -d --no-deps --no-recreate --wait " + service + "\n"
	}

	logged, err := run("postgres meshcore caddy\n", "")
	if err != nil || logged != restart("postgres")+restart("meshcore")+restart("caddy") {
		t.Fatalf("run = %q, %v", logged, err)
	}
	if _, err := os.Lstat(restartFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the restart file stays after every restart succeeded: %v", err)
	}
	if logged, err := run("postgres meshcore caddy", "meshcore"); err == nil ||
		strings.Contains(logged, "caddy") {
		t.Fatalf("a failed restart: %q, %v", logged, err)
	}
	if _, err := os.Lstat(restartFile); err != nil {
		t.Fatalf("the restart file goes after a failed restart: %v", err)
	}
	if logged, err := run("meshcore *", ""); err == nil || logged != "" {
		t.Fatalf("an unknown name: %q, %v", logged, err)
	}
}
