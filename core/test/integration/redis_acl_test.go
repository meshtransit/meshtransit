//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeaudit"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/ratelimit"
)

// The Redis user of each role (role isolation design §6, TD-SEC-90 S6) can
// do what that role's composition calls and is refused what belongs to
// another role. Needs a throwaway Redis (MESHTRANSIT_REDIS_DISPOSABLE=1)
// with an aclfile Redis writes, and its administrator:
// MESHTRANSIT_REDIS_ADMIN_USERNAME and MESHTRANSIT_REDIS_ADMIN_PASSWORD_FILE.
func TestRedisACLRoleUsers(t *testing.T) {
	adminUser, adminPasswordPath := os.Getenv("MESHTRANSIT_REDIS_ADMIN_USERNAME"),
		os.Getenv("MESHTRANSIT_REDIS_ADMIN_PASSWORD_FILE")
	// The test rotates the passwords of mesh_api, mesh_control, mesh_worker
	// and mesh_all: never against a Redis anything else uses. The project's
	// runners (MESHTRANSIT_INTEGRATION=1) always provide one, so a missing
	// setting there fails instead of passing by skipping.
	missing := adminUser == "" || adminPasswordPath == "" || os.Getenv("MESHTRANSIT_REDIS_DISPOSABLE") != "1"
	switch {
	case missing && os.Getenv("MESHTRANSIT_INTEGRATION") == "1":
		t.Fatal("needs MESHTRANSIT_REDIS_ADMIN_USERNAME, MESHTRANSIT_REDIS_ADMIN_PASSWORD_FILE and " +
			"MESHTRANSIT_REDIS_DISPOSABLE=1 (a throwaway Redis only)")
	case missing:
		t.Skip("needs a throwaway Redis and its administrator (see the comment)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	address := os.Getenv("MESHTRANSIT_REDIS_ADDRESS")
	caFile, err := config.NewTrustFile(os.Getenv("MESHTRANSIT_REDIS_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	adminPassword, err := config.NewSecretFile(adminPasswordPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	passwords := map[string][]byte{}
	passwordFiles := map[string]config.SecretFile{}
	for _, role := range redisadapter.ACLRoles {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		passwords[role] = []byte(hex.EncodeToString(raw))
		path := filepath.Join(dir, role)
		if err := os.WriteFile(path, append(passwords[role], '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if passwordFiles[role], err = config.NewSecretFile(path); err != nil {
			t.Fatal(err)
		}
	}
	admin := redisadapter.Options{Address: address, Username: adminUser, PasswordFile: adminPassword,
		CAFile: caFile, PoolSize: 1, RequestTimeout: 10 * time.Second}

	results, err := redisadapter.ApplyACL(ctx, redisadapter.ACLApplyOptions{Admin: admin, Passwords: passwords, Rotate: true})
	if err != nil || len(results) != len(redisadapter.ACLRoles) {
		t.Fatalf("ApplyACL() = %+v, %v", results, err)
	}
	again, err := redisadapter.ApplyACL(ctx, redisadapter.ACLApplyOptions{Admin: admin, Passwords: passwords})
	if err != nil {
		t.Fatalf("ApplyACL() again error = %v", err)
	}
	for _, result := range again {
		if result.Created || result.PasswordChanged {
			t.Fatalf("a second apply with the same passwords changed %+v", result)
		}
	}
	other := map[string][]byte{redisadapter.ACLRoleAPI: []byte(strings.Repeat("Q7", 20))}
	if _, err := redisadapter.ApplyACL(ctx, redisadapter.ACLApplyOptions{Admin: admin, Passwords: other}); !errors.Is(err, redisadapter.ErrACLPasswordDiffers) {
		t.Fatalf("ApplyACL() with another password error = %v, want ErrACLPasswordDiffers", err)
	}

	open := func(role string) *redisadapter.Client {
		t.Helper()
		client, err := redisadapter.Open(ctx, redisadapter.Options{Address: address, Username: "mesh_" + role,
			PasswordFile: passwordFiles[role], CAFile: caFile, PoolSize: 2, RequestTimeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("open %s: %v", role, err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Check(ctx); err != nil {
			t.Fatalf("%s Check() error = %v", role, err)
		}
		return client
	}
	api, control, worker, all := open(redisadapter.ACLRoleAPI), open(redisadapter.ACLRoleControl),
		open(redisadapter.ACLRoleWorker), open(redisadapter.ACLRoleAll)
	fixture := newRedisACLFixture(t)

	// control
	fixture.presence(ctx, t, control, true)
	fixture.gateway(ctx, t, control, true)
	key, err := mapsession.NewConnectivityKey(fixture.node, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.LoadConnectivity(ctx, []mapsession.ConnectivityKey{key}); err != nil {
		t.Fatalf("control LoadConnectivity() (EVALSHA_RO) error = %v", err)
	}
	fixture.delivery(ctx, t, control, true)
	if _, _, err := control.TakeKubernetesOperations(ctx, mustPublicID(t).String(), "acl-gateway", 1,
		kubeaudit.DefaultLimits); err != nil {
		t.Fatalf("control TakeKubernetesOperations() error = %v", err)
	}
	replica := "acl-" + mustPublicID(t).String()
	if _, err := control.PublishLoad(ctx, replica, 3, time.Minute); err != nil {
		t.Fatalf("control PublishLoad() error = %v", err)
	}
	if _, err := control.Loads(ctx); err != nil {
		t.Fatalf("control Loads() error = %v", err)
	}
	if err := control.WithdrawLoad(ctx, replica); err != nil {
		t.Fatalf("control WithdrawLoad() error = %v", err)
	}
	for name, publish := range map[string]func(context.Context) error{
		"PublishDeviceAliasClaimed": control.PublishDeviceAliasClaimed,
		"PublishKubeCertQueued":     control.PublishKubeCertQueued,
	} {
		if err := publish(ctx); err != nil {
			t.Fatalf("control %s() error = %v", name, err)
		}
	}
	closeAll(t, "control",
		subscribe(control.SubscribeNetworkRevisionAdvanced(ctx)),
		subscribe(control.SubscribeConnectivityChanged(ctx)),
		subscribe(control.SubscribeKubeCertSettled(ctx)))

	// api and worker read what control recorded.
	for role, client := range map[string]*redisadapter.Client{"api": api, "worker": worker, "all": all} {
		observations, err := client.LoadObservations(ctx, []node.ID{fixture.node})
		if err != nil || len(observations) != 1 {
			t.Fatalf("%s LoadObservations() = %d, %v", role, len(observations), err)
		}
	}

	// api
	fixture.rateLimit(ctx, t, api, true)
	if _, err := api.CountSiteRouters(ctx, "acl-site-"+mustPublicID(t).String(), time.Now()); err != nil {
		t.Fatalf("api CountSiteRouters() error = %v", err)
	}
	if _, err := api.CountExitNodes(ctx, "acl-pool-"+mustPublicID(t).String(), time.Now()); err != nil {
		t.Fatalf("api CountExitNodes() error = %v", err)
	}
	if _, err := api.LoadDNSZoneApplication(ctx, fixture.network, "acl.example", time.Now(), nil); err != nil {
		t.Fatalf("api LoadDNSZoneApplication() error = %v", err)
	}
	if _, err := api.CountResolverHealth(ctx, fixture.network,
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}, time.Now()); err != nil {
		t.Fatalf("api CountResolverHealth() error = %v", err)
	}

	// worker
	fixture.marks(ctx, t, worker, true)
	if err := worker.PublishNetworkRevisionAdvanced(ctx, fixture.revision); err != nil {
		t.Fatalf("worker PublishNetworkRevisionAdvanced() error = %v", err)
	}
	if err := worker.PublishKubeCertSettled(ctx, mustPublicID(t)); err != nil {
		t.Fatalf("worker PublishKubeCertSettled() error = %v", err)
	}
	closeAll(t, "worker",
		subscribe(worker.SubscribeNetworkRevisionAdvanced(ctx)),
		subscribe(worker.SubscribeDeviceAliasClaimed(ctx)),
		subscribe(worker.SubscribeKubeCertQueued(ctx)),
		subscribe(worker.SubscribeSiteHealthFailed(ctx)))

	// Each role is refused what another role does.
	fixture.presence(ctx, t, api, false)
	fixture.presence(ctx, t, worker, false)
	fixture.gateway(ctx, t, api, false)
	fixture.gateway(ctx, t, worker, false)
	fixture.delivery(ctx, t, api, false)
	fixture.delivery(ctx, t, worker, false)
	fixture.marks(ctx, t, api, false)
	fixture.marks(ctx, t, control, false)
	fixture.rateLimit(ctx, t, control, false)
	fixture.rateLimit(ctx, t, worker, false)
	if err := api.PublishNetworkRevisionAdvanced(ctx, fixture.revision); !refused(err) {
		t.Errorf("api PublishNetworkRevisionAdvanced() error = %v, want a refusal", err)
	}
	if _, err := api.SubscribeConnectivityChanged(ctx); !refused(err) {
		t.Errorf("api SubscribeConnectivityChanged() error = %v, want a refusal", err)
	}
	if _, _, err := worker.TakeKubernetesOperations(ctx, mustPublicID(t).String(), "acl-gateway", 1,
		kubeaudit.DefaultLimits); !refused(err) {
		t.Errorf("worker TakeKubernetesOperations() error = %v, want a refusal", err)
	}
	if _, err := control.LoadObservations(ctx, []node.ID{fixture.node}); !refused(err) {
		t.Errorf("control LoadObservations() error = %v, want a refusal", err)
	}

	// The role that runs everything can do all of it.
	fixture.presence(ctx, t, all, true)
	fixture.rateLimit(ctx, t, all, true)
	fixture.marks(ctx, t, all, true)
}

// refused reports an ACL refusal: of the command itself (NOPERM), or of a
// command a script it was allowed to start runs.
func refused(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "NOPERM") || strings.Contains(err.Error(), "ACL failure in script"))
}

type closer interface{ Close() error }

func subscribe[S closer](subscription S, err error) func(*testing.T, string) {
	return func(t *testing.T, role string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s subscribe error = %v", role, err)
		}
		if err := subscription.Close(); err != nil {
			t.Errorf("%s subscription Close() error = %v", role, err)
		}
	}
}

func closeAll(t *testing.T, role string, checks ...func(*testing.T, string)) {
	t.Helper()
	for _, check := range checks {
		check(t, role)
	}
}

// redisACLFixture holds fresh identifiers, so the test never meets state
// another test left.
type redisACLFixture struct {
	node     node.ID
	nodeKey  node.Key
	machine  [32]byte
	network  network.ID
	revision network.RevisionAdvanced
	install  deployment.ID
	subject  ratelimit.Subject
	policy   ratelimit.Policy
}

func newRedisACLFixture(t *testing.T) redisACLFixture {
	t.Helper()
	var fixture redisACLFixture
	var err error
	if fixture.node, err = node.NewID(mustPublicID(t).Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(fixture.nodeKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(fixture.machine[:]); err != nil {
		t.Fatal(err)
	}
	networkID := mustPublicID(t).String()
	if fixture.network, err = network.ParseID(networkID); err != nil {
		t.Fatal(err)
	}
	if fixture.revision, err = network.NewRevisionAdvanced(networkID, 7); err != nil {
		t.Fatal(err)
	}
	if fixture.install, err = deployment.ParseID(mustPublicID(t).String()); err != nil {
		t.Fatal(err)
	}
	keyID, err := ratelimit.NewDigestKeyID("integration-acl-v1")
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	digester, err := ratelimit.NewDigester(keyID, material)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.subject, err = digester.Subject(ratelimit.SubjectSource, "192.0.2.77"); err != nil {
		t.Fatal(err)
	}
	if fixture.policy, err = ratelimit.NewPolicy(100, time.Minute); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture redisACLFixture) presence(ctx context.Context, t *testing.T, client *redisadapter.Client, allowed bool) {
	t.Helper()
	lease := integrationPresenceLease(t, fixture.node, time.Now().UnixNano(), "acl-replica")
	_, err := client.AcquirePresence(ctx, redisIntegrationScope(t), lease)
	if allowed && err != nil || !allowed && !refused(err) {
		t.Errorf("AcquirePresence() error = %v, allowed %v", err, allowed)
		return
	}
	if allowed {
		if _, err := client.RenewPresence(ctx, lease); err != nil {
			t.Errorf("RenewPresence() error = %v", err)
		}
		if _, err := client.ReleasePresence(ctx, redisIntegrationScope(t), lease); err != nil {
			t.Errorf("ReleasePresence() error = %v", err)
		}
	}
}

// gateway claims a gateway stream's presence, checks rotation (a read-only
// script) and releases it; refused roles fail at the check.
func (fixture redisACLFixture) gateway(ctx context.Context, t *testing.T, client *redisadapter.Client, allowed bool) {
	t.Helper()
	lease := gatewayPresenceLease(t, fixture.node, time.Now().UnixNano(), "acl-gateway", fixture.machine)
	if allowed {
		if _, err := client.AcquireGatewayPresence(ctx, redisIntegrationScope(t), lease, time.Minute); err != nil {
			t.Errorf("AcquireGatewayPresence() error = %v", err)
			return
		}
	}
	_, err := client.CheckGatewayRotation(ctx, lease)
	if allowed && err != nil || !allowed && !refused(err) {
		t.Errorf("CheckGatewayRotation() error = %v, allowed %v", err, allowed)
		return
	}
	if allowed {
		if _, err := client.ReleaseGatewayPresence(ctx, redisIntegrationScope(t), lease); err != nil {
			t.Errorf("ReleaseGatewayPresence() error = %v", err)
		}
	}
}

func (fixture redisACLFixture) delivery(ctx context.Context, t *testing.T, client *redisadapter.Client, allowed bool) {
	t.Helper()
	err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: fixture.node, NodeKey: fixture.nodeKey,
		MachineFingerprint: fixture.machine, SessionGeneration: time.Now().UnixNano(), NetworkRevision: 3,
		PolicyRevision: 2, DeliveredAt: time.Now().UTC().Truncate(time.Millisecond)})
	if allowed && err != nil || !allowed && !refused(err) {
		t.Errorf("RecordDelivery() error = %v, allowed %v", err, allowed)
	}
}

func (fixture redisACLFixture) marks(ctx context.Context, t *testing.T, client *redisadapter.Client, allowed bool) {
	t.Helper()
	now := time.Now()
	_, err := client.Compare(ctx, fixture.install, kubeca.Guard{Generation: 1, CertificateMark: 1, CAMark: 1,
		ReadStarted: now, ReadFinished: now.Add(time.Millisecond)})
	if allowed && err != nil || !allowed && !refused(err) {
		t.Errorf("Compare() error = %v, allowed %v", err, allowed)
	}
}

func (fixture redisACLFixture) rateLimit(ctx context.Context, t *testing.T, client *redisadapter.Client, allowed bool) {
	t.Helper()
	_, err := client.Allow(ctx, fixture.subject, fixture.policy)
	if allowed && err != nil || !allowed && !refused(err) {
		t.Errorf("Allow() error = %v, allowed %v", err, allowed)
		return
	}
	if allowed {
		if err := client.Refund(ctx, fixture.subject, fixture.policy); err != nil {
			t.Errorf("Refund() error = %v", err)
		}
	}
}
