package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/secretstore"
	"meshtransit.net/client/internal/version"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/kubejoin"
)

// fakeGateway is a gateway's control client: Core takes the machine keys in
// current (by public key) with the node key text each holds, and answers
// rotations with rotateErr.
type fakeGateway struct {
	*fakeControl
	mu        sync.Mutex
	current   map[key.MachinePublic]string
	retired   map[key.MachinePublic]bool
	probes    []string // machine:node texts probed, in order
	rotateErr error
	rotated   []key.MachinePublic
	podTokens []string // pod tokens the machine key rotations carried
}

func machinePublic(t *testing.T, text []byte) key.MachinePublic {
	t.Helper()
	raw, err := controlplane.ParsePrivateKey(text)
	if err != nil {
		t.Fatal(err)
	}
	private, err := key.MachinePrivateFromBytes(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return private.Public()
}

func mustMachinePublic(text []byte) key.MachinePublic {
	raw, err := controlplane.ParsePrivateKey(text)
	if err != nil {
		return key.MachinePublic{}
	}
	private, err := key.MachinePrivateFromBytes(raw[:])
	if err != nil {
		return key.MachinePublic{}
	}
	return private.Public()
}

func (gateway *fakeGateway) ProbeGateway(_ context.Context, _ string, material controlplane.KeyMaterial,
	_ string,
) error {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	machine, node := mustMachinePublic(material.MachinePrivateKey), string(material.NodePrivateKey)
	gateway.probes = append(gateway.probes, string(material.MachinePrivateKey)+":"+node)
	switch held, bound := gateway.current[machine]; {
	case gateway.retired[machine]:
		return controlplane.ErrMachineKeyRetired
	case !bound:
		return controlplane.ErrMachineKeyUnbound
	case held != node:
		return controlplane.ErrNodeKeyNotCurrent
	}
	return nil
}

func (gateway *fakeGateway) RotateMachineKey(_ context.Context, _ string, material controlplane.KeyMaterial,
	_ string, next key.MachinePrivate, podToken controlplane.PodToken,
) error {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	gateway.rotated = append(gateway.rotated, next.Public())
	gateway.podTokens = append(gateway.podTokens, podToken.Reveal())
	if gateway.rotateErr != nil {
		return gateway.rotateErr
	}
	former := mustMachinePublic(material.MachinePrivateKey)
	node := gateway.current[former]
	delete(gateway.current, former)
	gateway.retired[former] = true
	gateway.current[next.Public()] = node
	return nil
}

func newGatewayService(t *testing.T) (*Service, *identity.Store, *fakeGateway, string, *time.Time) {
	t.Helper()
	stateDir := t.TempDir()
	profiles, err := profile.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = profiles.Close() })
	created, err := profiles.Create(t.Context(), profile.CreateInput{
		Name:       "meshgw",
		ControlURL: "https://control.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	protector, err := secretstore.New(bytes.Repeat([]byte{0x52}, secretstore.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.Open(stateDir, protector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identities.Close() })
	now := time.Date(2026, time.October, 25, 12, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{
		fakeControl: &fakeControl{
			streamPublished:   make(chan struct{}, 1),
			endpointPublished: make(chan struct{}, 1), streamStarted: make(chan struct{}, 4),
		},
		current: map[key.MachinePublic]string{}, retired: map[key.MachinePublic]bool{},
	}
	gateway.rotateFunc = func(_ context.Context, newNode []byte) (controlplane.RegistrationResult, error) {
		gateway.fakeControl.mu.Lock()
		material := gateway.rotationMaterials[len(gateway.rotationMaterials)-1]
		gateway.fakeControl.mu.Unlock()
		gateway.mu.Lock()
		defer gateway.mu.Unlock()
		gateway.current[mustMachinePublic(material.MachinePrivateKey)] = string(newNode)
		return controlplane.RegistrationResult{
			State:             controlplane.RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, nil
	}
	service, err := New(profiles, identities, version.Info{Version: "test"}, gateway,
		Options{Hostname: "prod-0", Clock: func() time.Time { return now }, Gateway: true})
	if err != nil {
		t.Fatal(err)
	}
	service.gatewayCommitWait = 10 * time.Millisecond
	machine, _ := controlplane.GenerateNodePrivateKey()
	node, _ := controlplane.GenerateNodePrivateKey()
	record, err := identity.NewRecord(created.ID, identity.Material{
		MachinePrivateKey: machine,
		NodePrivateKey:    node, ControlPublicKey: []byte("control-public"),
	}, testFingerprint, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identities.Create(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	return service, identities, gateway, created.ID, &now
}

func TestJoinClusterPrintsTheCodeThenJoins(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, _ := newGatewayService(t)
	nonce := [32]byte{9, 9}
	clusterID := [16]byte{0x01, 0x89, 0x0f, 0x90, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xc1}
	expires := time.Now().Add(time.Hour)
	gateway.registrationResults = []controlplane.RegistrationResult{
		{State: controlplane.RegistrationStateAdminApprovalRequired, Approval: &controlplane.AdminApproval{
			ClusterID: clusterID, RequestID: "request-1", RequestNonce: nonce, ExpiresAt: expires,
		}},
		{State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true},
	}
	waiting, err := service.JoinCluster(t.Context(), "mtk1.secret", map[string]string{"pod": "meshgw-0"}, time.Minute, testPodIdentity(t))
	if err != nil || waiting.State != ClusterJoinWaiting || waiting.RequestID != "request-1" ||
		!waiting.ExpiresAt.Equal(expires) {
		t.Fatalf("JoinCluster() = %+v, %v", waiting, err)
	}
	record, _ := identities.Get(t.Context(), profileID)
	machine, node, err := publicKeys(toProtocolMaterial(record.Material()))
	if err != nil {
		t.Fatal(err)
	}
	// The code v2 binds the trust the replica sent: its token's names.
	digest, err := podTrustDigest(testPodIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := kubejoin.ComputeV2(kubejoin.Inputs{
		MachineKey: machine, NodeKey: node, ClusterID: clusterID,
		RequestNonce: nonce,
	}, digest)
	if waiting.Code != want.String() {
		t.Fatalf("code %q, want %q", waiting.Code, want.String())
	}
	options := gateway.registerOptions[0]
	if options.ClusterJoin == nil || options.ClusterJoin.JoinKey != "mtk1.secret" || options.JoinWait != time.Minute ||
		options.ClusterJoin.PodToken != testPodIdentity(t).Token || options.ClusterJoin.Issuer == "" ||
		len(options.ClusterJoin.JWKS) == 0 {
		t.Fatalf("register options %+v", options)
	}
	joined, err := service.JoinCluster(t.Context(), "mtk1.secret", nil, time.Minute, testPodIdentity(t))
	if err != nil || joined.State != ClusterJoinJoined {
		t.Fatalf("second JoinCluster() = %+v, %v", joined, err)
	}
	record, _ = identities.Get(t.Context(), profileID)
	if !record.IsRegistered() || !record.IsGateway() {
		t.Fatalf("record %v", record)
	}
	if _, err := service.Logout(t.Context()); !errors.Is(err, ErrGatewayLogout) {
		t.Fatalf("a gateway logged out: %v", err)
	}
}

// The authorized answer was lost: asking again meets the gateway gate, and
// a proven session confirms the Device.
func TestJoinClusterAfterALostAnswer(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, _ := newGatewayService(t)
	record, _ := identities.Get(t.Context(), profileID)
	material := record.Material()
	gateway.current[machinePublic(t, material.MachinePrivateKey)] = string(material.NodePrivateKey)
	gateway.registerFunc = func(context.Context, controlplane.RegisterOptions) (controlplane.RegistrationResult, error) {
		return controlplane.RegistrationResult{}, controlplane.ErrGatewayProofRequired
	}
	joined, err := service.JoinCluster(t.Context(), "mtk1.secret", nil, time.Minute, testPodIdentity(t))
	if err != nil || joined.State != ClusterJoinJoined {
		t.Fatalf("JoinCluster() = %+v, %v", joined, err)
	}
	if record, _ := identities.Get(t.Context(), profileID); !record.IsGateway() {
		t.Fatal("the gateway was not recorded")
	}
}

func joinedGateway(t *testing.T) (*Service, *identity.Store, *fakeGateway, string, *time.Time) {
	t.Helper()
	service, identities, gateway, profileID, now := newGatewayService(t)
	if _, err := identities.CompleteClusterJoin(t.Context(), profileID); err != nil {
		t.Fatal(err)
	}
	record, _ := identities.Get(t.Context(), profileID)
	material := record.Material()
	gateway.current[machinePublic(t, material.MachinePrivateKey)] = string(material.NodePrivateKey)
	return service, identities, gateway, profileID, now
}

// At a start the gateway moves to a new machine key and a new node key;
// within two minutes it does not move again.
func TestPrepareGatewayKeysRotates(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, now := joinedGateway(t)
	before, _ := identities.Get(t.Context(), profileID)
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
	after, _ := identities.Get(t.Context(), profileID)
	if string(after.Material().MachinePrivateKey) == string(before.Material().MachinePrivateKey) ||
		len(after.PendingMachinePrivateKeys()) != 0 || !after.LastKeyRotationAt().Equal(*now) {
		t.Fatal("the machine key did not move")
	}
	if len(gateway.rotationKeys) != 1 {
		t.Fatalf("node key rotations %d", len(gateway.rotationKeys))
	}
	*now = now.Add(time.Minute)
	gateway.current[machinePublic(t, after.Material().MachinePrivateKey)] = string(after.Material().NodePrivateKey)
	if err := service.PrepareGatewayKeys(t.Context()); err != nil || len(gateway.rotated) != 1 {
		t.Fatalf("a second start within two minutes rotated: %v, %d", err, len(gateway.rotated))
	}
}

// A pod that died during a rotation finds its staged machine key first.
func TestPrepareGatewayKeysFindsTheStagedKey(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, now := joinedGateway(t)
	staged, _ := controlplane.GenerateNodePrivateKey()
	if _, err := identities.StageMachineKeyRotation(t.Context(), profileID, staged, *now); err != nil {
		t.Fatal(err)
	}
	record, _ := identities.Get(t.Context(), profileID)
	material := record.Material()
	// Core committed the rotation before the pod died.
	gateway.current[machinePublic(t, staged)] = string(material.NodePrivateKey)
	delete(gateway.current, machinePublic(t, material.MachinePrivateKey))
	gateway.retired[machinePublic(t, material.MachinePrivateKey)] = true
	*now = now.Add(30 * time.Second) // within two minutes: no new rotation
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
	after, _ := identities.Get(t.Context(), profileID)
	if string(after.Material().MachinePrivateKey) != string(staged) || len(after.PendingMachinePrivateKeys()) != 0 {
		t.Fatal("the staged machine key was not adopted")
	}
	if gateway.probes[0] != string(staged)+":"+string(material.NodePrivateKey) {
		t.Fatalf("probed %v first", gateway.probes[0])
	}
}

// A staged node key Core took is adopted; a refused machine rotation drops
// its key and the gateway goes on.
func TestPrepareGatewayKeysNodeKeyAndRefusal(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, _ := joinedGateway(t)
	pendingNode, _ := controlplane.GenerateNodePrivateKey()
	if _, err := identities.BeginNodeKeyRotation(t.Context(), profileID, pendingNode); err != nil {
		t.Fatal(err)
	}
	record, _ := identities.Get(t.Context(), profileID)
	gateway.current[machinePublic(t, record.Material().MachinePrivateKey)] = string(pendingNode)
	gateway.rotateErr = controlplane.ErrMachineKeyRotationRefused
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
	after, _ := identities.Get(t.Context(), profileID)
	if string(after.Material().NodePrivateKey) != string(pendingNode) || after.HasPendingNodeKeyRotation() ||
		len(after.PendingMachinePrivateKeys()) != 0 ||
		string(after.Material().MachinePrivateKey) != string(record.Material().MachinePrivateKey) {
		t.Fatal("the staged node key was not adopted, or the refused machine key kept")
	}
}

// No key works, twice: an administrator must act.
func TestPrepareGatewayKeysLost(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, _ := joinedGateway(t)
	record, _ := identities.Get(t.Context(), profileID)
	gateway.retired[machinePublic(t, record.Material().MachinePrivateKey)] = true
	if err := service.PrepareGatewayKeys(t.Context()); !errors.Is(err, ErrGatewayKeysLost) {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
}

// A staged machine key that never committed is dropped once Core's commit
// bound passed, so staged keys never pile up.
func TestPrepareGatewayKeysDropsDeadStagedKeys(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, now := joinedGateway(t)
	for range 2 {
		dead, _ := controlplane.GenerateNodePrivateKey()
		if _, err := identities.StageMachineKeyRotation(t.Context(), profileID, dead, *now); err != nil {
			t.Fatal(err)
		}
	}
	// Within two minutes a late commit may still land: they stay.
	*now = now.Add(time.Minute)
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
	if record, _ := identities.Get(t.Context(), profileID); record.PendingMachineKeyCount() != 2 ||
		len(gateway.rotated) != 0 {
		t.Fatalf("within two minutes: %d staged, %d rotations", record.PendingMachineKeyCount(), len(gateway.rotated))
	}
	*now = now.Add(2 * time.Minute)
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
	if record, _ := identities.Get(t.Context(), profileID); record.PendingMachineKeyCount() != 0 ||
		len(gateway.rotated) != 1 {
		t.Fatalf("after two minutes: %d staged, %d rotations", record.PendingMachineKeyCount(), len(gateway.rotated))
	}
}

// When Core no longer takes its keys, a gateway's Run ends for meshgw to
// restart; a daemon on the other kind's state refuses to run.
func TestGatewayRunStops(t *testing.T) {
	t.Parallel()
	service, _, gateway, _, _ := joinedGateway(t)
	gateway.fakeControl.mu.Lock()
	gateway.streamError = controlplane.ErrMachineKeyRetired
	gateway.fakeControl.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := service.Run(ctx); !errors.Is(err, ErrGatewayStopped) ||
		!errors.Is(err, controlplane.ErrMachineKeyRetired) {
		t.Fatalf("Run() = %v", err)
	}

	ordinary, identities, _, profileID, _ := newTestService(t)
	_ = ordinary
	record, err := identity.NewRecord(profileID, identity.Material{
		MachinePrivateKey: []byte("machine-private"),
		NodePrivateKey:    []byte("privkey:" + strings.Repeat("01", 32)), ControlPublicKey: []byte("control-public"),
	},
		testFingerprint, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := identities.Create(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := identities.CompleteClusterJoin(t.Context(), profileID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := ordinary.Run(ctx); !errors.Is(err, ErrGatewayModeMismatch) {
		t.Fatalf("meshd on a gateway's state: Run() = %v", err)
	}
}

// A pod that died right after sending a rotation restarts before Core's
// commit landed: the staged key is kept, and adopted once it committed.
func TestPrepareGatewayKeysLateCommit(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, now := joinedGateway(t)
	staged, _ := controlplane.GenerateNodePrivateKey()
	if _, err := identities.StageMachineKeyRotation(t.Context(), profileID, staged, *now); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Second)
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
	record, _ := identities.Get(t.Context(), profileID)
	if record.PendingMachineKeyCount() != 1 {
		t.Fatal("a staged key Core may still commit was dropped")
	}
	// Core's commit lands.
	former := machinePublic(t, record.Material().MachinePrivateKey)
	gateway.current[machinePublic(t, staged)] = gateway.current[former]
	delete(gateway.current, former)
	gateway.retired[former] = true
	*now = now.Add(5 * time.Second)
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() after the commit = %v", err)
	}
	if record, _ := identities.Get(t.Context(), profileID); string(record.Material().MachinePrivateKey) != string(staged) {
		t.Fatal("the committed staged key was not adopted")
	}
}

// An ordinary daemon refuses gateway calls.
func TestOrdinaryDaemonHasNoGatewayCalls(t *testing.T) {
	t.Parallel()
	service, _, _, _, _ := newTestService(t)
	if _, err := service.JoinCluster(t.Context(), "mtk1.secret", nil, time.Minute, testPodIdentity(t)); !errors.Is(err, ErrNotGateway) {
		t.Fatalf("JoinCluster() = %v", err)
	}
	if err := service.PrepareGatewayKeys(t.Context()); !errors.Is(err, ErrNotGateway) {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
}

// testPodIdentity is a pod's identity as meshgw reads it: a token whose
// payload names the pod (the replica never verifies it), and the cluster's
// issuer and keys.
func testPodIdentity(t *testing.T) PodIdentity {
	t.Helper()
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"kubernetes.io":{"namespace":"mt-kube-k1",` +
		`"pod":{"name":"meshgw-0","uid":"u"},"serviceaccount":{"name":"meshgw","uid":"s"}}}`))
	return PodIdentity{
		Token:  controlplane.PodToken("eyJhbGciOiJFUzI1NiJ9." + payload + ".c2ln"),
		Issuer: "https://kubernetes.default.svc.cluster.local",
		JWKS: []byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k1",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`),
	}
}

// Keys that hold a request with other signing material: the replica gets
// its own code for that request, to print (K1.1 design §6.3).
func TestJoinClusterConflictGivesTheReplicasCode(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, _ := newGatewayService(t)
	nonce := [32]byte{7, 7}
	clusterID := [16]byte{0x01, 0x89, 0x0f, 0x90, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xc1}
	gateway.registerFunc = func(context.Context, controlplane.RegisterOptions) (controlplane.RegistrationResult, error) {
		return controlplane.RegistrationResult{}, &controlplane.RejectedError{
			Code: "conflict", Message: "other trust",
			Approval: &controlplane.AdminApproval{ClusterID: clusterID, RequestID: "request-9", RequestNonce: nonce},
		}
	}
	conflict, err := service.JoinCluster(t.Context(), "mtk1.secret", nil, time.Minute, testPodIdentity(t))
	if err != nil || conflict.State != ClusterJoinConflict || conflict.RequestID != "request-9" {
		t.Fatalf("JoinCluster() = %+v, %v", conflict, err)
	}
	record, _ := identities.Get(t.Context(), profileID)
	machine, node, err := publicKeys(toProtocolMaterial(record.Material()))
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := podTrustDigest(testPodIdentity(t))
	want, _ := kubejoin.ComputeV2(kubejoin.Inputs{
		MachineKey: machine, NodeKey: node, ClusterID: clusterID,
		RequestNonce: nonce,
	}, digest)
	if conflict.Code != want.String() {
		t.Fatalf("code %q, want %q", conflict.Code, want.String())
	}
}

// A join without a readable pod identity asks nothing.
func TestJoinClusterNeedsThePodIdentity(t *testing.T) {
	t.Parallel()
	service, _, gateway, _, _ := newGatewayService(t)
	gateway.registrationResults = []controlplane.RegistrationResult{{
		State: controlplane.RegistrationStateAdminApprovalRequired, Approval: &controlplane.AdminApproval{
			ClusterID: [16]byte{1}, RequestID: "request-1", RequestNonce: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour),
		},
	}}
	pod := testPodIdentity(t)
	pod.JWKS = []byte(`{}`)
	if _, err := service.JoinCluster(t.Context(), "mtk1.secret", nil, time.Minute, pod); err == nil {
		t.Fatal("a join with keys that are not a JWKS printed a code")
	}
}

// Both rotations carry the pod token, read from its file each time (K1.1).
func TestPrepareGatewayKeysCarriesThePodToken(t *testing.T) {
	t.Parallel()
	service, identities, gateway, profileID, now := joinedGateway(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-token-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service.gatewayTokenFile = tokenFile
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("PrepareGatewayKeys() = %v", err)
	}
	// Kubelet replaced the token: the next start reads the new one.
	if err := os.WriteFile(tokenFile, []byte("pod-token-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(3 * time.Minute)
	record, _ := identities.Get(t.Context(), profileID)
	gateway.current[machinePublic(t, record.Material().MachinePrivateKey)] = string(record.Material().NodePrivateKey)
	if err := service.PrepareGatewayKeys(t.Context()); err != nil {
		t.Fatalf("second PrepareGatewayKeys() = %v", err)
	}
	gateway.fakeControl.mu.Lock()
	nodeTokens := slices.Clone(gateway.rotationTokens)
	gateway.fakeControl.mu.Unlock()
	if !slices.Equal(gateway.podTokens, []string{"pod-token-1", "pod-token-2"}) ||
		!slices.Equal(nodeTokens, []string{"pod-token-1", "pod-token-2"}) {
		t.Fatalf("machine key tokens %v, node key tokens %v", gateway.podTokens, nodeTokens)
	}
}

// A pod token file that is empty or too large is never sent.
func TestReadPodTokenRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, content := range map[string]string{"empty": " \n", "too large": strings.Repeat("a", MaxPodTokenSize+1)} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPodToken(path); err == nil {
			t.Errorf("%s: ReadPodToken() accepted it", name)
		}
	}
	if _, err := ReadPodToken(filepath.Join(dir, "missing")); err == nil {
		t.Error("ReadPodToken() accepted a missing file")
	}
}
