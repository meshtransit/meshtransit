package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/kubejoin"
)

// A Kubernetes gateway replica (mtcp-v1 §6.6–6.8) joins its cluster with a
// join key and an administrator's approval, then proves its node key on
// every session and moves to new keys at every start. Only meshgw sets
// Options.Gateway; meshd never runs this.

const (
	// gatewayRotationInterval: a gateway that started within it does not
	// rotate again.
	gatewayRotationInterval = 2 * time.Minute
	// gatewayCommitBound outlasts Core's detached commit of a machine key
	// rotation: a probe that found no key is repeated after it, as the
	// rotation may have been committing meanwhile.
	gatewayCommitBound = 15 * time.Second
)

var (
	// ErrGatewayKeysLost means Core takes none of the gateway's machine and
	// node keys: an administrator must remove the Device.
	ErrGatewayKeysLost = errors.New("daemon: Core takes none of the gateway's keys")
	// ErrGatewayStopped ends Run for a gateway whose keys Core no longer
	// takes or whose Device was removed; meshgw exits and restarts.
	ErrGatewayStopped = errors.New("daemon: the gateway's control session cannot go on")
	// ErrNotGateway means a gateway call reached a daemon or profile that
	// is not a gateway's.
	ErrNotGateway = errors.New("daemon: not a Kubernetes gateway")
	// ErrGatewayLogout: an administrator removes a gateway; it never logs
	// out (mtcp-v1 §6.5).
	ErrGatewayLogout = errors.New("daemon: a Kubernetes gateway does not log out")
	// ErrGatewayModeMismatch: the daemon runs as a gateway on an ordinary
	// Device's state, or the other way round.
	ErrGatewayModeMismatch = errors.New("daemon: the state belongs to another kind of Device")
)

// gatewayProber is what a gateway's control client adds (mtcpclient.NewGateway).
type gatewayProber interface {
	ProbeGateway(context.Context, string, controlplane.KeyMaterial, string) error
	RotateMachineKey(context.Context, string, controlplane.KeyMaterial, string, key.MachinePrivate,
		controlplane.PodToken) error
}

// ClusterJoinState is where a gateway's cluster join stands.
type ClusterJoinState string

// Cluster join states.
const (
	ClusterJoinWaiting ClusterJoinState = "waiting"
	ClusterJoinJoined  ClusterJoinState = "joined"
	// ClusterJoinConflict: the keys hold a request with other signing
	// material; Code is this replica's own code for it, which differs from
	// the request's, so an administrator rejects it (K1.1).
	ClusterJoinConflict ClusterJoinState = "conflict"
)

// PodIdentity is what a K1 gateway replica proves itself with (K1.1): its
// pod's ServiceAccount token, and its cluster's issuer and keys as the API
// server serves them.
type PodIdentity struct {
	Token  controlplane.PodToken
	Issuer string
	JWKS   []byte
}

// ClusterJoin is a cluster join's answer: while it waits, the code an
// administrator types and until when this request waits.
type ClusterJoin struct {
	State     ClusterJoinState
	Code      string
	RequestID string
	ExpiresAt time.Time
}

// JoinCluster asks to join the cluster with joinKey, or asks again with the
// same keys; it waits up to wait on the session for the approval. The key
// is used for this request only, never stored.
func (s *Service) JoinCluster(ctx context.Context, joinKey string, reported map[string]string,
	wait time.Duration, pod PodIdentity,
) (ClusterJoin, error) {
	gateway, err := s.gatewayClient()
	if err != nil {
		return ClusterJoin{}, err
	}
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return ClusterJoin{}, err
	}
	defer release()
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return ClusterJoin{}, err
	}
	record, err := s.identities.Get(ctx, active.ID)
	if errors.Is(err, identity.ErrNotFound) {
		return ClusterJoin{}, ErrControlNotTrusted
	}
	if err != nil {
		return ClusterJoin{}, fmt.Errorf("reading identity: %w", err)
	}
	if record.IsRegistered() {
		if !record.IsGateway() {
			return ClusterJoin{}, fmt.Errorf("%w: the profile holds an ordinary Device", ErrGatewayModeMismatch)
		}
		return ClusterJoin{State: ClusterJoinJoined}, nil
	}
	identityMaterial := record.Material()
	material := toProtocolMaterial(identityMaterial)
	clearIdentityMaterial(identityMaterial)
	defer clearProtocolMaterial(material)
	result, err := s.prober.Register(ctx, active.ControlURL, material, controlplane.RegisterOptions{
		Hostname: s.hostname, Version: s.product() + "/" + s.build.Version,
		PinnedFingerprint: record.ControlKeyFingerprint(),
		ClusterJoin: &controlplane.ClusterJoin{
			JoinKey: joinKey, Reported: reported, PodToken: pod.Token,
			Issuer: pod.Issuer, JWKS: pod.JWKS,
		},
		JoinWait: wait,
	})
	if errors.Is(err, controlplane.ErrGatewayProofRequired) {
		// The join completed but its answer was lost: the keys now are a
		// gateway's, which a proven session confirms (mtcp-v1 §6.6).
		err = gateway.ProbeGateway(ctx, active.ControlURL, material, record.ControlKeyFingerprint())
		if err == nil {
			result.State = controlplane.RegistrationStateAuthorized
		}
	}
	if rejected, ok := errors.AsType[*controlplane.RejectedError](err); ok && rejected.Approval != nil {
		code, codeErr := joinCode(material, rejected.Approval, pod)
		if codeErr != nil {
			return ClusterJoin{}, codeErr
		}
		return ClusterJoin{State: ClusterJoinConflict, Code: code, RequestID: rejected.Approval.RequestID}, nil
	}
	if err != nil {
		return ClusterJoin{}, err
	}
	switch result.State {
	case controlplane.RegistrationStateAuthorized:
		if err := s.markGatewayJoined(ctx, active.ID); err != nil {
			return ClusterJoin{}, err
		}
		s.signalControlSync()
		return ClusterJoin{State: ClusterJoinJoined}, nil
	case controlplane.RegistrationStateAdminApprovalRequired:
		code, err := joinCode(material, result.Approval, pod)
		if err != nil {
			return ClusterJoin{}, err
		}
		return ClusterJoin{
			State: ClusterJoinWaiting, Code: code, RequestID: result.Approval.RequestID,
			ExpiresAt: result.Approval.ExpiresAt,
		}, nil
	default:
		return ClusterJoin{}, fmt.Errorf("%w: unexpected registration state", controlplane.ErrRegistration)
	}
}

// markGatewayJoined records the Device, durably and in one write, before
// anything else uses it.
func (s *Service) markGatewayJoined(ctx context.Context, profileID string) error {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rotationPersistTimeout)
	defer cancel()
	if _, err := s.identities.CompleteClusterJoin(persistCtx, profileID); err != nil {
		return fmt.Errorf("recording the joined gateway: %w", err)
	}
	return nil
}

// joinCode is the code an administrator types: the code v2 binds this
// replica's own keys, what Core chose, and the signing material it sent
// (shared/kubejoin): the names in its own token, never what Core answers.
func joinCode(material controlplane.KeyMaterial, approval *controlplane.AdminApproval, pod PodIdentity) (string,
	error,
) {
	if approval == nil {
		return "", fmt.Errorf("%w: no admin approval", controlplane.ErrRegistration)
	}
	digest, err := podTrustDigest(pod)
	if err != nil {
		return "", fmt.Errorf("%w: %w", controlplane.ErrRegistration, err)
	}
	machine, node, err := publicKeys(material)
	if err != nil {
		return "", err
	}
	code, err := kubejoin.ComputeV2(kubejoin.Inputs{
		MachineKey: machine, NodeKey: node,
		ClusterID: approval.ClusterID, RequestNonce: approval.RequestNonce,
	}, digest)
	if err != nil {
		return "", fmt.Errorf("%w: %w", controlplane.ErrRegistration, err)
	}
	return code.String(), nil
}

func publicKeys(material controlplane.KeyMaterial) ([32]byte, [32]byte, error) {
	machineRaw, err := controlplane.ParsePrivateKey(material.MachinePrivateKey)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	defer clear(machineRaw[:])
	nodeRaw, err := controlplane.ParsePrivateKey(material.NodePrivateKey)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	defer clear(nodeRaw[:])
	machine, err := key.MachinePrivateFromBytes(machineRaw[:])
	if err != nil {
		return [32]byte{}, [32]byte{}, controlplane.ErrInvalidMaterial
	}
	node, err := key.NodePrivateFromBytes(nodeRaw[:])
	if err != nil {
		return [32]byte{}, [32]byte{}, controlplane.ErrInvalidMaterial
	}
	return [32]byte(machine.Public()), [32]byte(node.Public()), nil
}

// PrepareGatewayKeys runs at every start of a joined gateway, and must end
// before Run starts the map stream: its sessions would otherwise push the
// stream's out, contesting the keys (mtcp-v1 §6.8). It finds the machine
// key and node key Core takes, newest staged first, and then, unless it
// rotated within two minutes, moves to a new machine key and a new node
// key.
func (s *Service) PrepareGatewayKeys(ctx context.Context) error {
	gateway, err := s.gatewayClient()
	if err != nil {
		return err
	}
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return err
	}
	defer release()
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return err
	}
	if err := s.settleGatewayKeys(ctx, gateway, active.ID, active.ControlURL); err != nil {
		return err
	}
	return s.rotateGatewayKeys(ctx, gateway, active.ID, active.ControlURL)
}

// settleGatewayKeys probes every staged and current machine key with every
// staged and current node key, and makes the pair Core takes current. When
// none works it tries once more after Core's commit bound.
func (s *Service) settleGatewayKeys(ctx context.Context, gateway gatewayProber, profileID, controlURL string) error {
	for attempt := range 2 {
		if attempt > 0 {
			if err := sleepContext(ctx, s.gatewayCommitWait); err != nil {
				return err
			}
		}
		found, err := s.probeGatewayKeys(ctx, gateway, profileID, controlURL)
		if err != nil || found {
			return err
		}
	}
	return ErrGatewayKeysLost
}

func (s *Service) probeGatewayKeys(ctx context.Context, gateway gatewayProber, profileID, controlURL string) (
	bool, error,
) {
	record, err := s.identities.Get(ctx, profileID)
	if err != nil {
		return false, fmt.Errorf("reading identity: %w", err)
	}
	if !record.IsRegistered() {
		return false, ErrNotGateway
	}
	if !record.IsGateway() {
		return false, fmt.Errorf("%w: the state holds an ordinary (K0) Device; a K1 gateway needs a new state Secret",
			ErrGatewayModeMismatch)
	}
	current := record.Material()
	defer clearIdentityMaterial(current)
	staged := record.PendingMachinePrivateKeys()
	defer func() {
		for _, value := range staged {
			clear(value)
		}
	}()
	machines := append(slices.Clone(staged), current.MachinePrivateKey) // staged newest first, then current
	nodes := [][]byte{current.NodePrivateKey}
	pendingNode := record.PendingNodePrivateKey()
	defer clear(pendingNode)
	if len(pendingNode) > 0 {
		nodes = [][]byte{pendingNode, current.NodePrivateKey}
	}
	for _, machine := range machines {
	nodeKeys:
		for _, node := range nodes {
			material := controlplane.KeyMaterial{
				MachinePrivateKey: machine, NodePrivateKey: node,
				ControlPublicKey: current.ControlPublicKey,
			}
			err := gateway.ProbeGateway(ctx, controlURL, material, record.ControlKeyFingerprint())
			switch {
			case err == nil:
				return true, s.adoptGatewayKeys(ctx, profileID, record, machine, node, pendingNode)
			case errors.Is(err, controlplane.ErrNodeKeyNotCurrent):
				continue nodeKeys
			case errors.Is(err, controlplane.ErrMachineKeyRetired), errors.Is(err, controlplane.ErrMachineKeyUnbound):
				break nodeKeys
			default:
				return false, err
			}
		}
	}
	return false, nil
}

// adoptGatewayKeys makes the keys that proved current, durably. Staged keys
// tried before them answered no; once the last rotation is two minutes old
// (far past any send and Core's commit bound) they surely never committed
// and are dropped. Until then they stay: a commit may still land, and a
// rotation within two minutes is skipped anyway, so none pile up.
func (s *Service) adoptGatewayKeys(ctx context.Context, profileID string, record identity.Record,
	machine, node, pendingNode []byte,
) error {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rotationPersistTimeout)
	defer cancel()
	current := record.Material()
	defer clearIdentityMaterial(current)
	if string(machine) != string(current.MachinePrivateKey) {
		if _, err := s.identities.PromoteMachineKey(persistCtx, profileID, machine); err != nil {
			return fmt.Errorf("promoting the gateway's machine key: %w", err)
		}
	} else if s.rotationSettled(record) {
		staged := record.PendingMachinePrivateKeys()
		defer func() {
			for _, value := range staged {
				clear(value)
			}
		}()
		for _, dead := range staged {
			if _, err := s.identities.AbandonMachineKeyRotation(persistCtx, profileID, dead); err != nil {
				return fmt.Errorf("dropping a machine key that never committed: %w", err)
			}
		}
	}
	switch {
	case len(pendingNode) > 0 && string(node) == string(pendingNode):
		if _, err := s.identities.CompleteNodeKeyRotation(persistCtx, profileID, pendingNode); err != nil {
			return fmt.Errorf("promoting the gateway's node key: %w", err)
		}
	case len(pendingNode) > 0 && s.rotationSettled(record):
		// The current node key proved: the staged one never committed.
		if _, err := s.identities.AbandonNodeKeyRotation(persistCtx, profileID, pendingNode); err != nil {
			return fmt.Errorf("dropping the gateway's staged node key: %w", err)
		}
	}
	return nil
}

// rotateGatewayKeys moves the gateway to a new machine key, then a new node
// key, unless it did within two minutes. A staged key is sent once: an
// unknown outcome is settled by the next start's probe.
func (s *Service) rotateGatewayKeys(ctx context.Context, gateway gatewayProber, profileID, controlURL string) error {
	record, err := s.identities.Get(ctx, profileID)
	if err != nil {
		return fmt.Errorf("reading identity: %w", err)
	}
	now := s.clock()
	if last := record.LastKeyRotationAt(); !last.IsZero() && last.Before(now) && now.Sub(last) < gatewayRotationInterval {
		return nil
	}
	if record.PendingMachineKeyCount() >= 3 {
		s.logControlSessionFailure("gateway key rotation skipped", errors.New("three machine keys are already staged"))
		return nil
	}
	next, err := controlplane.GenerateNodePrivateKey() // the same X25519 form
	if err != nil {
		return err
	}
	defer clear(next)
	nextRaw, err := controlplane.ParsePrivateKey(next)
	if err != nil {
		return err
	}
	defer clear(nextRaw[:])
	nextMachine, err := key.MachinePrivateFromBytes(nextRaw[:])
	if err != nil {
		return controlplane.ErrInvalidMaterial
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rotationPersistTimeout)
	defer cancel()
	if record, err = s.identities.StageMachineKeyRotation(persistCtx, profileID, next, now); err != nil {
		return fmt.Errorf("staging the gateway's machine key: %w", err)
	}
	current := record.Material()
	material := toProtocolMaterial(current)
	clearIdentityMaterial(current)
	defer clearProtocolMaterial(material)
	err = gateway.RotateMachineKey(ctx, controlURL, material, record.ControlKeyFingerprint(), nextMachine,
		s.gatewayPodToken())
	switch {
	case errors.Is(err, controlplane.ErrMachineKeyRotationRefused):
		// Surely not applied: the key is dropped and the gateway goes on.
		if _, abandonErr := s.identities.AbandonMachineKeyRotation(persistCtx, profileID, next); abandonErr != nil {
			return fmt.Errorf("dropping the refused machine key: %w", abandonErr)
		}
		s.logControlSessionFailure("gateway machine key rotation refused", err)
		return nil
	case err != nil:
		return err
	}
	if _, err := s.identities.PromoteMachineKey(persistCtx, profileID, next); err != nil {
		return fmt.Errorf("promoting the gateway's machine key: %w", err)
	}
	if _, _, err := s.rotateNodeKeyLocked(ctx, true); err != nil &&
		!errors.Is(err, controlplane.ErrNodeKeyRotationRefused) {
		return err
	}
	return nil
}

// gatewayClient returns the gateway's control client, or ErrNotGateway.
func (s *Service) gatewayClient() (gatewayProber, error) {
	if !s.gateway {
		return nil, ErrNotGateway
	}
	gateway, ok := s.prober.(gatewayProber)
	if !ok {
		return nil, fmt.Errorf("%w: the control client is not a gateway's", ErrNotGateway)
	}
	return gateway, nil
}

// sleepContext waits d, or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// product names the client in the versions it reports.
func (s *Service) product() string {
	if s.gateway {
		return "meshgw"
	}
	return "meshd"
}

// rotationSettled reports whether the gateway's last rotation is old enough
// that nothing it sent can still commit. A rotation time ahead of the clock
// (a clock stepped back) counts as recent.
func (s *Service) rotationSettled(record identity.Record) bool {
	last := record.LastKeyRotationAt()
	now := s.clock()
	return last.IsZero() || (!last.After(now) && now.Sub(last) >= gatewayRotationInterval)
}

// podTrustDigest digests what the replica sends with its join: the issuer,
// its keys and the namespace, ServiceAccount and pod its token names.
func podTrustDigest(pod PodIdentity) ([32]byte, error) {
	jwks, err := kubejoin.ParseJWKS(pod.JWKS)
	if err != nil {
		return [32]byte{}, err
	}
	namespace, account, name, err := kubejoin.TokenPod(pod.Token.Reveal())
	if err != nil {
		return [32]byte{}, err
	}
	return kubejoin.TrustDigest(kubejoin.Trust{
		Issuer: pod.Issuer, JWKS: jwks, Namespace: namespace,
		ServiceAccount: account, PodName: name,
	})
}

// gatewayPodToken reads the gateway's pod token for a key rotation, again
// each time; none (no file, or not a gateway) sends none, and Core refuses
// the rotation, which the gateway survives (K1.1 design §7.1). A missing
// token is reported once per start.
func (s *Service) gatewayPodToken() controlplane.PodToken {
	if !s.gateway || s.gatewayTokenFile == "" {
		return ""
	}
	token, err := ReadPodToken(s.gatewayTokenFile)
	if err != nil {
		if !s.podTokenWarned.Swap(true) {
			s.logControlSessionFailure("gateway pod token unreadable", err)
		}
		return ""
	}
	return token
}

// MaxPodTokenSize bounds a pod token file: Core takes tokens of 8 KiB.
const MaxPodTokenSize = 8 << 10

// ReadPodToken reads a projected pod token, bounded; an empty or oversized
// file is an error, never sent.
func ReadPodToken(path string) (controlplane.PodToken, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the configured projected token
	if err != nil {
		return "", fmt.Errorf("reading the pod token: %w", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, MaxPodTokenSize+2))
	if err != nil {
		return "", fmt.Errorf("reading the pod token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	switch {
	case token == "":
		return "", errors.New("the pod token file is empty")
	case len(token) > MaxPodTokenSize:
		return "", errors.New("the pod token is over 8 KiB")
	}
	return controlplane.PodToken(token), nil
}
