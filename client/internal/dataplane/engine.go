// Package dataplane owns the unprivileged tunnel lifecycle.
package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/meshtransit/meshtransit/client/internal/netadmin"
	"github.com/meshtransit/meshtransit/client/internal/networkmap"
)

// State is the non-secret readiness state exposed through daemon status.
type State string

const (
	// StateIdle means no server-authorized peer path is active. An encrypted
	// transport may remain ready so control presence does not depend on peers.
	StateIdle State = "idle"
	// StateTUNReady means the privileged descriptor exists but packet crypto is absent.
	StateTUNReady State = "tun_ready_no_crypto"
	// StateWaitingEndpoint means policy permits a path but control has no direct endpoint yet.
	StateWaitingEndpoint State = "waiting_endpoint"
	// StatePolicyUnsupported is reserved for map semantics the packet gate cannot enforce safely.
	StatePolicyUnsupported State = "policy_unsupported"
	// StateEncrypted means the direct encrypted packet engine is active.
	StateEncrypted State = "encrypted_direct"
	// StateEncryptedRelay means the encrypted engine has a bounded relay fallback.
	StateEncryptedRelay State = "encrypted_relay_ready"
	// StateFailed means privileged setup failed closed.
	StateFailed State = "failed"
)

type tunOpener interface {
	OpenTUN(context.Context, netadmin.TUNConfig) (netadmin.TUN, error)
}

type tunRouteConfigurer interface {
	ConfigureTUNRoutes(context.Context, netadmin.TUNConfig) error
}

// Engine owns a TUN descriptor without yet reading packets or configuring routes.
// The daemon serializes Apply and Close after stopping the map callback.
type Engine struct {
	opener tunOpener
	file   *os.File
	name   string
	mtu    int
}

// New constructs the explicit TUN descriptor lifecycle.
func New(opener tunOpener) (*Engine, error) {
	if opener == nil {
		return nil, errors.New("dataplane: tun opener is required")
	}

	return &Engine{opener: opener}, nil
}

// Apply opens a TUN only when the validated map contains an authorized path.
func (e *Engine) Apply(
	ctx context.Context,
	snapshot networkmap.Snapshot,
	_ NodePrivateKey,
) (State, error) {
	if e == nil {
		return StateFailed, errors.New("dataplane: engine is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return StateFailed, err
	}
	if len(snapshot.Peers) == 0 || len(snapshot.Policy) == 0 {
		if err := e.Close(); err != nil {
			return StateFailed, err
		}

		return StateIdle, nil
	}
	if e.file != nil {
		return StateTUNReady, nil
	}

	tun, err := e.opener.OpenTUN(ctx, netadmin.TUNConfig{})
	if err != nil {
		return StateFailed, fmt.Errorf("dataplane: opening tun: %w", err)
	}
	if tun.File == nil || tun.Name == "" || tun.MTU < 1280 || tun.MTU > 9000 {
		if tun.File != nil {
			_ = tun.File.Close()
		}

		return StateFailed, errors.New("dataplane: helper returned invalid tun metadata")
	}
	e.file = tun.File
	e.name = tun.Name
	e.mtu = tun.MTU

	return StateTUNReady, nil
}

// Close drops the descriptor so Linux removes the non-persistent interface.
func (e *Engine) Close() error {
	if e == nil || e.file == nil {
		return nil
	}
	file := e.file
	e.file = nil
	e.name = ""
	e.mtu = 0
	if err := file.Close(); err != nil {
		return fmt.Errorf("dataplane: closing tun: %w", err)
	}

	return nil
}
