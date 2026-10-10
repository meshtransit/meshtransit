// Package controlselect chooses meshd's control protocol for each control
// origin: MTCP v1 when the origin serves it, the legacy protocol otherwise,
// or one of them when the operator pins it.
package controlselect

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/mtcpclient"
)

// Mode is the operator's protocol choice.
type Mode string

const (
	// ModeAuto uses MTCP where the origin serves it and the legacy
	// protocol where it does not.
	ModeAuto Mode = "auto"
	// ModeMTCP uses only MTCP.
	ModeMTCP Mode = "mtcp"
	// ModeLegacy uses only the legacy protocol.
	ModeLegacy Mode = "legacy"
)

// ErrInvalidMode reports an unknown mode.
var ErrInvalidMode = errors.New("controlselect: invalid control protocol")

// ParseMode validates a mode name.
func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeAuto, ModeMTCP, ModeLegacy:
		return Mode(value), nil
	default:
		return "", fmt.Errorf("%w %q", ErrInvalidMode, value)
	}
}

// Protocol is one control protocol client (the daemon's contract).
type Protocol interface {
	Probe(context.Context, string) (controlplane.Result, error)
	BootstrapTrust(context.Context, string, string) (controlplane.TrustResult, error)
	VerifyTrust(context.Context, string, controlplane.KeyMaterial, string) error
	Register(context.Context, string, controlplane.KeyMaterial, controlplane.RegisterOptions) (
		controlplane.RegistrationResult, error)
	RotateNodeKey(context.Context, string, controlplane.KeyMaterial, []byte, controlplane.RegisterOptions) (
		controlplane.RegistrationResult, error)
	StreamNetmap(context.Context, string, controlplane.KeyMaterial, controlplane.NetmapOptions,
		controlplane.NetmapHandler) error
}

// Client dispatches each operation to the chosen protocol. Both protocols
// use the same key material, so a profile moves between them without
// registering again.
type Client struct {
	mode   Mode
	mtcp   Protocol
	legacy Protocol
}

// New validates its protocols; legacy may be nil in ModeMTCP.
func New(mode Mode, mtcp, legacy Protocol) (*Client, error) {
	if _, err := ParseMode(string(mode)); err != nil {
		return nil, err
	}
	if mtcp == nil && mode != ModeLegacy || legacy == nil && mode != ModeMTCP {
		return nil, ErrInvalidMode
	}
	return &Client{mode: mode, mtcp: mtcp, legacy: legacy}, nil
}

// choose runs operation with MTCP, falling back to legacy in ModeAuto when
// the origin does not serve MTCP.
func choose[T any](c *Client, mtcp, legacy func(Protocol) (T, error)) (T, error) {
	switch c.mode {
	case ModeLegacy:
		return legacy(c.legacy)
	case ModeMTCP:
		return mtcp(c.mtcp)
	}
	result, err := mtcp(c.mtcp)
	if errors.Is(err, mtcpclient.ErrUnavailable) {
		return legacy(c.legacy)
	}
	return result, err
}

// Probe implements the daemon's contract.
func (c *Client) Probe(ctx context.Context, url string) (controlplane.Result, error) {
	run := func(p Protocol) (controlplane.Result, error) { return p.Probe(ctx, url) }
	return choose(c, run, run)
}

// BootstrapTrust implements the daemon's contract.
func (c *Client) BootstrapTrust(ctx context.Context, url, pin string) (controlplane.TrustResult, error) {
	run := func(p Protocol) (controlplane.TrustResult, error) { return p.BootstrapTrust(ctx, url, pin) }
	return choose(c, run, run)
}

// VerifyTrust implements the daemon's contract.
func (c *Client) VerifyTrust(ctx context.Context, url string, material controlplane.KeyMaterial, pin string) error {
	run := func(p Protocol) (struct{}, error) { return struct{}{}, p.VerifyTrust(ctx, url, material, pin) }
	_, err := choose(c, run, run)
	return err
}

// Register implements the daemon's contract.
func (c *Client) Register(ctx context.Context, url string, material controlplane.KeyMaterial,
	options controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	run := func(p Protocol) (controlplane.RegistrationResult, error) {
		return p.Register(ctx, url, material, options)
	}
	return choose(c, run, run)
}

// RotateNodeKey implements the daemon's contract.
func (c *Client) RotateNodeKey(ctx context.Context, url string, material controlplane.KeyMaterial, newKey []byte,
	options controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	run := func(p Protocol) (controlplane.RegistrationResult, error) {
		return p.RotateNodeKey(ctx, url, material, newKey, options)
	}
	return choose(c, run, run)
}

// StreamNetmap implements the daemon's contract.
func (c *Client) StreamNetmap(ctx context.Context, url string, material controlplane.KeyMaterial,
	options controlplane.NetmapOptions, handler controlplane.NetmapHandler,
) error {
	run := func(p Protocol) (struct{}, error) {
		return struct{}{}, p.StreamNetmap(ctx, url, material, options, handler)
	}
	_, err := choose(c, run, run)
	return err
}
