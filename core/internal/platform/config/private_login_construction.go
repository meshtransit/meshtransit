package config

import (
	"context"
	"log/slog"
)

// PrivateLoginConstruction exclusively owns one startup candidate. Constructors
// copy resident bytes; Clear erases only this temporary owner's buffers.
type PrivateLoginConstruction struct {
	Keys     *PrivateIdentityKeyMaterial
	Material *PrivateLoginMaterial
	source   privateLoginFileSnapshot
}

// LoadConstruction binds the originally loaded protected JSON, all purpose keys
// and TLS/client-secret material within one caller-clamped five-second budget.
// No reread, merge, retry, listener or provider/database effect is permitted.
func (profile *PrivateLoginConfig) LoadConstruction(ctx context.Context) (*PrivateLoginConstruction, error) {
	if profile == nil || profile.keys == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityKeyTimeout)
	defer cancel()
	return profile.loadConstructionCandidate(ctx, func(ctx context.Context, file SecretFile) ([32]byte,
		privateIdentityKeySnapshot, error) {
		return file.readPrivateIdentityKeySnapshot(ctx)
	}, readPrivateLoginFileSnapshot)
}

// Only local deterministic fixtures substitute readers. Serving and validation
// always use the production readers above, with no operator fault knob.
func (profile *PrivateLoginConfig) loadConstructionCandidate(
	ctx context.Context,
	readKey func(context.Context, SecretFile) ([32]byte, privateIdentityKeySnapshot, error),
	readMaterial privateLoginFileReader,
) (*PrivateLoginConstruction, error) {
	if !profile.source.stillCurrent(ctx) {
		return nil, ErrInvalid
	}
	result := &PrivateLoginConstruction{source: profile.source}
	accepted := false
	defer func() {
		if !accepted {
			result.Clear()
		}
	}()
	var err error
	result.Keys, err = profile.keys.loadCandidate(ctx, readKey)
	if err != nil {
		return nil, ErrInvalid
	}
	result.Material, err = profile.loadMaterialCandidate(ctx, readMaterial)
	if err != nil || result.CheckCurrent(ctx) != nil {
		return nil, ErrInvalid
	}
	accepted = true
	return result, nil
}

// CheckCurrent rechecks original metadata before releasing an unstarted graph,
// without reloading bytes. It detects ordinary atomic/mount rotation, not a
// global filesystem transaction or privileged restoration of inode metadata.
func (candidate *PrivateLoginConstruction) CheckCurrent(ctx context.Context) error {
	if candidate == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityKeyTimeout)
	defer cancel()
	if !candidate.source.stillCurrent(ctx) || !candidate.Keys.stillCurrent(ctx) ||
		!candidate.Material.stillCurrent(ctx) || ctx.Err() != nil {
		return ErrInvalid
	}
	return nil
}

// Clear releases all owned bytes and metadata, including optional previous keys.
func (candidate *PrivateLoginConstruction) Clear() {
	if candidate == nil {
		return
	}
	candidate.Keys.Clear()
	candidate.Material.Clear()
	candidate.Keys, candidate.Material = nil, nil
	candidate.source = privateLoginFileSnapshot{}
}

// String redacts the complete temporary bundle.
func (PrivateLoginConstruction) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (PrivateLoginConstruction) GoString() string { return redactedValue }

// LogValue redacts structured diagnostics.
func (PrivateLoginConstruction) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses construction material serialization.
func (PrivateLoginConstruction) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
