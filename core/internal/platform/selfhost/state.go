package selfhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// ErrInvalidState reports a state.json setup cannot trust.
var ErrInvalidState = errors.New("invalid self-host state")

const (
	stateFile   = "state.json"
	stateFormat = "meshtransit-selfhost-state/v1"
)

// State is what setup decided once and must never change by accident: the
// identities bootstrap writes into the database, the identity configuration
// the operator approved, and the control key's expiry. It is authority state:
// back it up with the database; after a restore the database's values win.
type State struct {
	Format               string `json:"format"`
	DeploymentID         string `json:"deployment_id"`
	RecoveryEpoch        int64  `json:"recovery_epoch"`
	ProviderID           string `json:"provider_id"`
	ClientID             string `json:"client_id"`
	ProviderGeneration   int64  `json:"provider_generation"`
	ConnectorGeneration  int64  `json:"connector_generation"`
	CoreClientGeneration int64  `json:"core_client_generation"`
	IdentityFingerprint  string `json:"identity_fingerprint"`
	// ApprovedIssuer and ApprovedOrigin are the public names the first
	// approval saw; bootstrap writes them into the database, so they never
	// change afterwards.
	ApprovedIssuer  string    `json:"approved_issuer"`
	ApprovedOrigin  string    `json:"approved_origin"`
	MTCPKeyNotAfter time.Time `json:"mtcp_key_not_after"`
}

// publicNamesMatch reports whether config still has the issuer and origin
// the first approval pinned (always true before one).
func (state State) publicNamesMatch(config Config) bool {
	return state.ApprovedIssuer == "" ||
		state.ApprovedIssuer == issuer(config) && state.ApprovedOrigin == consoleOrigin(config)
}

// LoadState reads dir's state.json strictly.
func LoadState(dir string) (State, error) {
	contents, err := readRegularFile(filepath.Join(dir, stateFile), maximumRenderedBytes)
	if err != nil {
		return State{}, fmt.Errorf("%w: %w", ErrInvalidState, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil || state.Format != stateFormat || !state.valid() {
		return State{}, ErrInvalidState
	}
	return state, nil
}

func (state State) valid() bool {
	for _, id := range []string{state.DeploymentID, state.ProviderID, state.ClientID} {
		parsed, err := publicid.Parse(id)
		if err != nil || parsed.String() != id {
			return false
		}
	}
	return state.RecoveryEpoch > 0 && state.ProviderGeneration > 0 && state.ConnectorGeneration > 0 &&
		state.CoreClientGeneration > 0 && !state.MTCPKeyNotAfter.IsZero()
}

// ensureState creates state.json when dir has none, and leaves an existing
// one untouched.
func ensureState(dir string, options GenerateOptions) error {
	if _, err := os.Lstat(filepath.Join(dir, stateFile)); err == nil {
		_, err := LoadState(dir)
		return err
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrInvalidState, err)
	}
	ids := make([]string, 3)
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidState, err)
		}
		ids[index] = id.String()
	}
	state := State{
		Format: stateFormat, DeploymentID: ids[0], RecoveryEpoch: 1, ProviderID: ids[1], ClientID: ids[2],
		ProviderGeneration: 1, ConnectorGeneration: 1, CoreClientGeneration: 1,
		MTCPKeyNotAfter: options.Now.UTC().Truncate(time.Second).AddDate(1, 0, 0),
	}
	return writeState(dir, state, options.Owner, false)
}

// writeState writes state.json: only if absent unless replace is set
// (approving an identity change replaces it).
func writeState(dir string, state State, owner *Owner, replace bool) error {
	contents, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidState, err)
	}
	if !replace {
		_, err = writeIfAbsent(dir, stateFile, contents, 0o600, owner)
		return err
	}
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidState, err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := writeAndSync(temporary, contents, 0o600, owner); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidState, err)
	}
	if err := os.Rename(temporaryName, filepath.Join(dir, stateFile)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidState, err)
	}
	return nil
}
