// Package guardrail holds Workspace guardrails (R1-67): owner-level
// invariants that no rule or share may break, whoever makes the change. A
// guardrail only ever narrows what is reachable; adding one cannot open a
// path. This package validates guardrails, decides whether a change narrows
// or weakens one, and evaluates share edges against them. PostgreSQL stores
// them and checks the permission each change needs.
package guardrail

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalid reports a malformed guardrail, change or result.
	ErrInvalid = errors.New("guardrail: invalid guardrail or result")
	// ErrForbidden conceals missing authority or an unavailable Workspace.
	ErrForbidden = errors.New("guardrail: permission denied")
	// ErrNotFound reports an unknown or deleted guardrail.
	ErrNotFound = errors.New("guardrail: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("guardrail: version conflict")
	// ErrUnknownNetwork reports a referenced Network outside the Workspace.
	ErrUnknownNetwork = errors.New("guardrail: Network is not in the Workspace")
	// ErrLimit reports a Workspace that already has the maximum guardrails.
	ErrLimit = errors.New("guardrail: limit reached")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("guardrail: unavailable")
)

// Bounds shared with PostgreSQL.
const (
	MaximumNameLength        = 80
	MaximumDescriptionLength = 280
	MaximumListLength        = 64
	MaximumGuardrails        = 100
)

// Kind is what a guardrail constrains.
type Kind string

const (
	// KindNetworkIsolation keeps Devices in some Networks from ever reaching some others.
	KindNetworkIsolation Kind = "network_isolation"
	// KindNetworkSharing stops some Networks sharing out, in, or either way.
	KindNetworkSharing Kind = "network_sharing"
	// KindExternalSharing stops sharing with other Workspaces, optionally per
	// Network and except listed partner Workspaces.
	KindExternalSharing Kind = "external_sharing"
)

// Mode is whether a guardrail blocks or only records findings.
type Mode string

const (
	// ModeAudit records findings without blocking, to see impact first.
	ModeAudit Mode = "audit"
	// ModeEnforce blocks every change that breaks the guardrail.
	ModeEnforce Mode = "enforce"
)

// Direction is which way sharing a guardrail covers, seen from a Network.
type Direction string

// Directions a guardrail can cover.
const (
	DirectionOutgoing Direction = "outgoing"
	DirectionIncoming Direction = "incoming"
	DirectionBoth     Direction = "both"
)

func (direction Direction) valid() bool {
	return direction == DirectionOutgoing || direction == DirectionIncoming || direction == DirectionBoth
}

func (direction Direction) covers(side Direction) bool {
	return direction == DirectionBoth || direction == side
}

// within reports whether every side this direction covers is covered by other.
func (direction Direction) within(other Direction) bool {
	return other == DirectionBoth || other == direction
}

// NetworkIsolationParams blocks Devices in From from reaching Devices in To,
// and the reverse too when BothDirections is set.
type NetworkIsolationParams struct {
	From           []network.ID
	To             []network.ID
	BothDirections bool
}

// NetworkSharingParams blocks shares out of, into, or either way for Networks.
type NetworkSharingParams struct {
	Networks  []network.ID
	Direction Direction
}

// ExternalSharingParams blocks shares with other Workspaces in Direction.
// Empty Networks means every Network of the Workspace; AllowedWorkspaces are
// partners the guardrail still lets through.
type ExternalSharingParams struct {
	Direction         Direction
	Networks          []network.ID
	AllowedWorkspaces []workspace.ID
}

// Spec is the editable part of a guardrail.
type Spec struct {
	Kind        Kind
	Name        string
	Description string
	Mode        Mode
	Isolation   NetworkIsolationParams
	Sharing     NetworkSharingParams
	External    ExternalSharingParams
}

// Guardrail is one stored, active guardrail.
type Guardrail struct {
	ID      publicid.ID
	Version int64
	Spec
}

func validIDs[T interface{ IsValid() bool }](ids []T, allowEmpty bool) bool {
	if len(ids) > MaximumListLength || (!allowEmpty && len(ids) == 0) {
		return false
	}
	for _, id := range ids {
		if !id.IsValid() {
			return false
		}
	}
	return true
}

func unique[T comparable](values []T) bool {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

// IsValid reports a complete, bounded spec for its kind.
func (spec Spec) IsValid() bool {
	name := strings.TrimSpace(spec.Name)
	if name != spec.Name || name == "" || utf8.RuneCountInString(name) > MaximumNameLength ||
		utf8.RuneCountInString(spec.Description) > MaximumDescriptionLength ||
		!utf8.ValidString(spec.Name) || !utf8.ValidString(spec.Description) ||
		(spec.Mode != ModeAudit && spec.Mode != ModeEnforce) {
		return false
	}
	return spec.paramsValid()
}

// paramsValid reports complete, bounded parameters for the spec's kind.
func (spec Spec) paramsValid() bool {
	switch spec.Kind {
	case KindNetworkIsolation:
		params := spec.Isolation
		if !validIDs(params.From, false) || !validIDs(params.To, false) || !unique(params.From) || !unique(params.To) {
			return false
		}
		for _, id := range params.From {
			if slices.Contains(params.To, id) {
				return false
			}
		}
		return true
	case KindNetworkSharing:
		return validIDs(spec.Sharing.Networks, false) && unique(spec.Sharing.Networks) && spec.Sharing.Direction.valid()
	case KindExternalSharing:
		params := spec.External
		return params.Direction.valid() && validIDs(params.Networks, true) && unique(params.Networks) &&
			validIDs(params.AllowedWorkspaces, true) && unique(params.AllowedWorkspaces)
	default:
		return false
	}
}

// Networks returns every Network the spec names, for scope checks.
func (spec Spec) Networks() []network.ID {
	switch spec.Kind {
	case KindNetworkIsolation:
		return slices.Concat(spec.Isolation.From, spec.Isolation.To)
	case KindNetworkSharing:
		return slices.Clone(spec.Sharing.Networks)
	case KindExternalSharing:
		return slices.Clone(spec.External.Networks)
	default:
		return nil
	}
}

func sortedIDs[T interface{ String() string }](ids []T) []string {
	texts := make([]string, len(ids))
	for index, id := range ids {
		texts[index] = id.String()
	}
	slices.Sort(texts)
	return texts
}

// ParamsDocument is the canonical stored form of the kind's parameters:
// sorted identifiers, every list present, so equal meaning gives equal bytes.
func (spec Spec) ParamsDocument() ([]byte, error) {
	if !spec.IsValid() {
		return nil, ErrInvalid
	}
	switch spec.Kind {
	case KindNetworkIsolation:
		return json.Marshal(struct {
			From           []string `json:"from_networks"`
			To             []string `json:"to_networks"`
			BothDirections bool     `json:"both_directions"`
		}{sortedIDs(spec.Isolation.From), sortedIDs(spec.Isolation.To), spec.Isolation.BothDirections})
	case KindNetworkSharing:
		return json.Marshal(struct {
			Networks  []string `json:"networks"`
			Direction string   `json:"direction"`
		}{sortedIDs(spec.Sharing.Networks), string(spec.Sharing.Direction)})
	default:
		return json.Marshal(struct {
			Direction         string   `json:"direction"`
			Networks          []string `json:"networks"`
			AllowedWorkspaces []string `json:"allowed_workspaces"`
		}{string(spec.External.Direction), sortedIDs(spec.External.Networks), sortedIDs(spec.External.AllowedWorkspaces)})
	}
}

// SemanticHash commits to what the guardrail enforces: kind, mode and
// canonical parameters, not its name or description.
func (spec Spec) SemanticHash() ([sha256.Size]byte, error) {
	params, err := spec.ParamsDocument()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(struct {
		Kind   string          `json:"kind"`
		Mode   string          `json:"mode"`
		Params json.RawMessage `json:"params"`
	}{string(spec.Kind), string(spec.Mode), params})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func parseIDs[T any](texts []string, parse func(string) (T, error)) ([]T, error) {
	if len(texts) > MaximumListLength {
		return nil, ErrInvalid
	}
	ids := make([]T, len(texts))
	for index, text := range texts {
		id, err := parse(text)
		if err != nil {
			return nil, ErrInvalid
		}
		ids[index] = id
	}
	return ids, nil
}

// ParseParams reads canonical parameters for a kind into spec.
func ParseParams(kind Kind, raw []byte, spec *Spec) error {
	if spec == nil || len(raw) == 0 || len(raw) > 16384 {
		return ErrInvalid
	}
	var document struct {
		From              []string `json:"from_networks"`
		To                []string `json:"to_networks"`
		BothDirections    bool     `json:"both_directions"`
		Networks          []string `json:"networks"`
		Direction         string   `json:"direction"`
		AllowedWorkspaces []string `json:"allowed_workspaces"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return ErrInvalid
	}
	spec.Kind = kind
	var err error
	switch kind {
	case KindNetworkIsolation:
		if spec.Isolation.From, err = parseIDs(document.From, network.ParseID); err != nil {
			return err
		}
		if spec.Isolation.To, err = parseIDs(document.To, network.ParseID); err != nil {
			return err
		}
		spec.Isolation.BothDirections = document.BothDirections
	case KindNetworkSharing:
		if spec.Sharing.Networks, err = parseIDs(document.Networks, network.ParseID); err != nil {
			return err
		}
		spec.Sharing.Direction = Direction(document.Direction)
	case KindExternalSharing:
		if spec.External.Networks, err = parseIDs(document.Networks, network.ParseID); err != nil {
			return err
		}
		if spec.External.AllowedWorkspaces, err = parseIDs(document.AllowedWorkspaces, workspace.ParseID); err != nil {
			return err
		}
		spec.External.Direction = Direction(document.Direction)
	default:
		return ErrInvalid
	}
	return nil
}
