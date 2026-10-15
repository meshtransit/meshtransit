package guardrail

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// An enforced guardrail is retroactive: maps drop every share it blocks,
// whenever the share was made. Saving one therefore needs a preview of the
// shares it cuts, and the save carries the preview's ImpactHash so it is
// refused when that impact changed in between.

var (
	// ErrImpactChanged reports an enforce-mode save without the impact hash
	// of a current preview.
	ErrImpactChanged = errors.New("guardrail: the shares it cuts changed since the preview")
	// ErrImpactTooLarge reports a Workspace with more active shares than a
	// preview reads.
	ErrImpactTooLarge = errors.New("guardrail: too many shares to preview")
)

// Bounds shared with PostgreSQL.
const (
	// MaximumShareContracts bounds the active shares one preview reads.
	MaximumShareContracts = 20000
	// MaximumPreviewItems bounds the affected shares a preview lists.
	MaximumPreviewItems = 256
)

// impactHashDomain separates impact hashes from every other digest.
const impactHashDomain = "meshtransit.guardrail.impact.v1"

// ImpactHash commits to what saving a guardrail does: its semantic hash and
// the shares it affects. The zero value means none was given.
type ImpactHash [sha256.Size]byte

// ParseImpactHash reads 64 lowercase hexadecimal digits.
func ParseImpactHash(text string) (ImpactHash, error) {
	var hash ImpactHash
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != len(hash) || hex.EncodeToString(decoded) != text {
		return ImpactHash{}, ErrInvalid
	}
	copy(hash[:], decoded)
	return hash, nil
}

// IsZero reports an absent hash.
func (hash ImpactHash) IsZero() bool { return hash == ImpactHash{} }

// String returns the lowercase hexadecimal form.
func (hash ImpactHash) String() string { return hex.EncodeToString(hash[:]) }

// Side is which side of a share the Workspace holds.
type Side string

// Sides of a share.
const (
	SideProvider Side = "provider"
	SideConsumer Side = "consumer"
	// SideBoth is a share between two Networks of the same Workspace.
	SideBoth Side = "both"
)

// ShareContract is one active share touching a Workspace, as that
// Workspace sees it.
type ShareContract struct {
	ID   publicid.ID
	Edge ShareEdge
	Side Side
	// NetworkID is the Workspace's own Network of the share (the provider's
	// for SideBoth).
	NetworkID network.ID
	// Label is the name the Workspace already sees for the share.
	Label string
}

// validFor reports a complete contract whose side matches owner.
func (contract ShareContract) validFor(owner workspace.ID) bool {
	if !contract.ID.IsValid() || !contract.Edge.Provider.IsValid() || !contract.Edge.Consumer.IsValid() {
		return false
	}
	provider := contract.Edge.Provider.WorkspaceID() == owner
	consumer := contract.Edge.Consumer.WorkspaceID() == owner
	switch contract.Side {
	case SideProvider:
		return provider && !consumer && contract.NetworkID == contract.Edge.Provider.NetworkID()
	case SideConsumer:
		return consumer && !provider && contract.NetworkID == contract.Edge.Consumer.NetworkID()
	case SideBoth:
		return provider && consumer && contract.NetworkID == contract.Edge.Provider.NetworkID()
	default:
		return false
	}
}

// ShareInventory is a Workspace's active guardrails and active shares, read
// together.
type ShareInventory struct {
	Guardrails []Guardrail
	Contracts  []ShareContract
}

// Candidate is a guardrail about to be saved: a new one (zero GuardrailID)
// or a replacement of GuardrailID at ExpectedVersion.
type Candidate struct {
	GuardrailID     publicid.ID
	ExpectedVersion int64
	Spec            Spec
}

// Impact is what saving a candidate does to existing shares. In enforce
// mode Affected are the shares it cuts that no guardrail cuts already; in
// audit mode they are the shares it reports. Affected is ordered by ID.
type Impact struct {
	Mode     Mode
	Affected []ShareContract
	Hash     ImpactHash
}

// Blocks reports whether an enforced guardrail of owner blocks edge.
func Blocks(guardrails []Guardrail, owner workspace.ID, edge ShareEdge) bool {
	return len(Blocking(Evaluate(guardrails, owner, edge))) > 0
}

// replace returns current with id's spec replaced by spec, or spec added.
func replace(current []Guardrail, id publicid.ID, spec Spec) []Guardrail {
	next := make([]Guardrail, 0, len(current)+1)
	for _, item := range current {
		if id.IsValid() && item.ID == id {
			continue
		}
		next = append(next, item)
	}
	return append(next, Guardrail{ID: id, Version: 1, Spec: spec})
}

// ComputeImpact returns what saving candidate does when before are the
// Workspace's active guardrails.
func ComputeImpact(owner workspace.ID, before []Guardrail, candidate Candidate, contracts []ShareContract) (Impact, error) {
	if !owner.IsValid() || !candidate.Spec.IsValid() || len(contracts) > MaximumShareContracts {
		return Impact{}, ErrInvalid
	}
	semantic, err := candidate.Spec.SemanticHash()
	if err != nil {
		return Impact{}, err
	}
	after := replace(before, candidate.GuardrailID, candidate.Spec)
	only := []Guardrail{{ID: candidate.GuardrailID, Version: 1, Spec: candidate.Spec}}
	affected := []ShareContract{}
	for _, contract := range contracts {
		if !contract.validFor(owner) {
			return Impact{}, ErrInvalid
		}
		var hit bool
		if candidate.Spec.Mode == ModeEnforce {
			hit = Blocks(after, owner, contract.Edge) && !Blocks(before, owner, contract.Edge)
		} else {
			hit = len(Evaluate(only, owner, contract.Edge)) > 0
		}
		if hit {
			affected = append(affected, contract)
		}
	}
	slices.SortFunc(affected, func(first, second ShareContract) int {
		return bytes.Compare(first.ID[:], second.ID[:])
	})
	return Impact{Mode: candidate.Spec.Mode, Affected: affected, Hash: impactHash(semantic, affected)}, nil
}

// ChangedShares returns the contracts that owner's guardrails block in
// exactly one of before and after: the shares a guardrail change cuts or
// restores.
func ChangedShares(owner workspace.ID, before, after []Guardrail, contracts []ShareContract) []ShareContract {
	changed := []ShareContract{}
	for _, contract := range contracts {
		if Blocks(before, owner, contract.Edge) != Blocks(after, owner, contract.Edge) {
			changed = append(changed, contract)
		}
	}
	return changed
}

// impactHash is SHA-256 over the domain, the semantic hash and the sorted
// contract identifiers, each length-delimited.
func impactHash(semantic [sha256.Size]byte, affected []ShareContract) ImpactHash {
	digest := sha256.New()
	_, _ = digest.Write([]byte(impactHashDomain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(semantic[:])
	_ = binary.Write(digest, binary.BigEndian, uint64(len(affected)))
	for _, contract := range affected {
		_, _ = digest.Write(contract.ID[:])
	}
	var hash ImpactHash
	copy(hash[:], digest.Sum(nil))
	return hash
}

// ParseEnforced reads the kind and canonical parameters of an enforce-mode
// guardrail as maps read them, without its name.
func ParseEnforced(kind Kind, params []byte) (Guardrail, error) {
	var spec Spec
	if err := ParseParams(kind, params, &spec); err != nil {
		return Guardrail{}, err
	}
	spec.Mode = ModeEnforce
	if !spec.paramsValid() {
		return Guardrail{}, ErrInvalid
	}
	return Guardrail{Spec: spec}, nil
}
