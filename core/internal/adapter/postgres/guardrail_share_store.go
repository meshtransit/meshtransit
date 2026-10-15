package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// An enforced guardrail is retroactive (schema 164): saving one recomputes,
// inside its transaction, the shares it cuts and refuses the save when they
// are not those of the preview; every share it cuts or restores advances
// both sides' Network revisions, with evidence and the revision wakeup on
// each Network's own stream, so their maps are rebuilt.

// Schema 167 versions: the share readers take their bound from MeshCore,
// the preview admits guardrail.manage or guardrail.weaken, and the bump
// rechecks the shares MeshCore evaluated once it holds the revision locks.
const listGuardrailShareContractsSQL = `SELECT mesh_ops.list_guardrail_share_contracts_v2(` + sessionArguments +
	`,$10::UUID,$11::INTEGER)::TEXT`

const guardrailChangeShareContractsSQL = `SELECT mesh_ops.guardrail_change_share_contracts_v2($1::UUID,$2::INTEGER)::TEXT`

const bumpGuardrailShareNetworksSQL = `SELECT mesh_ops.bump_guardrail_share_networks_v2($1::UUID[],$2::UUID[],$3::UUID)::TEXT`

const appendGuardrailShareEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 $7::TEXT,$8::UUID,$9::BIGINT,$10::BIGINT,$11::UUID,$12::TEXT,$13::TEXT,
 $14::UUID,$15::BYTEA,$16::BYTEA,$17::JSONB,'network.revision.advanced',$18::JSONB)`

// maximumGuardrailShareEvidenceIDs bounds the contract IDs one Network
// event lists; the counts are always complete.
const maximumGuardrailShareEvidenceIDs = 64

// maximumGuardrailShareLabelLength bounds a share label (Imported Resource
// names are at most 128 characters, access labels 63).
const maximumGuardrailShareLabelLength = 128

type guardrailShareContractDocument struct {
	ID                  string `json:"trust_contract_id"`
	ProviderWorkspaceID string `json:"provider_workspace_id"`
	ProviderNetworkID   string `json:"provider_network_id"`
	ConsumerWorkspaceID string `json:"consumer_workspace_id"`
	ConsumerNetworkID   string `json:"consumer_network_id"`
	Side                string `json:"side"`
	NetworkID           string `json:"network_id"`
	Label               string `json:"label"`
}

func (document guardrailShareContractDocument) contract() (guardrail.ShareContract, error) {
	id, err := publicid.Parse(document.ID)
	if err != nil {
		return guardrail.ShareContract{}, guardrail.ErrInvalid
	}
	provider, providerErr := scopeFromPublicIDs(document.ProviderWorkspaceID, document.ProviderNetworkID)
	consumer, consumerErr := scopeFromPublicIDs(document.ConsumerWorkspaceID, document.ConsumerNetworkID)
	local, localErr := network.ParseID(document.NetworkID)
	if providerErr != nil || consumerErr != nil || localErr != nil || !utf8.ValidString(document.Label) ||
		utf8.RuneCountInString(document.Label) > maximumGuardrailShareLabelLength {
		return guardrail.ShareContract{}, guardrail.ErrInvalid
	}
	return guardrail.ShareContract{
		ID: id, Edge: guardrail.ShareEdge{Provider: provider, Consumer: consumer},
		Side: guardrail.Side(document.Side), NetworkID: local, Label: document.Label,
	}, nil
}

func scopeFromPublicIDs(workspaceText, networkText string) (network.Scope, error) {
	workspaceID, err := workspace.ParseID(workspaceText)
	if err != nil {
		return network.Scope{}, err
	}
	networkID, err := network.ParseID(networkText)
	if err != nil {
		return network.Scope{}, err
	}
	return network.NewScope(workspaceID, networkID)
}

// decodeGuardrailShareInventory reads the schema 164 inventory document of
// at most limit shares.
func decodeGuardrailShareInventory(encoded string, limit int) (guardrail.ShareInventory, error) {
	var document struct {
		Guardrails []guardrailDocument              `json:"guardrails"`
		Contracts  []guardrailShareContractDocument `json:"contracts"`
	}
	if err := strictJSON([]byte(encoded), &document); err != nil || document.Guardrails == nil ||
		document.Contracts == nil || len(document.Guardrails) > guardrail.MaximumGuardrails ||
		len(document.Contracts) > limit {
		return guardrail.ShareInventory{}, guardrail.ErrInvalid
	}
	inventory := guardrail.ShareInventory{
		Guardrails: make([]guardrail.Guardrail, 0, len(document.Guardrails)),
		Contracts:  make([]guardrail.ShareContract, 0, len(document.Contracts)),
	}
	for _, item := range document.Guardrails {
		parsed, err := item.guardrail()
		if err != nil {
			return guardrail.ShareInventory{}, err
		}
		inventory.Guardrails = append(inventory.Guardrails, parsed)
	}
	for _, item := range document.Contracts {
		parsed, err := item.contract()
		if err != nil {
			return guardrail.ShareInventory{}, err
		}
		inventory.Contracts = append(inventory.Contracts, parsed)
	}
	return inventory, nil
}

// ShareInventory authorizes guardrail.manage and returns the Workspace's
// active guardrails and active shares, read together.
func (store *GuardrailStore) ShareInventory(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (_ guardrail.ShareInventory, resultErr error) {
	if !session.IsValid() || !workspaceID.IsValid() {
		return guardrail.ShareInventory{}, guardrail.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return guardrail.ShareInventory{}, err
	}
	var encoded *string
	if err := tx.QueryRow(ctx, listGuardrailShareContractsSQL,
		append(sessionQueryArguments(session), workspaceID.String(), store.limits.Impact)...).Scan(&encoded); err != nil {
		return guardrail.ShareInventory{}, guardrailDatabaseError(err)
	}
	if encoded == nil {
		return guardrail.ShareInventory{}, guardrail.ErrForbidden
	}
	inventory, err := decodeGuardrailShareInventory(*encoded, store.limits.Impact)
	if err != nil {
		return guardrail.ShareInventory{}, errors.Join(guardrail.ErrUnavailable, err)
	}
	return inventory, nil
}

// guardrailShareChange is what a guardrail change whose result is in enforce
// mode does to shares: the guardrails after it, the shares it evaluated, and
// those whose blocked state it flips.
type guardrailShareChange struct {
	after     []guardrail.Guardrail
	contracts []guardrail.ShareContract
	changed   []guardrail.ShareContract
}

// guardrailShareOutcome is what a change did to shares: the Networks it
// advanced, with their locked stream heads, and either the evaluated shares
// (a result in enforce mode) or a wakeup of Networks chosen in SQL (a
// change that only restores), deferred when more were left to the
// reconcile interval.
type guardrailShareOutcome struct {
	heads    []guardrailShareHead
	shares   *guardrailShareChange
	deferred bool
}

// changeShares advances the revisions of the Networks whose maps a change
// affects. Only a result in enforce mode can cut a share: it evaluates the
// shares (at most the impact bound), checks the preview's hash and
// rechecks them under the revision locks. Deleting or switching an enforced
// guardrail to audit mode can only restore shares: PostgreSQL picks the
// Networks and no share list is read. Any other change (one that never
// enforced) changes no map.
func (store *GuardrailStore) changeShares(ctx context.Context, tx accountSessionTransaction, change guardrail.Change,
	saved guardrail.Guardrail, deleted bool, changeID publicid.ID) (guardrailShareOutcome, error) {
	if !deleted && change.Spec.Mode == guardrail.ModeEnforce {
		shares, err := checkGuardrailShareImpact(ctx, tx, change, saved, deleted, changeID, store.limits.Impact)
		if err != nil {
			return guardrailShareOutcome{}, err
		}
		heads, err := bumpGuardrailShareNetworks(ctx, tx, shares, changeID)
		if err != nil {
			return guardrailShareOutcome{}, err
		}
		return guardrailShareOutcome{heads: heads, shares: &shares}, nil
	}
	if change.Previous == nil || change.Previous.Mode != guardrail.ModeEnforce {
		return guardrailShareOutcome{}, nil
	}
	return wakeGuardrailShareNetworks(ctx, tx, *change.Previous, changeID, store.limits.WakeNetworks)
}

// checkGuardrailShareImpact reads, after an enforce-mode change in this
// transaction, the Workspace's guardrails and at most impactLimit shares;
// refuses the change when its impact is not the preview's; and returns the
// shares whose blocked state the change flips.
func checkGuardrailShareImpact(ctx context.Context, tx accountSessionTransaction, change guardrail.Change,
	saved guardrail.Guardrail, deleted bool, changeID publicid.ID, impactLimit int) (guardrailShareChange, error) {
	var encoded string
	if err := tx.QueryRow(ctx, guardrailChangeShareContractsSQL, changeID.String(), impactLimit).Scan(&encoded); err != nil {
		return guardrailShareChange{}, guardrailDatabaseError(err)
	}
	inventory, err := decodeGuardrailShareInventory(encoded, impactLimit)
	if err != nil {
		return guardrailShareChange{}, errors.Join(guardrail.ErrUnavailable, err)
	}
	// The read must show exactly the saved guardrail; before is the set the
	// change replaced (the previous spec was read at the expected version).
	before := make([]guardrail.Guardrail, 0, len(inventory.Guardrails)+1)
	present := false
	for _, item := range inventory.Guardrails {
		if item.ID == saved.ID {
			present = item.Version == saved.Version
			continue
		}
		before = append(before, item)
	}
	if deleted || !present || change.Spec.Mode != guardrail.ModeEnforce ||
		(change.Operation == guardrail.OperationCreate) != (change.Previous == nil) {
		return guardrailShareChange{}, guardrail.ErrUnavailable
	}
	if change.Previous != nil {
		before = append(before, guardrail.Guardrail{ID: saved.ID, Version: change.ExpectedVersion, Spec: *change.Previous})
	}
	impact, err := guardrail.ComputeImpact(change.WorkspaceID, before,
		guardrail.Candidate{GuardrailID: saved.ID, ExpectedVersion: change.ExpectedVersion, Spec: change.Spec},
		inventory.Contracts)
	if err != nil {
		return guardrailShareChange{}, errors.Join(guardrail.ErrUnavailable, err)
	}
	if change.ImpactHash.IsZero() || impact.Hash != change.ImpactHash {
		return guardrailShareChange{}, guardrail.ErrImpactChanged
	}
	return guardrailShareChange{
		after: inventory.Guardrails, contracts: inventory.Contracts,
		changed: guardrail.ChangedShares(change.WorkspaceID, before, inventory.Guardrails, inventory.Contracts),
	}, nil
}

// guardrailShareHead is one Network whose revisions the change advanced,
// with its locked audit stream head.
type guardrailShareHead struct {
	WorkspaceID     string `json:"workspace_id"`
	NetworkID       string `json:"network_id"`
	OwnWorkspace    bool   `json:"own_workspace"`
	NetworkRevision int64  `json:"network_revision"`
	SharingRevision int64  `json:"sharing_revision"`
	StreamID        int64  `json:"stream_id"`
	NextSequence    int64  `json:"next_sequence"`
	LatestEventHash string `json:"latest_event_hash"`
}

// bumpGuardrailShareNetworks advances both sides' revisions of every changed
// share and returns the locked stream heads of those Networks. It runs even
// when nothing changed: once the revisions are locked, PostgreSQL checks
// that the shares evaluated are still exactly the Workspace's active ones,
// so a share made or ended meanwhile fails the attempt (MTG03), which
// Change redoes, instead of being missed.
func bumpGuardrailShareNetworks(ctx context.Context, tx accountSessionTransaction,
	shares guardrailShareChange, changeID publicid.ID) ([]guardrailShareHead, error) {
	ids := contractIDs(shares.changed)
	var encoded string
	if err := tx.QueryRow(ctx, bumpGuardrailShareNetworksSQL, ids, contractIDs(shares.contracts),
		changeID.String()).Scan(&encoded); err != nil {
		return nil, guardrailDatabaseError(err)
	}
	var heads []guardrailShareHead
	if err := strictJSON([]byte(encoded), &heads); err != nil || heads == nil || len(heads) > 2*len(ids) ||
		(len(ids) == 0) != (len(heads) == 0) {
		return nil, guardrail.ErrUnavailable
	}
	return heads, nil
}

// wakeGuardrailShareNetworksSQL wakes, for a change that only restores, the
// Networks on both sides of the shares of the Networks the guardrail named
// (schema 167), at most $3 of them.
const wakeGuardrailShareNetworksSQL = `SELECT mesh_ops.wake_guardrail_share_networks_v1($1::UUID,$2::UUID[],$3::INTEGER)::TEXT`

// wakeGuardrailShareNetworks advances the Networks whose maps deleting or
// switching to audit the enforced guardrail previous may restore. The
// guardrail's own Networks narrow the shares (none named means every
// Network of the Workspace); PostgreSQL picks at most limit Networks in a
// stable order and says whether it deferred others.
func wakeGuardrailShareNetworks(ctx context.Context, tx accountSessionTransaction, previous guardrail.Spec,
	changeID publicid.ID, limit int) (guardrailShareOutcome, error) {
	named := previous.Networks()
	networks := make([]string, len(named))
	for index, id := range named {
		networks[index] = id.String()
	}
	var encoded string
	if err := tx.QueryRow(ctx, wakeGuardrailShareNetworksSQL, changeID.String(), networks, limit).
		Scan(&encoded); err != nil {
		return guardrailShareOutcome{}, guardrailDatabaseError(err)
	}
	var document struct {
		Heads    []guardrailShareHead `json:"heads"`
		Deferred bool                 `json:"deferred"`
	}
	if err := strictJSON([]byte(encoded), &document); err != nil || document.Heads == nil ||
		len(document.Heads) > limit || (document.Deferred && len(document.Heads) != limit) {
		return guardrailShareOutcome{}, guardrail.ErrUnavailable
	}
	return guardrailShareOutcome{heads: document.Heads, deferred: document.Deferred}, nil
}

func contractIDs(contracts []guardrail.ShareContract) []string {
	ids := make([]string, len(contracts))
	for index, contract := range contracts {
		ids[index] = contract.ID.String()
	}
	return ids
}

// guardrailShareNetworkEvidence is what one Network records about a change
// of its shares: for a result in enforce mode, the shares cut and restored
// (complete counts, at most 64 IDs each); for a wakeup, only that shares
// may have been restored.
type guardrailShareNetworkEvidence struct {
	NetworkID     string    `json:"network_id"`
	GuardrailID   string    `json:"guardrail_id,omitempty"`
	ActingSide    string    `json:"acting_side_details,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	CutCount      *int      `json:"cut_count,omitempty"`
	Cut           *[]string `json:"cut_contracts,omitempty"`
	RestoredCount *int      `json:"restored_count,omitempty"`
	Restored      *[]string `json:"restored_contracts,omitempty"`
}

// guardrailShareCounterpartDetails tells the other Workspace's Network that
// its share changed because of the counterpart's guardrails, which it does
// not see.
const guardrailShareCounterpartDetails = "counterpart_guardrail"

// guardrailShareWakeReason marks a wakeup by a change that only restores.
const guardrailShareWakeReason = "guardrail_no_longer_enforced"

// shareChangeEvidence lists, per Network, the shares an enforce-mode result
// cut and restored.
func shareChangeEvidence(change guardrail.Change, shares guardrailShareChange) map[string]*guardrailShareNetworkEvidence {
	evidence := map[string]*guardrailShareNetworkEvidence{}
	for _, contract := range shares.changed {
		cut := guardrail.Blocks(shares.after, change.WorkspaceID, contract.Edge)
		for _, scope := range []network.Scope{contract.Edge.Provider, contract.Edge.Consumer} {
			key := scope.NetworkID().String()
			entry := evidence[key]
			if entry == nil {
				cutCount, restoredCount, cutIDs, restoredIDs := 0, 0, []string{}, []string{}
				entry = &guardrailShareNetworkEvidence{NetworkID: key, CutCount: &cutCount, Cut: &cutIDs,
					RestoredCount: &restoredCount, Restored: &restoredIDs}
				evidence[key] = entry
			}
			count, ids := entry.RestoredCount, entry.Restored
			if cut {
				count, ids = entry.CutCount, entry.Cut
			}
			*count++
			if len(*ids) < maximumGuardrailShareEvidenceIDs {
				*ids = append(*ids, contract.ID.String())
			}
		}
	}
	for _, entry := range evidence {
		slices.Sort(*entry.Cut)
		slices.Sort(*entry.Restored)
	}
	return evidence
}

// appendGuardrailShareNetworkEvidence records the change on the stream of
// every Network it advanced, with the revision wakeup.
func appendGuardrailShareNetworkEvidence(ctx context.Context, tx accountSessionTransaction, change guardrail.Change,
	saved guardrail.Guardrail, changeID publicid.ID, outcome guardrailShareOutcome) error {
	if len(outcome.heads) == 0 {
		return nil
	}
	var evidence map[string]*guardrailShareNetworkEvidence
	if outcome.shares != nil {
		evidence = shareChangeEvidence(change, *outcome.shares)
		if len(outcome.heads) != len(evidence) {
			return guardrail.ErrInvalid
		}
	}
	after, err := saved.SemanticHash()
	if err != nil {
		return err
	}
	for _, head := range outcome.heads {
		entry := &guardrailShareNetworkEvidence{NetworkID: head.NetworkID, Reason: guardrailShareWakeReason}
		if evidence != nil {
			entry = evidence[head.NetworkID]
		}
		networkID, parseErr := publicid.Parse(head.NetworkID)
		previous, hashErr := hex.DecodeString(head.LatestEventHash)
		if entry == nil || parseErr != nil || hashErr != nil || len(previous) != sha256.Size ||
			head.StreamID <= 0 || head.NextSequence <= 0 || head.NetworkRevision <= 0 || head.SharingRevision <= 0 ||
			head.OwnWorkspace != (head.WorkspaceID == change.WorkspaceID.String()) {
			return guardrail.ErrInvalid
		}
		event := guardrailShareEvent{
			head: head, previous: [sha256.Size]byte(previous), changeID: changeID,
			aggregateKind: "network", aggregateID: networkID, aggregateVersion: head.NetworkRevision,
			action: "sharing.counterpart_guardrail_changed", permission: "system.reconcile",
		}
		if head.OwnWorkspace {
			entry.GuardrailID = saved.ID.String()
			event.aggregateKind, event.aggregateID, event.aggregateVersion = "guardrail", saved.ID, saved.Version
			event.action, event.permission = "guardrail.share_access_changed", string(change.Permission)
			event.actor, event.correlationID, event.after = publicid.ID(change.Session.PrincipalID()),
				change.CorrelationID, &after
		} else {
			entry.ActingSide = guardrailShareCounterpartDetails
		}
		event.payload = entry
		if err := appendGuardrailShareEvent(ctx, tx, event); err != nil {
			return err
		}
	}
	return nil
}

type guardrailShareEvent struct {
	head             guardrailShareHead
	previous         [sha256.Size]byte
	changeID         publicid.ID
	aggregateKind    string
	aggregateID      publicid.ID
	aggregateVersion int64
	actor            publicid.ID
	action           string
	permission       string
	correlationID    publicid.ID
	after            *[sha256.Size]byte
	payload          any
}

func optionalID(id publicid.ID) any {
	if !id.IsValid() {
		return nil
	}
	return id.String()
}

func appendGuardrailShareEvent(ctx context.Context, tx accountSessionTransaction, event guardrailShareEvent) error {
	payload, err := json.Marshal(event.payload)
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(resourceAuthorityOutboxPayload{
		NetworkRevision: event.head.NetworkRevision, Subsystem: "sharing", SubsystemRevision: event.head.SharingRevision,
	})
	if err != nil {
		return err
	}
	eventID, err := publicid.New()
	if err != nil {
		return err
	}
	outboxID, err := publicid.New()
	if err != nil {
		return err
	}
	var after [sha256.Size]byte
	var afterArgument any
	if event.after != nil {
		after = *event.after
		afterArgument = after[:]
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: event.previous, EventID: eventID, ChangeID: event.changeID,
		AggregateKind: event.aggregateKind, AggregateID: event.aggregateID, AggregateVersion: event.aggregateVersion,
		NetworkRevision: event.head.NetworkRevision, ActorPrincipalID: event.actor, Action: event.action,
		Permission: event.permission, CorrelationID: event.correlationID, AfterSemanticHash: after,
		AuditPayloadHash: sha256.Sum256(payload), OutboxEventClass: resourceAuthorityOutboxEventClass,
		OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendGuardrailShareEvidenceSQL, event.head.StreamID, eventID.String(),
		outboxID.String(), event.head.NextSequence, event.previous[:], eventHash[:], event.aggregateKind,
		event.aggregateID.String(), event.aggregateVersion, event.head.NetworkRevision, optionalID(event.actor),
		event.action, event.permission, optionalID(event.correlationID), nil, afterArgument, payload,
		outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != event.head.NextSequence {
		return guardrail.ErrInvalid
	}
	return nil
}
