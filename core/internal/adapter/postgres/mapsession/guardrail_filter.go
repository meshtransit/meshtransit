package mapsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/workspace"
)

// mapShareGuardrailsSQL reads the enforce-mode guardrails of the Workspaces
// of this Network's shares (schema 164); any other Workspace fails it.
const mapShareGuardrailsSQL = `SELECT mesh_ops.map_share_guardrails_v1($1::UUID[])::TEXT`

// maximumGuardrailWorkspaces is what schema 164 accepts in one read: the
// Workspaces of every share a map may read, its own included.
const maximumGuardrailWorkspaces = 16384

// maximumGuardrailDocumentBytes bounds the reader's answer.
const maximumGuardrailDocumentBytes = 64 << 20

// dropGuardrailBlocked removes every share an enforced guardrail of its
// provider's or its consumer's Workspace blocks: an enforce-mode guardrail
// is retroactive, while the share's state stays as it is, so weakening the
// guardrail restores the share. A blocked share leaves no peer, alias or
// rule in the map. Guardrails that cannot be read fail the map; a share is
// never kept on missing evidence. It returns the shares kept and how many
// were cut.
func dropGuardrailBlocked(
	ctx context.Context, transaction databaseTransaction, projections []appmapsession.DirectDeviceProjection,
) ([]appmapsession.DirectDeviceProjection, int, error) {
	if len(projections) == 0 {
		return projections, 0, nil
	}
	requested := map[workspace.ID]struct{}{}
	for _, projection := range projections {
		requested[projection.ProviderScope().WorkspaceID()] = struct{}{}
		requested[projection.ConsumerScope().WorkspaceID()] = struct{}{}
	}
	if len(requested) > maximumGuardrailWorkspaces {
		return nil, 0, errors.Join(ErrLoadSnapshot, ErrSnapshotEvidence)
	}
	ids := make([]string, 0, len(requested))
	for id := range requested {
		ids = append(ids, id.String())
	}
	slices.Sort(ids)
	guardrails, err := readShareGuardrails(ctx, transaction, ids)
	if err != nil {
		return nil, 0, err
	}
	kept := make([]appmapsession.DirectDeviceProjection, 0, len(projections))
	for _, projection := range projections {
		edge := guardrail.ShareEdge{Provider: projection.ProviderScope(), Consumer: projection.ConsumerScope()}
		provider, consumer := edge.Provider.WorkspaceID(), edge.Consumer.WorkspaceID()
		if guardrail.Blocks(guardrails[provider], provider, edge) || guardrail.Blocks(guardrails[consumer], consumer, edge) {
			continue
		}
		kept = append(kept, projection)
	}
	return kept, len(projections) - len(kept), nil
}

type shareGuardrailDocument struct {
	WorkspaceID string `json:"workspace_id"`
	Guardrails  []struct {
		Kind   string          `json:"kind"`
		Params json.RawMessage `json:"params"`
	} `json:"guardrails"`
}

// readShareGuardrails returns the enforced guardrails of exactly the
// requested Workspaces.
func readShareGuardrails(
	ctx context.Context, transaction databaseTransaction, ids []string,
) (map[workspace.ID][]guardrail.Guardrail, error) {
	rows, err := transaction.Query(ctx, mapShareGuardrailsSQL, ids)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read share guardrails: %w", err))
	}
	defer rows.Close()
	var encoded string
	read := 0
	for rows.Next() {
		if read++; read > 1 {
			return nil, ErrSnapshotEvidence
		}
		if err := rows.Scan(&encoded); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan share guardrails: %w", err))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate share guardrails: %w", err))
	}
	if read != 1 || len(encoded) > maximumGuardrailDocumentBytes {
		return nil, ErrSnapshotEvidence
	}
	var documents []shareGuardrailDocument
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	var extra any
	if err := decoder.Decode(&documents); err != nil || !errors.Is(decoder.Decode(&extra), io.EOF) ||
		len(documents) != len(ids) {
		return nil, ErrSnapshotEvidence
	}
	result := make(map[workspace.ID][]guardrail.Guardrail, len(documents))
	for _, document := range documents {
		id, err := workspace.ParseID(document.WorkspaceID)
		_, listed := slices.BinarySearch(ids, id.String())
		if err != nil || !listed || document.Guardrails == nil ||
			len(document.Guardrails) > guardrail.MaximumGuardrails {
			return nil, ErrSnapshotEvidence
		}
		if _, duplicate := result[id]; duplicate {
			return nil, ErrSnapshotEvidence
		}
		enforced := make([]guardrail.Guardrail, 0, len(document.Guardrails))
		for _, item := range document.Guardrails {
			parsed, err := guardrail.ParseEnforced(guardrail.Kind(item.Kind), item.Params)
			if err != nil {
				return nil, errors.Join(ErrSnapshotEvidence, err)
			}
			enforced = append(enforced, parsed)
		}
		result[id] = enforced
	}
	return result, nil
}
