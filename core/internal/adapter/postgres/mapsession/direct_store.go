package mapsession

import (
	"context"
	"errors"
	"fmt"
	"slices"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

// legacyEdgeLimit is what the share map readers before schema 147 accept:
// they fail the map past 256 endpoints or contracts.
const legacyEdgeLimit = 256

// limitedEdge is the last row a schema 147 reader returns when it stopped at
// its limit; what it returned before is kept.
const limitedEdge = `{"limited": true}`

// edgeReader is one share map reader and the most rows it returns.
type edgeReader struct {
	query string
	limit int
	// scaled readers (schema 147) end with limitedEdge at their limit
	// instead of failing the map.
	scaled bool
}

const loadDirectEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const loadAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v3($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

// loadReachableAliasEdgesSQL counts only shares this Device may reach
// (schema 114). It is used once the operator granted it to this role.
const loadReachableAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v4($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const reachableAliasEdgesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_alias_map_edges_v4(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// loadScaledAliasEdgesSQL is v4 bounded by the map peer limit instead of 256
// (schema 147), used once the operator granted it to this role.
const loadScaledAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v5($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const scaledAliasEdgesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_alias_map_edges_v5(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// loadSelectiveAliasEdgesSQL is v5 choosing endpoints from this Device's
// targets and rules instead of every endpoint (schema 149), used once the
// operator granted it to this role.
const loadSelectiveAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v6($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const selectiveAliasEdgesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_alias_map_edges_v6(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// loadKeyedAliasEdgesSQL is v6 authenticating the Device by its node key
// instead of scanning its Network (schema 155), used once the operator
// granted it to this role.
const loadKeyedAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v7($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const keyedAliasEdgesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_alias_map_edges_v7(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// setStatementTimeoutSQL changes the transaction's statement bound.
const setStatementTimeoutSQL = `SELECT pg_catalog.set_config('statement_timeout', $1, TRUE)`

// loadDirectEdges reads the Device's shares. With ShareStatementTimeout
// above StatementTimeout the share readers run under it: they are bounded by
// the share limit (10000) but cost about half a millisecond per share, so a
// Device receiving thousands of shares outlasts the per-statement bound that
// suits every other map read. The request deadline still bounds the map.
func (store *Store) loadDirectEdges(
	ctx context.Context, transaction databaseTransaction, self appmapsession.Snapshot,
	machineFingerprint, nodeKey []byte, legacy bool,
) (appmapsession.Snapshot, error) {
	widen := store.options.EnableDeviceAliases && store.options.ShareStatementTimeout > store.options.StatementTimeout
	if widen {
		if err := transaction.Exec(ctx, setStatementTimeoutSQL, postgresTimeout(store.options.ShareStatementTimeout)); err != nil {
			return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("widen share read timeout: %w", err))
		}
	}
	result, err := store.loadShareEdges(ctx, transaction, self, machineFingerprint, nodeKey, legacy)
	if err != nil || !widen {
		return result, err
	}
	if err := transaction.Exec(ctx, setStatementTimeoutSQL, postgresTimeout(store.options.StatementTimeout)); err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("restore statement timeout: %w", err))
	}
	return result, nil
}

// loadShareEdges reads the Device's shares; legacy false leaves out the
// legacy direct endpoint reader (the Network holds none).
func (store *Store) loadShareEdges(
	ctx context.Context, transaction databaseTransaction, self appmapsession.Snapshot,
	machineFingerprint, nodeKey []byte, legacy bool,
) (appmapsession.Snapshot, error) {
	if store.options.EnableDeviceAliases {
		var err error
		self, err = store.loadSharingDependencies(ctx, transaction, self, machineFingerprint, nodeKey)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
	}
	// Direct endpoints are no longer created (schema 92 activates every
	// share on the alias path); the legacy reader serves the rows left.
	var projections []appmapsession.DirectDeviceProjection
	limited := false
	if legacy {
		direct := edgeReader{query: loadDirectEdgesSQL, limit: legacyEdgeLimit}
		var err error
		projections, limited, err = readSharingEdges(ctx, transaction, self, machineFingerprint, nodeKey, direct,
			decodeDirectEdge)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
	}
	if store.options.EnableDeviceAliases {
		reader, err := aliasEdgesReader(ctx, transaction)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
		store.observeReader(ctx, FunctionPathAliasMapEdges, reader)
		aliases, aliasesLimited, err := readSharingEdges(ctx, transaction, self, machineFingerprint, nodeKey, reader, decodeAliasEdge)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
		projections = append(projections, aliases...)
		limited = limited || aliasesLimited
	}
	// Enforced guardrails cut shares after the readers' own row limits but
	// before the map's share cap, so a cut share does not count against the
	// cap; it still counts against a reader's limit.
	projections, cut, err := dropGuardrailBlocked(ctx, transaction, projections)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	store.stats.guardrailCuts.Add(uint64(cut)) // #nosec G115 -- cut is a non-negative count.
	omitted := 0
	if limited {
		omitted = 1 // at least one; the reader stopped before counting more
	}
	if len(projections) > appmapsession.MaximumDirectDeviceProjections {
		slices.SortFunc(projections, appmapsession.CompareDirectDeviceProjections)
		omitted += len(projections) - appmapsession.MaximumDirectDeviceProjections
		projections = projections[:appmapsession.MaximumDirectDeviceProjections]
	}
	result := self
	if len(projections) != 0 {
		result, err = self.WithDirectDeviceProjections(projections)
		if err != nil {
			return appmapsession.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
		}
	}
	if omitted != 0 {
		result, err = result.WithOmittedShares(omitted)
		if err != nil {
			return appmapsession.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
		}
	}
	return result, nil
}

// aliasEdgesReader selects the newest alias map reader runtime may execute,
// so a rolling upgrade or a pending operator step keeps the previous one.
func aliasEdgesReader(ctx context.Context, transaction databaseTransaction) (edgeReader, error) {
	keyed, err := functionGranted(ctx, transaction, keyedAliasEdgesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check alias map reader: %w", err))
	}
	if keyed {
		return edgeReader{query: loadKeyedAliasEdgesSQL, limit: appmapsession.MaximumDirectDeviceProjections,
			scaled: true}, nil
	}
	selective, err := functionGranted(ctx, transaction, selectiveAliasEdgesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check alias map reader: %w", err))
	}
	if selective {
		return edgeReader{query: loadSelectiveAliasEdgesSQL, limit: appmapsession.MaximumDirectDeviceProjections,
			scaled: true}, nil
	}
	scaled, err := functionGranted(ctx, transaction, scaledAliasEdgesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check alias map reader: %w", err))
	}
	if scaled {
		return edgeReader{query: loadScaledAliasEdgesSQL, limit: appmapsession.MaximumDirectDeviceProjections,
			scaled: true}, nil
	}
	granted, err := functionGranted(ctx, transaction, reachableAliasEdgesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check alias map reader: %w", err))
	}
	if granted {
		return edgeReader{query: loadReachableAliasEdgesSQL, limit: legacyEdgeLimit}, nil
	}
	return edgeReader{query: loadAliasEdgesSQL, limit: legacyEdgeLimit}, nil
}

// functionGranted runs a has_function_privilege query for this role.
func functionGranted(ctx context.Context, transaction databaseTransaction, query string) (bool, error) {
	rows, err := transaction.Query(ctx, query)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return false, err
	}
	defer rows.Close()
	granted := false
	if rows.Next() {
		if err := rows.Scan(&granted); err != nil {
			return false, fmt.Errorf("scan: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate: %w", err)
	}
	return granted, nil
}

// readSharingEdges reads one reader's edges. A legacy reader fails past its
// limit; a scaled one ends with limitedEdge, reported as limited.
func readSharingEdges(
	ctx context.Context, transaction databaseTransaction, self appmapsession.Snapshot,
	machineFingerprint, nodeKey []byte, reader edgeReader,
	decode func([]byte, appmapsession.Snapshot) (appmapsession.DirectDeviceProjection, error),
) ([]appmapsession.DirectDeviceProjection, bool, error) {
	requested := reader.limit + 1 // one more row reveals a legacy overflow
	if reader.scaled {
		requested = reader.limit
	}
	rows, err := transaction.Query(ctx, reader.query, machineFingerprint, nodeKey, requested)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("read direct sharing edges: %w", err))
	}
	defer rows.Close()
	projections := make([]appmapsession.DirectDeviceProjection, 0, 4)
	limited := false
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan direct sharing edge: %w", err))
		}
		if reader.scaled && encoded == limitedEdge {
			limited = true
			continue
		}
		if len(projections) == reader.limit || limited {
			// Past the reader's limit, or a row after limitedEdge.
			return nil, false, errors.Join(ErrLoadSnapshot, ErrSnapshotEvidence)
		}
		projection, err := decode([]byte(encoded), self)
		if err != nil {
			return nil, false, err
		}
		projections = append(projections, projection)
	}
	if err := rows.Err(); err != nil {
		return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate direct sharing edges: %w", err))
	}
	return projections, limited, nil
}
