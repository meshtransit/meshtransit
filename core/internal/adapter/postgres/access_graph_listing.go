package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
)

// maximumAccessGraphListingBytes bounds each JSON document of one graph page:
// at most 500 edges and the at most 1,000 participants they connect.
const maximumAccessGraphListingBytes = 2 * 1024 * 1024

const readAccessGraphSQL = `SELECT
    network_revision,
    inventory_revision,
    group_revision,
    policy_revision,
    dns_revision,
    route_revision,
    sharing_revision,
    isolation_generation,
    has_active_release,
    release_public_id::TEXT,
    compiler_format_version,
    release_semantic_hash,
    matching_paths,
    has_more,
    paths::TEXT,
    nodes::TEXT
FROM mesh_ops.read_access_graph_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::UUID, $13::TEXT, $14::UUID, $15::INTEGER, $16::TIMESTAMPTZ
)`

var _ accessgraph.GraphReader = (*AccessGraphStore)(nil)

// ReadGraph authorizes policy.read and device.read and reads one page of the
// active compiled edges from one repeatable-read, exact-Network transaction.
func (store *AccessGraphStore) ReadGraph(
	ctx context.Context,
	session accountsession.Session,
	query accessgraph.GraphQuery,
	evaluatedAt time.Time,
) (accessgraph.GraphPage, error) {
	if ctx == nil || !session.IsValid() || !query.IsValid() || evaluatedAt.IsZero() {
		return accessgraph.GraphPage{}, accessgraph.ErrInvalidQuery
	}
	if store == nil || store.database == nil || !validAccessGraphOptions(store.options) {
		return accessgraph.GraphPage{}, accessgraph.ErrUnavailable
	}
	return retryReadConflict(ctx, func() (accessgraph.GraphPage, error) {
		return store.readGraphOnce(ctx, session, query, evaluatedAt)
	})
}

func (store *AccessGraphStore) readGraphOnce(
	ctx context.Context,
	session accountsession.Session,
	query accessgraph.GraphQuery,
	evaluatedAt time.Time,
) (page accessgraph.GraphPage, resultErr error) {
	if err := ctx.Err(); err != nil {
		return accessgraph.GraphPage{}, errors.Join(accessgraph.ErrUnavailable, err)
	}
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return accessgraph.GraphPage{}, accessGraphListingError(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	if err := transaction.Exec(
		ctx,
		configureResourceAuthoritySQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return accessgraph.GraphPage{}, accessGraphListingError(ctx, err)
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(
		ctx,
		setResourceAuthorityScopeSQL,
		query.Scope().WorkspaceID().String(),
		query.Scope().NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return accessgraph.GraphPage{}, accessGraphListingError(ctx, err)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return accessgraph.GraphPage{}, accessgraph.ErrUnavailable
	}

	var deviceArgument, protocolArgument, afterArgument any
	if deviceID, filtered := query.DeviceID(); filtered {
		deviceArgument = deviceID.String()
	}
	if protocol, filtered := query.Protocol(); filtered {
		protocolArgument = protocol.String()
	}
	if cursor := query.Cursor(); !cursor.IsZero() {
		afterArgument = cursor.AfterProjection().String()
	}
	var record accessGraphListingRecord
	var paths, nodes string
	if err := transaction.QueryRow(
		ctx,
		readAccessGraphSQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		query.Scope().WorkspaceID().String(),
		query.Scope().NetworkID().String(),
		deviceArgument,
		protocolArgument,
		afterArgument,
		query.PageSize(),
		evaluatedAt,
	).Scan(
		&record.NetworkRevision,
		&record.InventoryRevision,
		&record.GroupRevision,
		&record.PolicyRevision,
		&record.DNSRevision,
		&record.RouteRevision,
		&record.SharingRevision,
		&record.IsolationGeneration,
		&record.HasActiveRelease,
		&record.ReleaseID,
		&record.CompilerFormatVersion,
		&record.SemanticHash,
		&record.MatchingPaths,
		&record.HasMore,
		&paths,
		&nodes,
	); err != nil {
		return accessgraph.GraphPage{}, accessGraphListingError(ctx, err)
	}
	if err := decodeAccessGraphListingJSON(paths, &record.Paths); err != nil {
		return accessgraph.GraphPage{}, err
	}
	if err := decodeAccessGraphListingJSON(nodes, &record.Nodes); err != nil {
		return accessgraph.GraphPage{}, err
	}
	page, err = record.page(query)
	if err != nil {
		return accessgraph.GraphPage{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return accessgraph.GraphPage{}, accessGraphListingError(ctx, err)
	}
	committed = true
	return page, nil
}

type accessGraphListingRecord struct {
	NetworkRevision       int64
	InventoryRevision     int64
	GroupRevision         int64
	PolicyRevision        int64
	DNSRevision           int64
	RouteRevision         int64
	SharingRevision       int64
	IsolationGeneration   int64
	HasActiveRelease      bool
	ReleaseID             *string
	CompilerFormatVersion *int
	SemanticHash          []byte
	MatchingPaths         int
	HasMore               bool
	Paths                 []accessGraphPathRecord
	Nodes                 []accessGraphNodeRecord
}

type accessGraphNodeRecord struct {
	Kind  string                  `json:"kind"`
	ID    string                  `json:"id"`
	Name  *string                 `json:"name"`
	State string                  `json:"state"`
	Share *accessGraphShareRecord `json:"share"`
}

// decodeAccessGraphListingJSON strictly decodes one bounded JSON array.
func decodeAccessGraphListingJSON(encoded string, target any) error {
	if len(encoded) > maximumAccessGraphListingBytes {
		return accessgraph.ErrInvalidSnapshot
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.Join(accessgraph.ErrInvalidSnapshot, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return accessgraph.ErrInvalidSnapshot
	}
	return nil
}

func (record accessGraphListingRecord) page(query accessgraph.GraphQuery) (accessgraph.GraphPage, error) {
	revision, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: record.NetworkRevision, InventoryRevision: record.InventoryRevision,
		GroupRevision: record.GroupRevision, PolicyRevision: record.PolicyRevision,
		DNSRevision: record.DNSRevision, RouteRevision: record.RouteRevision,
		SharingRevision: record.SharingRevision, IsolationGeneration: record.IsolationGeneration,
	})
	if err != nil {
		return accessgraph.GraphPage{}, accessgraph.ErrInvalidSnapshot
	}
	params := accessgraph.GraphPageParams{
		Scope: query.Scope(), Revision: revision, HasActiveRelease: record.HasActiveRelease,
		MatchingPaths: record.MatchingPaths, HasMore: record.HasMore,
	}
	if record.HasActiveRelease {
		if record.ReleaseID == nil || record.CompilerFormatVersion == nil || len(record.SemanticHash) != 32 {
			return accessgraph.GraphPage{}, accessgraph.ErrInvalidSnapshot
		}
		releaseID, err := publication.ParseReleaseID(*record.ReleaseID)
		if err != nil {
			return accessgraph.GraphPage{}, accessgraph.ErrInvalidSnapshot
		}
		var hashValue [32]byte
		copy(hashValue[:], record.SemanticHash)
		hash, err := publication.NewSemanticHash(hashValue)
		if err != nil {
			return accessgraph.GraphPage{}, accessgraph.ErrInvalidSnapshot
		}
		params.ReleaseID, params.CompilerFormatVersion, params.SemanticHash =
			releaseID, *record.CompilerFormatVersion, hash
	} else if record.ReleaseID != nil || record.CompilerFormatVersion != nil || len(record.SemanticHash) != 0 {
		return accessgraph.GraphPage{}, accessgraph.ErrInvalidSnapshot
	}
	params.Paths = make([]accessgraph.Path, len(record.Paths))
	for index, pathRecord := range record.Paths {
		path, err := pathRecord.path()
		if err != nil {
			return accessgraph.GraphPage{}, err
		}
		params.Paths[index] = path
	}
	params.Nodes = make([]accessgraph.GraphNode, len(record.Nodes))
	for index, nodeRecord := range record.Nodes {
		graphNode, err := nodeRecord.node()
		if err != nil {
			return accessgraph.GraphPage{}, err
		}
		params.Nodes[index] = graphNode
	}
	return accessgraph.NewGraphPage(query, params)
}

func (record accessGraphNodeRecord) node() (accessgraph.GraphNode, error) {
	name := ""
	if record.Name != nil {
		name = *record.Name
	}
	participant, err := accessgraph.NewParticipant(parseAccessGraphParticipantState(record.State), name)
	if err != nil {
		return accessgraph.GraphNode{}, err
	}
	params := accessgraph.GraphNodeParams{Participant: participant}
	switch record.Kind {
	case "device":
		params.Kind = accessgraph.GraphNodeKindDevice
		params.DeviceID, err = node.ParseID(record.ID)
	case "resource":
		params.Kind = accessgraph.GraphNodeKindResource
		params.ResourceID, err = resource.ParseID(record.ID)
	case "imported_resource":
		params.Kind = accessgraph.GraphNodeKindImportedResource
		params.ImportedResourceID, err = sharing.ParseImportedResourceID(record.ID)
	default:
		return accessgraph.GraphNode{}, accessgraph.ErrInvalidSnapshot
	}
	if err != nil {
		return accessgraph.GraphNode{}, accessgraph.ErrInvalidSnapshot
	}
	if record.Share != nil {
		share, err := record.Share.share()
		if err != nil {
			return accessgraph.GraphNode{}, err
		}
		params.Share = &share
	}
	return accessgraph.NewGraphNode(params)
}

// accessGraphListingError conceals missing authority and separates invalid
// input from an unavailable database.
func accessGraphListingError(ctx context.Context, err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "22023" {
		return accessgraph.ErrInvalidQuery
	}
	if errors.As(err, &databaseError) && databaseError.Code == "MTA01" {
		return accessgraph.ErrGraphTooLarge
	}
	return accessGraphDatabaseError(ctx, err)
}
