package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

const readBrowserEnrollmentWorkspacesSQL = `SELECT mesh_ops.list_browser_enrollment_workspaces_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::UUID, $6::INTEGER
)::TEXT`

const readBrowserEnrollmentNetworksInWorkspaceSQL = `SELECT mesh_ops.list_browser_enrollment_networks_v2(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::UUID, $6::UUID, $7::INTEGER
)::TEXT`

// ReadBrowserEnrollmentWorkspaces includes current, admitted memberships
// independently of ownership or the Account Session's original login Workspace.
func (store *AccountSessionStore) ReadBrowserEnrollmentWorkspaces(ctx context.Context,
	deploymentID deployment.ID, epoch int64, digest accountsession.Digest, after workspace.ID, limit int,
) (enrollment.BrowserEnrollmentWorkspaceChoices, bool, error) {
	if !deploymentID.IsValid() || epoch <= 0 || !digest.IsValid() ||
		(!after.IsValid() && after != (workspace.ID{})) || limit < 1 || limit > 101 {
		return enrollment.BrowserEnrollmentWorkspaceChoices{}, false, ErrInvalidBrowserEnrollmentChoices
	}
	var cursor any
	if after.IsValid() {
		cursor = after.String()
	}
	material := digest.Bytes()
	encoded, err := store.readBrowserChoiceJSON(ctx, readBrowserEnrollmentWorkspacesSQL,
		deploymentID.String(), epoch, digest.KeyID().String(), material[:], cursor, limit)
	if err != nil || encoded == nil {
		return enrollment.BrowserEnrollmentWorkspaceChoices{}, false, err
	}
	choices, err := decodeBrowserWorkspaceChoices(*encoded, after, limit)
	return choices, err == nil, err
}

// ReadBrowserEnrollmentNetworksInWorkspace admits the exact selected Workspace
// before exposing its bounded, current Network enrollment inventory.
func (store *AccountSessionStore) ReadBrowserEnrollmentNetworksInWorkspace(ctx context.Context,
	deploymentID deployment.ID, epoch int64, digest accountsession.Digest,
	selected workspace.ID, after network.ID, limit int,
) (enrollment.BrowserEnrollmentChoices, bool, error) {
	if !deploymentID.IsValid() || epoch <= 0 || !digest.IsValid() || !selected.IsValid() ||
		(!after.IsValid() && after != (network.ID{})) || limit < 1 || limit > 101 {
		return enrollment.BrowserEnrollmentChoices{}, false, ErrInvalidBrowserEnrollmentChoices
	}
	var cursor any
	if after.IsValid() {
		cursor = after.String()
	}
	material := digest.Bytes()
	encoded, err := store.readBrowserChoiceJSON(ctx, readBrowserEnrollmentNetworksInWorkspaceSQL,
		deploymentID.String(), epoch, digest.KeyID().String(), material[:], selected.String(), cursor, limit)
	if err != nil || encoded == nil {
		return enrollment.BrowserEnrollmentChoices{}, false, err
	}
	choices, err := decodeBrowserEnrollmentChoices(*encoded, after, limit)
	if err != nil || choices.WorkspaceID != selected || choices.WorkspaceDisplayName == "" {
		return enrollment.BrowserEnrollmentChoices{}, false, ErrBrowserEnrollmentChoicesEvidence
	}
	return choices, true, nil
}

func (store *AccountSessionStore) readBrowserChoiceJSON(ctx context.Context, query string, arguments ...any,
) (_ *string, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, ErrInvalidBrowserEnrollmentChoices
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return nil, ErrBrowserEnrollmentChoicesUnavailable
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return nil, errors.Join(ErrBrowserEnrollmentChoicesUnavailable, err)
	}
	var encoded *string
	if err := transaction.QueryRow(ctx, query, arguments...).Scan(&encoded); err != nil {
		return nil, errors.Join(ErrBrowserEnrollmentChoicesUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, errors.Join(ErrBrowserEnrollmentChoicesUnavailable, err)
	}
	closed = true
	return encoded, nil
}

func decodeBrowserWorkspaceChoices(encoded string, after workspace.ID, limit int,
) (enrollment.BrowserEnrollmentWorkspaceChoices, error) {
	var record struct {
		Workspaces []struct {
			ID   string `json:"workspace_id"`
			Name string `json:"display_name"`
		} `json:"workspaces"`
	}
	if err := json.Unmarshal([]byte(encoded), &record); err != nil || record.Workspaces == nil || len(record.Workspaces) > limit {
		return enrollment.BrowserEnrollmentWorkspaceChoices{}, ErrBrowserEnrollmentChoicesEvidence
	}
	choices := enrollment.BrowserEnrollmentWorkspaceChoices{
		Workspaces: make([]enrollment.BrowserEnrollmentWorkspaceChoice, 0, len(record.Workspaces)),
	}
	for _, choice := range record.Workspaces {
		id, err := workspace.ParseID(choice.ID)
		if err != nil || (after.IsValid() && id.String() <= after.String()) {
			return enrollment.BrowserEnrollmentWorkspaceChoices{}, ErrBrowserEnrollmentChoicesEvidence
		}
		choices.Workspaces = append(choices.Workspaces, enrollment.BrowserEnrollmentWorkspaceChoice{
			WorkspaceID: id, DisplayName: choice.Name,
		})
	}
	if !choices.IsValid() {
		return enrollment.BrowserEnrollmentWorkspaceChoices{}, ErrBrowserEnrollmentChoicesEvidence
	}
	return choices, nil
}
