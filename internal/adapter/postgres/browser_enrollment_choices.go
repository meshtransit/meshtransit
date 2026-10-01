package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const readBrowserEnrollmentNetworksSQL = `SELECT mesh_ops.list_browser_enrollment_networks_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::UUID, $6::INTEGER
)::TEXT`

var (
	// ErrInvalidBrowserEnrollmentChoices reports invalid enrollment-choice input.
	ErrInvalidBrowserEnrollmentChoices = errors.New("invalid browser enrollment choice request")
	// ErrBrowserEnrollmentChoicesUnavailable reports an unavailable choice projection.
	ErrBrowserEnrollmentChoicesUnavailable = errors.New("browser enrollment choices unavailable")
	// ErrBrowserEnrollmentChoicesEvidence reports inconsistent choice evidence.
	ErrBrowserEnrollmentChoicesEvidence = errors.New("invalid browser enrollment choice evidence")
)

// ReadBrowserEnrollmentNetworks reads only Networks eligible for the exact
// Account Session digest. A false found result means the session is no longer
// admitted; an empty Networks slice means it has no eligible Networks.
func (store *AccountSessionStore) ReadBrowserEnrollmentNetworks(
	ctx context.Context,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	digest accountsession.Digest,
	after network.ID,
	limit int,
) (_ enrollment.BrowserEnrollmentChoices, found bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !digest.IsValid() ||
		(!after.IsValid() && after != (network.ID{})) || limit < 1 || limit > 101 {
		return enrollment.BrowserEnrollmentChoices{}, false, ErrInvalidBrowserEnrollmentChoices
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return enrollment.BrowserEnrollmentChoices{}, false, ErrBrowserEnrollmentChoicesUnavailable
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout)); err != nil {
		return enrollment.BrowserEnrollmentChoices{}, false, errors.Join(ErrBrowserEnrollmentChoicesUnavailable, err)
	}
	var afterValue any
	if after.IsValid() {
		afterValue = after.String()
	}
	digestBytes := digest.Bytes()
	var encoded *string
	if err := transaction.QueryRow(ctx, readBrowserEnrollmentNetworksSQL,
		deploymentID.String(), recoveryEpoch, digest.KeyID().String(),
		digestBytes[:], afterValue, limit).Scan(&encoded); err != nil {
		return enrollment.BrowserEnrollmentChoices{}, false, errors.Join(ErrBrowserEnrollmentChoicesUnavailable, err)
	}
	if encoded == nil {
		if err := transaction.Commit(ctx); err != nil {
			return enrollment.BrowserEnrollmentChoices{}, false, errors.Join(ErrBrowserEnrollmentChoicesUnavailable, err)
		}
		closed = true
		return enrollment.BrowserEnrollmentChoices{}, false, nil
	}
	choices, err := decodeBrowserEnrollmentChoices(*encoded, after, limit)
	if err != nil {
		return enrollment.BrowserEnrollmentChoices{}, false, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return enrollment.BrowserEnrollmentChoices{}, false, errors.Join(ErrBrowserEnrollmentChoicesUnavailable, err)
	}
	closed = true
	return choices, true, nil
}

func decodeBrowserEnrollmentChoices(encoded string, after network.ID, limit int) (enrollment.BrowserEnrollmentChoices, error) {
	var record struct {
		WorkspaceID          string `json:"workspace_id"`
		WorkspaceDisplayName string `json:"workspace_display_name"`
		Networks             []struct {
			NetworkID   string `json:"network_id"`
			DisplayName string `json:"display_name"`
		} `json:"networks"`
	}
	if err := json.Unmarshal([]byte(encoded), &record); err != nil ||
		record.Networks == nil || len(record.Networks) > limit {
		return enrollment.BrowserEnrollmentChoices{}, ErrBrowserEnrollmentChoicesEvidence
	}
	workspaceID, err := workspace.ParseID(record.WorkspaceID)
	if err != nil {
		return enrollment.BrowserEnrollmentChoices{}, ErrBrowserEnrollmentChoicesEvidence
	}
	choices := enrollment.BrowserEnrollmentChoices{
		WorkspaceID:          workspaceID,
		WorkspaceDisplayName: record.WorkspaceDisplayName,
		Networks:             make([]enrollment.BrowserEnrollmentNetworkChoice, 0, len(record.Networks)),
	}
	previous := after
	for _, item := range record.Networks {
		id, err := network.ParseID(item.NetworkID)
		if err != nil || item.DisplayName == "" ||
			(previous.IsValid() && id.String() <= previous.String()) {
			return enrollment.BrowserEnrollmentChoices{}, ErrBrowserEnrollmentChoicesEvidence
		}
		choices.Networks = append(choices.Networks, enrollment.BrowserEnrollmentNetworkChoice{
			NetworkID: id, DisplayName: item.DisplayName,
		})
		previous = id
	}
	if !choices.IsValid() {
		return enrollment.BrowserEnrollmentChoices{}, ErrBrowserEnrollmentChoicesEvidence
	}
	return choices, nil
}
