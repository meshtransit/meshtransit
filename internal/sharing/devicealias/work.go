package devicealias

import (
	"context"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// Cursor identifies the last visited endpoint/consumer, including rows that
// produced no action. An absent Consumer means the endpoint was fully scanned.
type Cursor struct {
	EndpointID sharing.PrivateEndpointID
	ConsumerID node.ID
}

// IsValid accepts the initial zero cursor or a complete public endpoint selector.
func (cursor Cursor) IsValid() bool {
	return (cursor.EndpointID == (sharing.PrivateEndpointID{}) || cursor.EndpointID.IsValid()) &&
		(cursor.ConsumerID == (node.ID{}) || cursor.ConsumerID.IsValid() && cursor.EndpointID.IsValid())
}

// Advances reports keyset progress, including completion of the same endpoint.
func (cursor Cursor) Advances(previous Cursor) bool {
	if !cursor.EndpointID.IsValid() {
		return false
	}
	if !previous.EndpointID.IsValid() {
		return true
	}
	if cursor.EndpointID.String() != previous.EndpointID.String() {
		return cursor.EndpointID.String() > previous.EndpointID.String()
	}
	if !previous.ConsumerID.IsValid() {
		return false
	}
	return !cursor.ConsumerID.IsValid() || cursor.ConsumerID.String() > previous.ConsumerID.String()
}

// Page holds bounded discovery hints. It confers no permission to send packets.
type Page struct {
	Items []ChangeIntent
	Next  Cursor
	Done  bool
}

// IsValid rejects stalled cursors, foreign deployments and duplicated work.
func (page Page) IsValid(installation deployment.ID, after Cursor, limit int) bool {
	if !installation.IsValid() || !after.IsValid() || limit < 1 || limit > 128 || len(page.Items) > limit || !page.Next.IsValid() || !page.Done && !page.Next.Advances(after) {
		return false
	}
	seen := make(map[[2]string]struct{}, len(page.Items))
	for _, intent := range page.Items {
		if !intent.IsValid() || intent.DeploymentID != installation {
			return false
		}
		key := [2]string{intent.EndpointID.String(), intent.ConsumerID.String()}
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

// Work discovers at most one finite page without owning a write transaction.
type Work interface {
	List(context.Context, deployment.ID, Cursor, int) (Page, error)
}
