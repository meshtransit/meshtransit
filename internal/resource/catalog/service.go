package catalog

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

const rollbackWindow = 2 * time.Second

// Service owns authorized Resource catalog transaction boundaries.
type Service struct {
	transactions Transactions
	clock        Clock
}

// NewService validates and constructs the Resource catalog application service.
func NewService(dependencies Dependencies) (*Service, error) {
	if dependencies.Transactions == nil || dependencies.Clock == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{transactions: dependencies.Transactions, clock: dependencies.Clock}, nil
}

// GetResource returns one freshly authorized exact-scope Resource snapshot.
func (service *Service) GetResource(
	ctx context.Context, session accountsession.Session, scope network.Scope, id resource.ID,
) (_ Resource, resultErr error) {
	if ctx == nil || service == nil || !session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return Resource{}, ErrInvalidRequest
	}
	transaction, closeTransaction, err := service.begin(ctx, scope)
	if err != nil {
		return Resource{}, err
	}
	defer func() {
		if closeTransaction != nil {
			closeTransaction(&resultErr)
		}
	}()
	if err = transaction.Authorize(ctx, session, authorization.PermissionResourceRead, service.clock.Now().UTC()); err != nil {
		return Resource{}, err
	}
	value, err := transaction.Resource(ctx, id)
	if err != nil || !value.IsValid() || value.Scope() != scope || value.ID() != id {
		if err == nil {
			err = ErrInvalidResult
		}
		return Resource{}, err
	}
	if err = transaction.Commit(ctx); err != nil {
		return Resource{}, err
	}
	closeTransaction = nil
	return value, nil
}

// ResolvePolicyResources returns one snapshot-consistent, freshly authorized,
// active Resource set for policy compilation. IDs must be unique and bounded.
func (service *Service) ResolvePolicyResources(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	ids []resource.ID,
) (_ []Resource, resultErr error) {
	resources, _, err := service.ResolvePolicyDestinations(ctx, session, scope, ids, nil)
	return resources, err
}

// ResolvePolicyDestinations returns one snapshot-consistent, freshly authorized
// set of active Resources and immutable Resource Group definitions. Every group
// member must still match its pinned Resource version and target generation.
func (service *Service) ResolvePolicyDestinations(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	resourceIDs []resource.ID,
	groupIDs []resource.GroupID,
) (_ []Resource, _ []Group, resultErr error) {
	if ctx == nil || service == nil || !session.IsValid() || !scope.IsValid() ||
		(len(resourceIDs) == 0 && len(groupIDs) == 0) ||
		len(resourceIDs) > MaximumPolicyResources || len(groupIDs) > MaximumPolicyResourceGroups {
		return nil, nil, ErrInvalidRequest
	}
	resourceIDs, err := canonicalPolicyResourceIDs(resourceIDs)
	if err != nil {
		return nil, nil, err
	}
	groupIDs, err = canonicalPolicyResourceGroupIDs(groupIDs)
	if err != nil {
		return nil, nil, err
	}

	transaction, closeTransaction, err := service.begin(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if closeTransaction != nil {
			closeTransaction(&resultErr)
		}
	}()
	evaluatedAt := service.clock.Now().UTC()
	if len(groupIDs) > 0 {
		if err = transaction.Authorize(
			ctx, session, authorization.PermissionResourceGroupRead, evaluatedAt,
		); err != nil {
			return nil, nil, err
		}
	}
	if err = transaction.Authorize(
		ctx, session, authorization.PermissionResourceRead, evaluatedAt,
	); err != nil {
		return nil, nil, err
	}

	groups := make([]Group, len(groupIDs))
	references := make(map[resource.ID]resource.Reference, len(resourceIDs))
	for _, id := range resourceIDs {
		references[id] = resource.Reference{}
	}
	for index, id := range groupIDs {
		group, readErr := transaction.Group(ctx, id)
		if readErr != nil {
			return nil, nil, readErr
		}
		if !group.IsValid() || group.ID() != id || group.Scope() != scope {
			return nil, nil, ErrInvalidResult
		}
		if group.State() != resource.StateActive {
			return nil, nil, ErrConflict
		}
		groups[index] = group
		for _, reference := range group.Members() {
			if existing, found := references[reference.ResourceID()]; found &&
				existing.IsValid() && existing != reference {
				return nil, nil, ErrConflict
			}
			references[reference.ResourceID()] = reference
		}
	}
	if len(references) > MaximumPolicyResources {
		return nil, nil, ErrInvalidRequest
	}
	resourceIDs = resourceIDs[:0]
	for id := range references {
		resourceIDs = append(resourceIDs, id)
	}
	slices.SortFunc(resourceIDs, func(first, second resource.ID) int {
		return strings.Compare(first.String(), second.String())
	})
	resources := make([]Resource, len(resourceIDs))
	for index, id := range resourceIDs {
		value, readErr := transaction.Resource(ctx, id)
		if readErr != nil {
			return nil, nil, readErr
		}
		if !value.IsValid() || value.ID() != id || value.Scope() != scope {
			return nil, nil, ErrInvalidResult
		}
		if value.State() != resource.StateActive {
			return nil, nil, ErrConflict
		}
		if reference := references[id]; reference.IsValid() &&
			(reference.ResourceVersion() != value.Version() ||
				reference.TargetGeneration() != value.TargetGeneration()) {
			return nil, nil, ErrConflict
		}
		resources[index] = value
	}
	if err = transaction.Commit(ctx); err != nil {
		return nil, nil, err
	}
	closeTransaction = nil
	return resources, groups, nil
}

func canonicalPolicyResourceIDs(ids []resource.ID) ([]resource.ID, error) {
	ids = slices.Clone(ids)
	for _, id := range ids {
		if !id.IsValid() {
			return nil, ErrInvalidRequest
		}
	}
	slices.SortFunc(ids, func(first, second resource.ID) int {
		return strings.Compare(first.String(), second.String())
	})
	for index := 1; index < len(ids); index++ {
		if ids[index-1] == ids[index] {
			return nil, ErrInvalidRequest
		}
	}
	return ids, nil
}

func canonicalPolicyResourceGroupIDs(ids []resource.GroupID) ([]resource.GroupID, error) {
	ids = slices.Clone(ids)
	for _, id := range ids {
		if !id.IsValid() {
			return nil, ErrInvalidRequest
		}
	}
	slices.SortFunc(ids, func(first, second resource.GroupID) int {
		return strings.Compare(first.String(), second.String())
	})
	for index := 1; index < len(ids); index++ {
		if ids[index-1] == ids[index] {
			return nil, ErrInvalidRequest
		}
	}
	return ids, nil
}

// GetGroup returns one freshly authorized exact-scope Resource Group snapshot.
func (service *Service) GetGroup(
	ctx context.Context, session accountsession.Session, scope network.Scope, id resource.GroupID,
) (_ Group, resultErr error) {
	if ctx == nil || service == nil || !session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return Group{}, ErrInvalidRequest
	}
	transaction, closeTransaction, err := service.begin(ctx, scope)
	if err != nil {
		return Group{}, err
	}
	defer func() {
		if closeTransaction != nil {
			closeTransaction(&resultErr)
		}
	}()
	if err = transaction.Authorize(ctx, session, authorization.PermissionResourceGroupRead, service.clock.Now().UTC()); err != nil {
		return Group{}, err
	}
	value, err := transaction.Group(ctx, id)
	if err != nil || !value.IsValid() || value.Scope() != scope || value.ID() != id {
		if err == nil {
			err = ErrInvalidResult
		}
		return Group{}, err
	}
	if err = transaction.Commit(ctx); err != nil {
		return Group{}, err
	}
	closeTransaction = nil
	return value, nil
}

// ListResources returns one revision-pinned deterministic Resource page.
func (service *Service) ListResources(
	ctx context.Context, session accountsession.Session, scope network.Scope,
	state resource.State, limit int, cursor PageCursor,
) (_ ResourcePage, resultErr error) {
	if ctx == nil || service == nil || !validListRequest(session, scope, state, limit, cursor) {
		return ResourcePage{}, ErrInvalidRequest
	}
	transaction, closeTransaction, err := service.begin(ctx, scope)
	if err != nil {
		return ResourcePage{}, err
	}
	defer func() {
		if closeTransaction != nil {
			closeTransaction(&resultErr)
		}
	}()
	if err = transaction.Authorize(ctx, session, authorization.PermissionResourceRead, service.clock.Now().UTC()); err != nil {
		return ResourcePage{}, err
	}
	inventoryRevision, _, err := transaction.Revisions(ctx)
	if err != nil {
		return ResourcePage{}, err
	}
	if cursor.IsValid() && cursor.Revision() != inventoryRevision {
		return ResourcePage{}, ErrConflict
	}
	after := publicid.ID{}
	if cursor.IsValid() {
		after = cursor.After()
	}
	items, err := transaction.Resources(ctx, state, after, limit+1)
	if err != nil {
		return ResourcePage{}, err
	}
	if len(items) > limit+1 {
		return ResourcePage{}, ErrInvalidResult
	}
	page := ResourcePage{Items: items, Revision: inventoryRevision}
	if len(items) > limit {
		page.Items = items[:limit]
		page.Next, err = NewPageCursor(inventoryRevision, publicid.ID(page.Items[limit-1].ID()))
		if err != nil {
			return ResourcePage{}, ErrInvalidResult
		}
	}
	if err = validateResourcePage(page, scope); err != nil {
		return ResourcePage{}, err
	}
	if err = transaction.Commit(ctx); err != nil {
		return ResourcePage{}, err
	}
	closeTransaction = nil
	return page, nil
}

// ListGroups returns one revision-pinned deterministic Resource Group page.
func (service *Service) ListGroups(
	ctx context.Context, session accountsession.Session, scope network.Scope,
	state resource.State, limit int, cursor PageCursor,
) (_ GroupPage, resultErr error) {
	if ctx == nil || service == nil || !validListRequest(session, scope, state, limit, cursor) {
		return GroupPage{}, ErrInvalidRequest
	}
	transaction, closeTransaction, err := service.begin(ctx, scope)
	if err != nil {
		return GroupPage{}, err
	}
	defer func() {
		if closeTransaction != nil {
			closeTransaction(&resultErr)
		}
	}()
	if err = transaction.Authorize(ctx, session, authorization.PermissionResourceGroupRead, service.clock.Now().UTC()); err != nil {
		return GroupPage{}, err
	}
	_, groupRevision, err := transaction.Revisions(ctx)
	if err != nil {
		return GroupPage{}, err
	}
	if cursor.IsValid() && cursor.Revision() != groupRevision {
		return GroupPage{}, ErrConflict
	}
	after := publicid.ID{}
	if cursor.IsValid() {
		after = cursor.After()
	}
	items, err := transaction.Groups(ctx, state, after, limit+1)
	if err != nil {
		return GroupPage{}, err
	}
	if len(items) > limit+1 {
		return GroupPage{}, ErrInvalidResult
	}
	page := GroupPage{Items: items, Revision: groupRevision}
	if len(items) > limit {
		page.Items = items[:limit]
		page.Next, err = NewPageCursor(groupRevision, publicid.ID(page.Items[limit-1].ID()))
		if err != nil {
			return GroupPage{}, ErrInvalidResult
		}
	}
	if err = validateGroupPage(page, scope); err != nil {
		return GroupPage{}, err
	}
	if err = transaction.Commit(ctx); err != nil {
		return GroupPage{}, err
	}
	closeTransaction = nil
	return page, nil
}

func (service *Service) begin(
	ctx context.Context, scope network.Scope,
) (Transaction, func(*error), error) {
	transaction, err := service.transactions.Begin(ctx, scope)
	if err != nil || transaction == nil {
		return nil, nil, errors.Join(ErrUnavailable, err)
	}
	closeTransaction := func(resultErr *error) {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackWindow)
		defer cancel()
		if rollbackErr := transaction.Rollback(rollbackCtx); rollbackErr != nil {
			*resultErr = errors.Join(*resultErr, ErrUnavailable, rollbackErr)
		}
	}
	return transaction, closeTransaction, nil
}

func validListRequest(
	session accountsession.Session, scope network.Scope, state resource.State, limit int, cursor PageCursor,
) bool {
	return session.IsValid() && scope.IsValid() &&
		(state == resource.StateUnknown || validState(state)) && limit > 0 && limit <= MaximumPageSize &&
		(cursor == PageCursor{} || cursor.IsValid())
}

func validateResourcePage(page ResourcePage, scope network.Scope) error {
	if page.Revision <= 0 || len(page.Items) > MaximumPageSize {
		return ErrInvalidResult
	}
	for index, item := range page.Items {
		if !item.IsValid() || item.Scope() != scope ||
			(index > 0 && page.Items[index-1].ID().String() >= item.ID().String()) {
			return ErrInvalidResult
		}
	}
	return nil
}

func validateGroupPage(page GroupPage, scope network.Scope) error {
	if page.Revision <= 0 || len(page.Items) > MaximumPageSize {
		return ErrInvalidResult
	}
	for index, item := range page.Items {
		if !item.IsValid() || item.Scope() != scope ||
			(index > 0 && page.Items[index-1].ID().String() >= item.ID().String()) {
			return ErrInvalidResult
		}
	}
	return nil
}

// SystemClock reads wall time without retaining mutable state.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }
