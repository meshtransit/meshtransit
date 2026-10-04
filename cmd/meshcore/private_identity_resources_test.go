package main

import (
	"context"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// Composition fixture has no authority; resource operations fail closed.
type privateIdentityResourcePorts struct{}

func (privateIdentityResourcePorts) GetContract(context.Context, accountsession.Session, network.Scope, sharing.ContractID) (sharing.ContractSnapshot, error) {
	return sharing.ContractSnapshot{}, sharing.ErrUnavailable
}

func (privateIdentityResourcePorts) Create(context.Context, authority.Command) (authority.Result, error) {
	return authority.Result{}, authority.ErrMutationFailed
}
func (privateIdentityResourcePorts) GetResource(context.Context, accountsession.Session, network.Scope, resource.ID) (catalog.Resource, error) {
	return catalog.Resource{}, catalog.ErrUnavailable
}
func (privateIdentityResourcePorts) ListResources(context.Context, accountsession.Session, network.Scope, resource.State, int, catalog.PageCursor) (catalog.ResourcePage, error) {
	return catalog.ResourcePage{}, catalog.ErrUnavailable
}
func (privateIdentityResourcePorts) GetGroup(context.Context, accountsession.Session, network.Scope, resource.GroupID) (catalog.Group, error) {
	return catalog.Group{}, catalog.ErrUnavailable
}
func (privateIdentityResourcePorts) ListGroups(context.Context, accountsession.Session, network.Scope, resource.State, int, catalog.PageCursor) (catalog.GroupPage, error) {
	return catalog.GroupPage{}, catalog.ErrUnavailable
}
func (privateIdentityResourcePorts) CreateOffer(context.Context, sharing.CreateOffer) (sharing.MutationResult, error) {
	return sharing.MutationResult{}, sharing.ErrUnavailable
}
func (privateIdentityResourcePorts) DecideOffer(context.Context, sharing.DecideOffer) (sharing.MutationResult, error) {
	return sharing.MutationResult{}, sharing.ErrUnavailable
}
func (privateIdentityResourcePorts) ActivateContract(context.Context, sharing.ActivateContract) (sharing.MutationResult, error) {
	return sharing.MutationResult{}, sharing.ErrUnavailable
}
func (privateIdentityResourcePorts) RevokeContract(context.Context, sharing.RevokeContract) (sharing.MutationResult, error) {
	return sharing.MutationResult{}, sharing.ErrUnavailable
}
func (privateIdentityResourcePorts) GetOffer(context.Context, accountsession.Session, network.Scope, sharing.OfferID) (sharing.OfferSnapshot, error) {
	return sharing.OfferSnapshot{}, sharing.ErrUnavailable
}
func (privateIdentityResourcePorts) ListOffers(context.Context, accountsession.Session, network.Scope, sharing.Direction, sharing.OfferState, int, sharing.PageCursor) (sharing.OfferPage, error) {
	return sharing.OfferPage{}, sharing.ErrUnavailable
}
