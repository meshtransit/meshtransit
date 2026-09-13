package postgres

import (
	"context"
	"errors"
	"net/netip"

	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/ipam"
)

type registrationLease struct {
	prefix  registrationPrefix
	address netip.Addr
	family  int
}

func (transaction *registrationTransaction) allocateRegistrationLeases() ([]registrationLease, error) {
	allocated := make([]registrationLease, 0, 2)
	activeFamilies := len(transaction.locked.activeLeaseFamilies)
	for _, family := range [...]int{4, 6} {
		if _, exists := transaction.locked.activeLeaseFamilies[family]; exists {
			continue
		}
		familyAvailable := false
		allocatedBefore := len(allocated)
		for _, prefix := range transaction.locked.prefixes {
			if prefix.family != family {
				continue
			}
			familyAvailable = true
			address, err := ipam.NextAvailableAddress(
				prefix.prefix,
				prefix.occupied,
				transaction.candidateLimit,
			)
			if errors.Is(err, ipam.ErrAddressExhausted) {
				continue
			}
			if err != nil {
				return nil, errors.Join(ErrRegistrationAllocation, err)
			}
			allocated = append(allocated, registrationLease{
				prefix:  prefix,
				address: address,
				family:  family,
			})
			break
		}
		if familyAvailable && len(allocated) == allocatedBefore {
			return nil, errors.Join(ErrRegistrationAllocation, ipam.ErrAddressExhausted)
		}
	}
	if len(allocated)+activeFamilies == 0 {
		return nil, ErrRegistrationAllocation
	}
	return allocated, nil
}

func (transaction *registrationTransaction) persistRegistrationLeases(
	ctx context.Context,
	change registration.Change,
	deviceInternalID int64,
	leases []registrationLease,
) error {
	for _, lease := range leases {
		leaseID := change.MutationIDs().IPv4LeaseID()
		if lease.family == 6 {
			leaseID = change.MutationIDs().IPv6LeaseID()
		}
		if err := transaction.execRegistrationInsert(
			ctx,
			"create Node address lease",
			insertRegistrationLeaseSQL,
			leaseID.String(),
			transaction.workspaceInternalID,
			transaction.networkInternalID,
			lease.prefix.realmInternalID,
			lease.prefix.poolInternalID,
			lease.prefix.internalID,
			deviceInternalID,
			lease.address.String(),
			lease.family,
			change.OccurredAt(),
		); err != nil {
			return err
		}
	}
	return nil
}
