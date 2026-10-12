package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/ipam"
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
			address, err := ipam.NextAvailableAddressFrom(
				prefix.prefix,
				prefix.searchStart,
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
		if err := releaseReclaimedRegistrationLease(ctx, transaction.database, lease, change.OccurredAt()); err != nil {
			return err
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

// releaseReclaimedRegistrationLease releases a lease whose quarantine has
// ended if it holds the address about to be leased; most addresses have none.
func releaseReclaimedRegistrationLease(
	ctx context.Context,
	database registrationDatabaseTransaction,
	lease registrationLease,
	at time.Time,
) error {
	result, err := database.Exec(ctx, releaseReclaimedRegistrationLeaseSQL,
		lease.prefix.internalID, lease.address.String(), at)
	if err != nil {
		return fmt.Errorf("release reclaimed Node address lease: %w", err)
	}
	if result.RowsAffected() > 1 {
		return fmt.Errorf("release reclaimed Node address lease: %w", ErrRegistrationEvidence)
	}
	return nil
}
