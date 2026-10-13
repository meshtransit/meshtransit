package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/ipam"
)

// examineAddressPrefixes finds, for each address family the Device does not
// hold yet, the lowest free address of the first prefix (in lock order) that
// has one. Prefixes after it are not examined: allocation would not use them.
func (transaction *registrationTransaction) examineAddressPrefixes(
	ctx context.Context,
	locked *registrationLockedState,
) error {
	for _, family := range [...]int{4, 6} {
		if _, held := locked.activeLeaseFamilies[family]; held {
			continue
		}
		for index := range locked.prefixes {
			prefix := &locked.prefixes[index]
			if prefix.family != family {
				continue
			}
			if err := transaction.examineAddressPrefix(ctx, prefix); err != nil {
				return err
			}
			if prefix.free.IsValid() {
				break
			}
		}
	}
	return nil
}

// examineAddressPrefix locks the prefix's floor and finds its lowest free
// address (schema 157): the lowest lease below the floor whose quarantine
// ended, or else the first address at or after the floor that no live lease
// holds. It records the floor to store once that address is leased: every
// address below it is then held by a settled lease.
func (transaction *registrationTransaction) examineAddressPrefix(
	ctx context.Context,
	prefix *registrationPrefix,
) error {
	first := prefix.prefix.Addr().Next()
	if !first.IsValid() || !prefix.prefix.Contains(first) {
		return ErrRegistrationEvidence
	}
	floor, err := transaction.lockAddressFloor(ctx, prefix, first)
	if err != nil {
		return err
	}
	prefix.examined = true
	if floor.Compare(first) > 0 {
		reclaimable, found, err := transaction.lowestReclaimableAddress(ctx, prefix, first, floor)
		if err != nil {
			return err
		}
		if found {
			// The reclaimed address is settled again once leased, and the
			// release of its old lease lowers the floor to it: restore it.
			prefix.free, prefix.nextFloor = reclaimable, floor
			return nil
		}
	}
	walk, err := transaction.walkLiveLeases(ctx, prefix, floor)
	if err != nil {
		return err
	}
	prefix.free = walk.free
	next := walk.end
	if walk.free.IsValid() {
		next = walk.free.Next()
	}
	if walk.unsettled.IsValid() && walk.unsettled.Compare(next) < 0 {
		next = walk.unsettled
	}
	if next.IsValid() && next.Compare(floor) > 0 {
		prefix.nextFloor = next
	}
	return nil
}

// lockAddressFloor locks the prefix's floor, creating it at the first host
// when missing. A floor stored for another prefix value, or below the first
// host, counts as the first host.
func (transaction *registrationTransaction) lockAddressFloor(
	ctx context.Context,
	prefix *registrationPrefix,
	first netip.Addr,
) (netip.Addr, error) {
	for range 2 {
		var floorValue, prefixValue string
		err := transaction.database.QueryRow(ctx, lockRegistrationAddressFloorSQL, prefix.internalID).
			Scan(&floorValue, &prefixValue)
		if errors.Is(err, pgx.ErrNoRows) {
			if _, err := transaction.database.Exec(
				ctx,
				insertRegistrationAddressFloorSQL,
				transaction.workspaceInternalID,
				transaction.networkInternalID,
				prefix.internalID,
				prefix.prefix.String(),
				hostPrefix(first),
			); err != nil {
				return netip.Addr{}, fmt.Errorf("create address floor: %w", err)
			}
			continue
		}
		if err != nil {
			return netip.Addr{}, fmt.Errorf("lock address floor: %w", err)
		}
		floor, err := netip.ParseAddr(floorValue)
		if err != nil || floor.Is4() != first.Is4() || floor.Is4In6() || floor.Zone() != "" {
			return netip.Addr{}, ErrRegistrationEvidence
		}
		stored, err := netip.ParsePrefix(prefixValue)
		if err != nil || stored != prefix.prefix || floor.Compare(first) < 0 {
			return first, nil
		}
		return floor, nil
	}
	return netip.Addr{}, ErrRegistrationEvidence
}

func (transaction *registrationTransaction) lowestReclaimableAddress(
	ctx context.Context,
	prefix *registrationPrefix,
	first, floor netip.Addr,
) (netip.Addr, bool, error) {
	var value string
	err := transaction.database.QueryRow(
		ctx,
		lowestReclaimableRegistrationAddressSQL,
		prefix.internalID,
		hostPrefix(first),
		hostPrefix(floor),
	).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return netip.Addr{}, false, nil
	}
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("find reclaimable address: %w", err)
	}
	address, err := registrationAddressValue(value, prefix.family, prefix.prefix)
	if err != nil {
		return netip.Addr{}, false, err
	}
	if address.Compare(first) < 0 || address.Compare(floor) >= 0 {
		return netip.Addr{}, false, ErrRegistrationEvidence
	}
	return address, true, nil
}

// leaseWalk is what walkLiveLeases found: the first free address (invalid
// when the prefix is full), where the walk ended (the free address, or the
// first address past the prefix's hosts), and the first live lease it passed
// that does not settle the floor (invalid when none).
type leaseWalk struct {
	free      netip.Addr
	end       netip.Addr
	unsettled netip.Addr
}

// walkLiveLeases reads the prefix's live leases in address order from start,
// one window at a time, until an address no live lease holds. The floor is
// normally free itself, so this is one read of no rows.
func (transaction *registrationTransaction) walkLiveLeases(
	ctx context.Context,
	prefix *registrationPrefix,
	start netip.Addr,
) (leaseWalk, error) {
	var walk leaseWalk
	candidate := start
	for {
		if !registrationHost(prefix.prefix, candidate) {
			walk.end = candidate
			return walk, nil
		}
		passed, contiguous, err := transaction.walkLeaseWindow(ctx, prefix, &candidate, &walk)
		if err != nil {
			return leaseWalk{}, err
		}
		if !contiguous || passed < transaction.candidateLimit {
			if registrationHost(prefix.prefix, candidate) {
				walk.free = candidate
			}
			walk.end = candidate
			return walk, nil
		}
	}
}

// walkLeaseWindow reads one window of live leases from *candidate and moves
// *candidate past those that hold it in a row. It reports how many leases it
// passed and whether the whole window was contiguous.
func (transaction *registrationTransaction) walkLeaseWindow(
	ctx context.Context,
	prefix *registrationPrefix,
	candidate *netip.Addr,
	walk *leaseWalk,
) (int, bool, error) {
	rows, err := transaction.database.Query(
		ctx,
		loadRegistrationLeasesSQL,
		prefix.internalID,
		transaction.candidateLimit,
		hostPrefix(*candidate),
	)
	if err != nil {
		return 0, false, fmt.Errorf("load address allocation window: %w", err)
	}
	defer rows.Close()
	passed := 0
	for rows.Next() {
		address, unsettled, err := scanRegistrationLease(rows, prefix)
		if err != nil {
			return 0, false, err
		}
		if address.Compare(*candidate) < 0 {
			return 0, false, ErrRegistrationEvidence
		}
		if address != *candidate {
			return passed, false, nil
		}
		if unsettled && !walk.unsettled.IsValid() {
			walk.unsettled = address
		}
		passed++
		*candidate = candidate.Next()
		if !candidate.IsValid() {
			return 0, false, ErrRegistrationEvidence
		}
	}
	if err := rows.Err(); err != nil {
		return 0, false, fmt.Errorf("read address allocation window: %w", err)
	}
	return passed, true, nil
}

func scanRegistrationLease(rows registrationRows, prefix *registrationPrefix) (netip.Addr, bool, error) {
	var prefixInternalID, deviceInternalID int64
	var addressValue, leaseRole, state string
	var family int
	var unsettled bool
	if err := rows.Scan(
		&prefixInternalID,
		&deviceInternalID,
		&addressValue,
		&family,
		&leaseRole,
		&state,
		&unsettled,
	); err != nil {
		return netip.Addr{}, false, fmt.Errorf("scan address allocation window: %w", err)
	}
	if prefixInternalID != prefix.internalID || deviceInternalID <= 0 ||
		family != prefix.family ||
		(leaseRole != "primary" && leaseRole != "secondary" && leaseRole != "draining") ||
		(state != "active" && state != "quarantined") ||
		(unsettled && state != "active") {
		return netip.Addr{}, false, ErrRegistrationEvidence
	}
	address, err := registrationAddressValue(addressValue, family, prefix.prefix)
	if err != nil {
		return netip.Addr{}, false, err
	}
	return address, unsettled, nil
}

// registrationHost reports whether address is a host of prefix that
// registration may lease.
func registrationHost(prefix netip.Prefix, address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	_, err := ipam.NextAvailableAddressFrom(prefix, address, nil, 1)
	return err == nil
}

// storeAddressFloors stores the floors that examination found, once the
// leases are written. The transaction still holds each floor's row lock.
func (transaction *registrationTransaction) storeAddressFloors(ctx context.Context) error {
	for _, prefix := range transaction.locked.prefixes {
		if !prefix.examined || !prefix.nextFloor.IsValid() {
			continue
		}
		result, err := transaction.database.Exec(
			ctx,
			storeRegistrationAddressFloorSQL,
			prefix.internalID,
			hostPrefix(prefix.nextFloor),
			prefix.prefix.String(),
		)
		if err != nil {
			return fmt.Errorf("store address floor: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrRegistrationEvidence
		}
	}
	return nil
}
