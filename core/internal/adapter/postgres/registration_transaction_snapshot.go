package postgres

import (
	"context"
	"fmt"
	"net/netip"

	"meshtransit.net/core/internal/domain/node"
)

const maxRegistrationHostnameSnapshot = node.MaximumHostnameFamily

func (transaction *registrationTransaction) lockAuditHead(
	ctx context.Context,
	locked *registrationLockedState,
) error {
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockRegistrationAuditStreamSQL).Scan(
		&locked.audit.streamInternalID,
		&locked.audit.nextSequence,
		&previousHash,
	); err != nil {
		return fmt.Errorf("lock audit stream: %w", err)
	}
	if locked.audit.streamInternalID <= 0 || locked.audit.nextSequence <= 0 || len(previousHash) != 32 {
		return ErrRegistrationEvidence
	}
	copy(locked.audit.previousHash[:], previousHash)
	return nil
}

func (transaction *registrationTransaction) loadHostnames(
	ctx context.Context,
	locked *registrationLockedState,
	requested node.Hostname,
) error {
	var excludedDeviceID any
	if locked.device.internalID > 0 {
		excludedDeviceID = locked.device.internalID
	}
	family, err := node.HostnameFamilyPrefix(requested)
	if err != nil {
		return ErrRegistrationAllocation
	}
	rows, err := transaction.database.Query(
		ctx,
		loadRegistrationHostnamesSQL,
		excludedDeviceID,
		maxRegistrationHostnameSnapshot+1,
		family,
	)
	if err != nil {
		return fmt.Errorf("load hostname allocation snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		if len(locked.hostnames) == maxRegistrationHostnameSnapshot {
			return ErrRegistrationAllocation
		}
		var value string
		if err := rows.Scan(&value); err != nil {
			return fmt.Errorf("scan hostname allocation snapshot: %w", err)
		}
		hostname, err := node.ParseHostname(value)
		if err != nil {
			return ErrRegistrationEvidence
		}
		locked.hostnames = append(locked.hostnames, hostname)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read hostname allocation snapshot: %w", err)
	}
	return nil
}

func (transaction *registrationTransaction) lockAddressState(
	ctx context.Context,
	locked *registrationLockedState,
) error {
	rows, err := transaction.database.Query(
		ctx,
		lockRegistrationPrefixesSQL,
		maxRegistrationPrefixCount+1,
	)
	if err != nil {
		return fmt.Errorf("lock address prefixes: %w", err)
	}
	for rows.Next() {
		if len(locked.prefixes) == maxRegistrationPrefixCount {
			rows.Close()
			return ErrRegistrationAllocation
		}
		var record registrationPrefix
		var prefixValue string
		if err := rows.Scan(
			&record.internalID,
			&record.realmInternalID,
			&record.poolInternalID,
			&prefixValue,
			&record.family,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan address prefix: %w", err)
		}
		record.prefix, err = registrationPrefixValue(prefixValue, record.family)
		if err != nil || record.internalID <= 0 || record.realmInternalID <= 0 || record.poolInternalID <= 0 {
			rows.Close()
			return ErrRegistrationEvidence
		}
		locked.prefixes = append(locked.prefixes, record)
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return fmt.Errorf("read address prefixes: %w", readErr)
	}
	if len(locked.prefixes) == 0 {
		return ErrRegistrationAllocation
	}
	for index := range locked.prefixes {
		if err := transaction.loadPrefixLeases(ctx, &locked.prefixes[index]); err != nil {
			return err
		}
	}
	locked.activeLeaseFamilies = make(map[int]struct{}, 2)
	if locked.device.internalID <= 0 {
		return nil
	}
	leaseRows, err := transaction.database.Query(
		ctx,
		lockRegistrationDeviceLeasesSQL,
		locked.device.internalID,
	)
	if err != nil {
		return fmt.Errorf("lock existing Device leases: %w", err)
	}
	defer leaseRows.Close()
	for leaseRows.Next() {
		var family int
		if err := leaseRows.Scan(&family); err != nil {
			return fmt.Errorf("scan existing Device lease: %w", err)
		}
		if family != 4 && family != 6 {
			return ErrRegistrationEvidence
		}
		if _, duplicate := locked.activeLeaseFamilies[family]; duplicate {
			return ErrRegistrationEvidence
		}
		locked.activeLeaseFamilies[family] = struct{}{}
	}
	if err := leaseRows.Err(); err != nil {
		return fmt.Errorf("read existing Device leases: %w", err)
	}
	return nil
}

func (transaction *registrationTransaction) loadPrefixLeases(
	ctx context.Context,
	prefix *registrationPrefix,
) error {
	start, err := transaction.lowestFreeAddress(ctx, prefix)
	if err != nil {
		return err
	}
	prefix.searchStart = start
	rows, err := transaction.database.Query(
		ctx,
		loadRegistrationLeasesSQL,
		prefix.internalID,
		transaction.candidateLimit+1,
		hostPrefix(start),
	)
	if err != nil {
		return fmt.Errorf("load address allocation snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		if len(prefix.occupied) == transaction.candidateLimit {
			return nil
		}
		var prefixInternalID, deviceInternalID int64
		var addressValue, leaseRole, state string
		var family int
		if err := rows.Scan(
			&prefixInternalID,
			&deviceInternalID,
			&addressValue,
			&family,
			&leaseRole,
			&state,
		); err != nil {
			return fmt.Errorf("scan address allocation snapshot: %w", err)
		}
		if prefixInternalID != prefix.internalID || deviceInternalID <= 0 ||
			family != prefix.family ||
			(leaseRole != "primary" && leaseRole != "secondary" && leaseRole != "draining") ||
			(state != "active" && state != "quarantined") {
			return ErrRegistrationEvidence
		}
		address, err := registrationAddressValue(addressValue, family, prefix.prefix)
		if err != nil {
			return err
		}
		prefix.occupied = append(prefix.occupied, address)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read address allocation snapshot: %w", err)
	}
	return nil
}

// lowestFreeAddress returns the lowest address of prefix that no live lease
// holds, which may lie past the prefix when every host is taken.
func (transaction *registrationTransaction) lowestFreeAddress(
	ctx context.Context,
	prefix *registrationPrefix,
) (netip.Addr, error) {
	first := prefix.prefix.Addr().Next()
	if !first.IsValid() {
		return netip.Addr{}, ErrRegistrationEvidence
	}
	var value string
	if err := transaction.database.QueryRow(
		ctx,
		lowestFreeRegistrationAddressSQL,
		prefix.internalID,
		hostPrefix(first),
	).Scan(&value); err != nil {
		return netip.Addr{}, fmt.Errorf("find lowest free address: %w", err)
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Is4() != first.Is4() || address.Compare(first) < 0 {
		return netip.Addr{}, ErrRegistrationEvidence
	}
	return address, nil
}

// hostPrefix writes address as a host route (/32 or /128), the form leases
// are stored in.
func hostPrefix(address netip.Addr) string {
	return netip.PrefixFrom(address, address.BitLen()).String()
}
