package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"meshtransit.net/core/internal/domain/node"
)

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

// selectHostname chooses requested's lowest numbered variant that no other
// live Device of the Network holds, as node.NextAvailableHostname would over
// every hostname of the Network. It looks candidates up in growing batches
// through the hostname unique index, so a free requested name costs one
// probe. The caller holds the Network revision lock, which serializes
// registrations of the Network; the unique index stays the final arbiter.
func (transaction *registrationTransaction) selectHostname(
	ctx context.Context,
	locked *registrationLockedState,
	requested node.Hostname,
) error {
	var excludedDeviceID any
	if locked.device.internalID > 0 {
		excludedDeviceID = locked.device.internalID
	}
	for from, count := 0, 1; from <= node.MaximumHostnameFamily; from, count = from+count, count*hostnameBatchGrowth {
		count = min(count, node.MaximumHostnameFamily+1-from)
		candidates, err := node.HostnameCandidates(requested, from, count)
		if err != nil {
			return errors.Join(ErrRegistrationAllocation, err)
		}
		taken, err := transaction.takenHostnames(ctx, candidates, excludedDeviceID, locked.hostnameOwner)
		if err != nil {
			return err
		}
		for _, candidate := range candidates {
			if _, exists := taken[candidate.String()]; !exists {
				locked.hostname = candidate
				return nil
			}
		}
	}
	return ErrRegistrationAllocation
}

// hostnameBatchGrowth sizes the candidate batches 1, 16, 256, ...: the
// requested name alone first, then fewer round trips for a large family.
const hostnameBatchGrowth = 16

func (transaction *registrationTransaction) takenHostnames(
	ctx context.Context,
	candidates []node.Hostname,
	excludedDeviceID any,
	owner int64,
) (map[string]struct{}, error) {
	if owner <= 0 {
		return nil, ErrRegistrationEvidence
	}
	values := make([]string, len(candidates))
	for index, candidate := range candidates {
		values[index] = candidate.String()
	}
	rows, err := transaction.database.Query(
		ctx,
		registrationHostnamesTakenSQL,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		values,
		excludedDeviceID,
		owner,
	)
	if err != nil {
		return nil, fmt.Errorf("look up candidate hostnames: %w", err)
	}
	defer rows.Close()
	taken := make(map[string]struct{}, len(candidates))
	for rows.Next() {
		if len(taken) == len(candidates) {
			return nil, ErrRegistrationEvidence
		}
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan candidate hostname: %w", err)
		}
		taken[value] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read candidate hostnames: %w", err)
	}
	return taken, nil
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
	if err := transaction.lockDeviceLeaseFamilies(ctx, locked); err != nil {
		return err
	}
	return transaction.examineAddressPrefixes(ctx, locked)
}

// lockDeviceLeaseFamilies locks a resumed Device's primary leases and
// records their families, which it keeps.
func (transaction *registrationTransaction) lockDeviceLeaseFamilies(
	ctx context.Context,
	locked *registrationLockedState,
) error {
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

// hostPrefix writes address as a host route (/32 or /128), the form leases
// are stored in.
func hostPrefix(address netip.Addr) string {
	return netip.PrefixFrom(address, address.BitLen()).String()
}

// releaseHostname frees hostname from a revoked Device that may give it up
// (releasableHostnamePredicate) right before the registration writes it.
// It runs after the change context is set, so the audit captures it.
func (transaction *registrationTransaction) releaseHostname(
	ctx context.Context,
	hostname node.Hostname,
) error {
	var excludedDeviceID any
	if transaction.locked.device.internalID > 0 {
		excludedDeviceID = transaction.locked.device.internalID
	}
	if transaction.locked.hostnameOwner <= 0 {
		return ErrRegistrationEvidence
	}
	result, err := transaction.database.Exec(
		ctx,
		releaseRegistrationHostnameSQL,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		hostname.String(),
		excludedDeviceID,
		transaction.locked.hostnameOwner,
	)
	if err != nil {
		return fmt.Errorf("release hostname of a revoked Device: %w", err)
	}
	if result.RowsAffected() > 1 {
		return ErrRegistrationEvidence // hostname keys are unique among live rows
	}
	return nil
}
