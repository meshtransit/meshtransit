package registrationintake

import (
	"context"
	"fmt"
)

func (transaction *transaction) lockRevision(ctx context.Context) (int64, error) {
	var networkRevision, inventoryRevision, group, policy, dns, route, sharing, isolation int64
	if err := transaction.database.QueryRow(ctx, lockRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
		&group,
		&policy,
		&dns,
		&route,
		&sharing,
		&isolation,
	); err != nil {
		return 0, fmt.Errorf("lock Network revision: %w", err)
	}
	for _, value := range [...]int64{
		networkRevision,
		inventoryRevision,
		group,
		policy,
		dns,
		route,
		sharing,
		isolation,
	} {
		if value <= 0 {
			return 0, ErrEvidence
		}
	}
	return networkRevision, nil
}
