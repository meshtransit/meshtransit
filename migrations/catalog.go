// Package migrations owns the immutable, forward-only MeshTransit database
// migration catalog embedded in the meshcore binary.
package migrations

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

const (
	// ApplicationGeneration is the reader and writer generation implemented by
	// this binary. It advances only with a reviewed compatibility change.
	ApplicationGeneration int64 = 1

	platformFoundationDescription    = "platform migration foundation"
	authorityFoundationDescription   = "tenancy and address authority foundation"
	integrityFoundationDescription   = "audit and outbox integrity foundation"
	outboxDeliveryDescription        = "outbox worker delivery capability"
	registrationAuthorityDescription = "node enrollment and registration authority"
)

//go:embed 000001_platform_foundation.up.sql
var platformFoundationSQL string

//go:embed 000002_tenancy_address_authority.up.sql
var authorityFoundationSQL string

//go:embed 000003_audit_outbox_integrity.up.sql
var integrityFoundationSQL string

//go:embed 000004_outbox_worker_delivery.up.sql
var outboxDeliverySQL string

//go:embed 000005_node_enrollment_registration.up.sql
var registrationAuthoritySQL string

// Migration is one immutable, ordered, forward-only catalog entry.
type Migration struct {
	Version                 int64
	Description             string
	Checksum                string
	SQL                     string
	MinimumReaderGeneration int64
	MaximumReaderGeneration int64
	MinimumWriterGeneration int64
	MaximumWriterGeneration int64
}

// Catalog returns a caller-owned copy of the complete ordered catalog.
func Catalog() []Migration {
	return []Migration{
		newMigration(1, platformFoundationDescription, platformFoundationSQL),
		newMigration(2, authorityFoundationDescription, authorityFoundationSQL),
		newMigration(3, integrityFoundationDescription, integrityFoundationSQL),
		newMigration(4, outboxDeliveryDescription, outboxDeliverySQL),
		newMigration(5, registrationAuthorityDescription, registrationAuthoritySQL),
	}
}

// LatestVersion returns the latest schema version known to this binary.
func LatestVersion() int64 {
	catalog := Catalog()
	return catalog[len(catalog)-1].Version
}

func newMigration(version int64, description, sql string) Migration {
	digest := sha256.Sum256([]byte(sql))
	return Migration{
		Version:                 version,
		Description:             description,
		Checksum:                hex.EncodeToString(digest[:]),
		SQL:                     sql,
		MinimumReaderGeneration: ApplicationGeneration,
		MaximumReaderGeneration: ApplicationGeneration,
		MinimumWriterGeneration: ApplicationGeneration,
		MaximumWriterGeneration: ApplicationGeneration,
	}
}
