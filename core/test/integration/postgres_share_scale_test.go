//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	publication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/resource/authority"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/sharing/devicealias"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/idempotency"
)

// Share scale load test (share scale plan step 4, TD-CORE-07). Opt-in:
// MESHTRANSIT_SHARE_SCALE=N builds, on the database TestPostgreSQLMigrations
// prepared, N same-Workspace Device shares from Network 203 into Network 204
// through the production writers: N provider Devices with keys and
// addresses, N Device Resources, N offers accepted and activated, one policy
// release with a rule from one consumer Device to every share, and the alias
// worker's reserve and ready for each. It then measures one map read of the
// consumer Device (N shares) and of a provider Device, and the SQL readers.
// MESHTRANSIT_SHARE_SCALE_REPORT names a JSON file for the results.
const (
	shareScaleWorkspace = int64(103)
	shareScaleProvider  = int64(203)
	shareScaleConsumer  = int64(204)
	// shareScaleDeviceBase offsets the seeded Devices' internal IDs past
	// every fixture.
	shareScaleDeviceBase = int64(5_000_000)
)

type shareScaleDevice struct {
	id       int64
	publicID string
	machine  node.MachineKey
	key      node.Key
	address  netip.Addr
	address6 netip.Addr
}

type shareScaleReport struct {
	Shares            int                `json:"shares"`
	DualStack         bool               `json:"dual_stack"`
	SetupSeconds      map[string]float64 `json:"setup_seconds"`
	ReadyMilliseconds map[string]float64 `json:"ready_ms"`
	ConsumerMap       shareScaleRead     `json:"consumer_map"`
	ProviderMap       shareScaleRead     `json:"provider_map"`
	// Readers holds each SQL reader's time for the receiving Device and for
	// one providing Device, keyed "consumer alias v6" and so on.
	Readers           map[string]shareScaleReader `json:"readers"`
	LegacyReaderError string                      `json:"legacy_reader_error"`
}

type shareScaleReader struct {
	Milliseconds float64 `json:"ms"`
	Rows         int     `json:"rows"`
}

type shareScaleRead struct {
	Milliseconds []float64 `json:"ms"`
	Projections  int       `json:"projections"`
	Peers        int       `json:"peers"`
	DNSRecords   int       `json:"dns_records"`
	Limited      bool      `json:"limited"`
}

func TestPostgreSQLShareScale(t *testing.T) {
	count, err := strconv.Atoi(os.Getenv("MESHTRANSIT_SHARE_SCALE"))
	if err != nil || count <= 0 {
		t.Skip("set MESHTRANSIT_SHARE_SCALE=N on a database TestPostgreSQLMigrations prepared")
	}
	if count > mapsession.MaximumDirectDeviceProjections {
		t.Fatalf("MESHTRANSIT_SHARE_SCALE=%d is above the share limit", count)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Hour)
	defer cancel()
	adminConfig := loadIntegrationAdminConfig(t)
	admin := openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database, adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile, adminConfig.ConnectTimeout)
	runtimePool := openShareScaleRuntimePool(ctx, t)
	workerPool := openIntegrationWorkerPool(ctx, t, adminConfig)
	report := shareScaleReport{Shares: count, SetupSeconds: map[string]float64{}, ReadyMilliseconds: map[string]float64{}}
	step := func(name string, run func()) {
		started := time.Now()
		run()
		report.SetupSeconds[name] = time.Since(started).Seconds()
		t.Logf("%s: %v", name, time.Since(started).Round(time.Millisecond))
	}

	var providers []shareScaleDevice
	var consumer shareScaleDevice
	var dualStack bool
	step("seed devices", func() { providers, consumer, dualStack = seedShareScaleDevices(ctx, t, admin, count) })
	step("seed alias pools", func() { seedShareScaleAliasPools(ctx, t, admin, dualStack) })
	report.DualStack = dualStack
	logShareScaleAuthority(ctx, t, admin)
	session := shareScaleSession(ctx, t, admin)
	var resources []resource.ID
	step("create resources", func() { resources = createShareScaleResources(ctx, t, admin, runtimePool, session, providers) })
	var contracts []sharing.Contract
	step("create shares", func() { contracts = createShareScaleShares(ctx, t, runtimePool, session, resources) })
	if os.Getenv("MESHTRANSIT_SHARE_SCALE_PUBLISH") != "" {
		// Publish the rules through Core's publication path instead of SQL.
		step("publish rules", func() {
			seedShareScaleRelease(ctx, t, admin, consumer, false)
			publishShareScaleRules(ctx, t, runtimePool, session, consumer, contracts)
		})
	} else {
		step("publish rules", func() { seedShareScaleRelease(ctx, t, admin, consumer, true) })
	}
	// Bulk-loaded tables have no statistics until autovacuum analyzes them;
	// measure the steady state (MESHTRANSIT_SHARE_SCALE_COLD=1 skips this).
	if os.Getenv("MESHTRANSIT_SHARE_SCALE_COLD") == "" {
		step("analyze", func() {
			if _, err := admin.Exec(ctx, `ANALYZE`); err != nil {
				t.Fatal(err)
			}
		})
	}
	var readyTimes []time.Duration
	step("alias reserve and ready", func() { readyTimes = readyShareScaleAliases(ctx, t, admin, workerPool, consumer, contracts) })
	report.ReadyMilliseconds = shareScaleTimes(readyTimes)

	report.Readers = map[string]shareScaleReader{}
	report.LegacyReaderError = measureShareScaleReaders(ctx, t, admin, "consumer", consumer, report.Readers)
	measureShareScaleReaders(ctx, t, admin, "provider", providers[0], report.Readers)
	report.ConsumerMap = measureShareScaleMap(ctx, t, runtimePool, consumer)
	report.ProviderMap = measureShareScaleMap(ctx, t, runtimePool, providers[0])
	if report.ConsumerMap.Projections != count || report.ProviderMap.Projections != 1 {
		t.Fatalf("consumer map has %d of %d shares, provider map %d of 1",
			report.ConsumerMap.Projections, count, report.ProviderMap.Projections)
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	t.Logf("share scale report:\n%s", encoded)
	if path := os.Getenv("MESHTRANSIT_SHARE_SCALE_REPORT"); path != "" {
		if err := os.WriteFile(path, encoded, 0o600); err != nil { //nolint:gosec // the operator names the report file
			t.Errorf("write share scale report: %v", err)
		}
	}
}

func openShareScaleRuntimePool(ctx context.Context, t *testing.T) *postgresadapter.Pool {
	t.Helper()
	processConfig, err := config.Load(os.LookupEnv)
	if err != nil || processConfig.Storage == nil || processConfig.Storage.PostgreSQL.Runtime == nil {
		t.Fatalf("runtime configuration: %v", err)
	}
	postgresConfig := processConfig.Storage.PostgreSQL
	runtime := *postgresConfig.Runtime
	pool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role: postgresadapter.PoolRoleRuntime, Address: postgresConfig.Address, Database: postgresConfig.Database,
		User: runtime.User, PasswordFile: runtime.PasswordFile, CAFile: postgresConfig.CAFile,
		MaxConnections: runtime.MaxConnections, ConnectTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		t.Fatalf("open runtime pool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// shareScaleProof is a distinct idempotency proof per kind and index.
func shareScaleProof(t *testing.T, kind byte, index int) idempotency.Proof {
	t.Helper()
	var digest [32]byte
	digest[0] = 0x5c
	digest[1] = kind
	binary.BigEndian.PutUint64(digest[24:], uint64(index)) //nolint:gosec // index is non-negative
	proof, err := idempotency.NewProof("share-scale-v1", digest)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func shareScaleUUID(t *testing.T) string {
	t.Helper()
	return newScaleID(t)
}

// seedShareScaleDevices adds a /18 to the provider Network and seeds count
// provider Devices in it and one consumer Device in Network 204, each with
// fresh keys and an address, in one audited inventory change per Network.
func seedShareScaleDevices(ctx context.Context, t *testing.T, admin *pgx.Conn, count int) (
	providers []shareScaleDevice, consumer shareScaleDevice, dualStack bool,
) {
	t.Helper()
	seed := newShareScaleSeed(ctx, t, admin, count)
	for _, side := range seed.sides {
		var revision int64
		if err := admin.QueryRow(ctx, `SELECT network_revision + 1 FROM mesh_ops.network_revision WHERE workspace_id = $1 AND network_id = $2`,
			shareScaleWorkspace, side.network).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
			changePublicID: shareScaleUUID(t), eventPublicID: shareScaleUUID(t), outboxPublicID: shareScaleUUID(t),
			streamID: side.network, aggregateKind: "device", networkRevision: revision,
			aggregatePublicID: side.devices[0].publicID, aggregateVersion: 1,
			action: "device.registered", permission: "system.bootstrap", outboxEventClass: "network.inventory.changed",
		}, func(tx pgx.Tx) { side.insert(ctx, t, tx) })
	}
	return seed.providers, seed.consumer, seed.dualStack
}

type shareScalePrefix struct {
	realm, pool, prefixID int64
	prefix                netip.Prefix
	profile               int64
}

// shareScaleSide is one Network's part of a seed: its Devices and, for the
// provider, the /18 they are addressed from.
type shareScaleSide struct {
	network  int64
	row      shareScalePrefix
	prefixID int64
	row6     shareScalePrefix
	devices  []shareScaleDevice
	prefix   string
}

type shareScaleSeed struct {
	providers []shareScaleDevice
	consumer  shareScaleDevice
	dualStack bool
	sides     []shareScaleSide
}

// newShareScaleSeed chooses the Devices, keys and addresses of a seed
// without writing them.
func newShareScaleSeed(ctx context.Context, t *testing.T, admin *pgx.Conn, count int) shareScaleSeed {
	t.Helper()
	var (
		providers []shareScaleDevice
		consumer  shareScaleDevice
		dualStack bool
	)
	newDevice := func(id int64, address, address6 netip.Addr) shareScaleDevice {
		var machineRaw, keyRaw [32]byte
		if _, err := rand.Read(machineRaw[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(keyRaw[:]); err != nil {
			t.Fatal(err)
		}
		machine, err := node.NewMachineKey(machineRaw)
		if err != nil {
			t.Fatal(err)
		}
		key, err := node.NewKey(keyRaw)
		if err != nil {
			t.Fatal(err)
		}
		return shareScaleDevice{id: id, publicID: integrationPublicID("01890f5c-0000-7000-8000-", id),
			machine: machine, key: key, address: address, address6: address6}
	}
	readPrefix := func(networkID int64, family int) (shareScalePrefix, bool) {
		var row shareScalePrefix
		var prefix string
		if err := admin.QueryRow(ctx, `SELECT prefix.address_realm_id, prefix.address_pool_id, prefix.id, prefix.prefix::TEXT,
                (SELECT profile.id FROM mesh.enrollment_profile AS profile WHERE profile.workspace_id = prefix.workspace_id
                   AND profile.network_id = prefix.network_id AND profile.state = 'active' ORDER BY profile.id LIMIT 1)
            FROM mesh.network_prefix AS prefix
            WHERE prefix.workspace_id = $1 AND prefix.network_id = $2 AND prefix.family = $3 AND prefix.state = 'active'
            ORDER BY prefix.id LIMIT 1`, shareScaleWorkspace, networkID, family).Scan(
			&row.realm, &row.pool, &row.prefixID, &prefix, &row.profile); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shareScalePrefix{}, false
			}
			t.Fatalf("read Network %d prefix: %v", networkID, err)
		}
		row.prefix = netip.MustParsePrefix(prefix)
		return row, true
	}
	provider, found4 := readPrefix(shareScaleProvider, 4)
	consumerPrefix, found4c := readPrefix(shareScaleConsumer, 4)
	if !found4 || !found4c {
		t.Fatal("the share scale Networks have no IPv4 prefix")
	}
	// A Device alias of a family needs an address of that family: with IPv6
	// prefixes the Devices are dual-stack, otherwise aliases are IPv4 only.
	provider6, found6 := readPrefix(shareScaleProvider, 6)
	consumer6, found6c := readPrefix(shareScaleConsumer, 6)
	dualStack = found6 && found6c
	// A free /18 of the Workspace pool for the provider Devices.
	var scalePrefix string
	if err := admin.QueryRow(ctx, `SELECT candidate::TEXT FROM (VALUES ('100.64.64.0/18'::CIDR),('100.64.128.0/18'::CIDR),('100.64.192.0/18'::CIDR)) AS c(candidate)
        WHERE NOT EXISTS (SELECT 1 FROM mesh.network_prefix AS prefix WHERE prefix.address_realm_id = $1 AND prefix.prefix && c.candidate)
        ORDER BY 1 LIMIT 1`, provider.realm).Scan(&scalePrefix); err != nil {
		t.Fatalf("no free /18 for the provider Devices: %v", err)
	}
	scale := netip.MustParsePrefix(scalePrefix)
	var scalePrefixID int64
	if err := admin.QueryRow(ctx, `SELECT COALESCE(max(id), 0) + 100 FROM mesh.network_prefix`).Scan(&scalePrefixID); err != nil {
		t.Fatal(err)
	}
	providers = make([]shareScaleDevice, count)
	address := scale.Addr().Next()
	// IPv6 addresses well past any fixture lease in the /64.
	var address6 netip.Addr
	if dualStack {
		address6 = provider6.prefix.Addr()
		for range 0x5c00 {
			address6 = address6.Next()
		}
	}
	for index := range providers {
		providers[index] = newDevice(shareScaleDeviceBase+int64(index), address, address6)
		address = address.Next()
		if dualStack {
			address6 = address6.Next()
		}
	}
	consumerAddress := consumerPrefix.prefix.Addr()
	used := map[netip.Addr]bool{}
	rows, err := admin.Query(ctx, `SELECT host(address) FROM mesh.node_address_lease WHERE network_prefix_id = $1`, consumerPrefix.prefixID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		used[netip.MustParseAddr(value)] = true
	}
	rows.Close()
	for consumerAddress = consumerAddress.Next(); used[consumerAddress] || consumerAddress == consumerPrefix.prefix.Addr(); {
		consumerAddress = consumerAddress.Next()
	}
	var consumer6Address netip.Addr
	if dualStack {
		consumer6Address = consumer6.prefix.Addr()
		for range 0x5c00 {
			consumer6Address = consumer6Address.Next()
		}
	}
	consumer = newDevice(shareScaleDeviceBase+int64(count), consumerAddress, consumer6Address)

	return shareScaleSeed{providers: providers, consumer: consumer, dualStack: dualStack, sides: []shareScaleSide{
		{shareScaleProvider, provider, scalePrefixID, provider6, providers, scalePrefix},
		{shareScaleConsumer, consumerPrefix, consumerPrefix.prefixID, consumer6, []shareScaleDevice{consumer}, ""},
	}}
}

// insert writes the side in transaction tx: the Network revision, the /18
// and the Devices with their keys and leases. The caller records evidence.
func (side shareScaleSide) insert(ctx context.Context, t *testing.T, tx pgx.Tx) {
	t.Helper()
	if _, err := tx.Exec(ctx, `UPDATE mesh_ops.network_revision SET network_revision = network_revision + 1,
        inventory_revision = inventory_revision + 1, updated_at = clock_timestamp()
        WHERE workspace_id = $1 AND network_id = $2`, shareScaleWorkspace, side.network); err != nil {
		t.Fatal(err)
	}
	if side.prefix != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO mesh.network_prefix (id, public_id, workspace_id, network_id,
            address_realm_id, address_pool_id, prefix, family, state)
            OVERRIDING SYSTEM VALUE VALUES ($1, $2::UUID, $3, $4, $5, $6, $7::CIDR, 4, 'active')`,
			side.prefixID, shareScaleUUID(t), shareScaleWorkspace, side.network, side.row.realm, side.row.pool, side.prefix); err != nil {
			t.Fatalf("add the share scale prefix: %v", err)
		}
	}
	networkID, row, prefixID, row6 := side.network, side.row, side.prefixID, side.row6
	batch := &pgx.Batch{}
	for _, device := range side.devices {
		machine, key := device.machine.Bytes(), device.key.Bytes()
		fingerprint, keyFingerprint := device.machine.Fingerprint(), device.key.Fingerprint()
		batch.Queue(`INSERT INTO mesh.device (id, public_id, workspace_id, network_id, enrollment_profile_id,
                owner_principal_id, custodian_principal_id, registered_by_kind, registered_by_principal_id,
                hostname, hostname_key, is_ephemeral, expires_at, state)
                OVERRIDING SYSTEM VALUE VALUES ($1, $2::UUID, $3, $4, $5, 11, 11, 'principal', 11, $6, $6, FALSE,
                clock_timestamp() + interval '4 hours', 'active')`,
			device.id, device.publicID, shareScaleWorkspace, networkID, row.profile, fmt.Sprintf("scale-%d.example", device.id))
		// Explicit IDs past the fixtures', which insert theirs explicitly
		// and so leave the identity sequences behind.
		offset := device.id - shareScaleDeviceBase
		batch.Queue(`INSERT INTO mesh.device_machine_key_epoch (id, public_id, workspace_id, network_id, device_id, epoch,
                public_key, fingerprint, valid_from, state) OVERRIDING SYSTEM VALUE
                VALUES ($7, $1::UUID, $2, $3, $4, 1, $5, $6, transaction_timestamp(), 'active')`,
			shareScaleUUID(t), shareScaleWorkspace, networkID, device.id, machine[:], fingerprint[:], 6*shareScaleDeviceBase+offset)
		batch.Queue(`INSERT INTO mesh.device_node_key_epoch (id, public_id, workspace_id, network_id, device_id, epoch,
                public_key, fingerprint, valid_from, state) OVERRIDING SYSTEM VALUE
                VALUES ($7, $1::UUID, $2, $3, $4, 1, $5, $6, transaction_timestamp(), 'active')`,
			shareScaleUUID(t), shareScaleWorkspace, networkID, device.id, key[:], keyFingerprint[:], 7*shareScaleDeviceBase+offset)
		batch.Queue(`INSERT INTO mesh.node_address_lease (id, public_id, workspace_id, network_id, address_realm_id,
                address_pool_id, network_prefix_id, device_id, address, family, generation, lease_role, state, created_at)
                OVERRIDING SYSTEM VALUE
                VALUES ($9, $1::UUID, $2, $3, $4, $5, $6, $7, $8::INET, 4, 1, 'primary', 'active', transaction_timestamp() - interval '1 second')`,
			shareScaleUUID(t), shareScaleWorkspace, networkID, row.realm, row.pool, prefixID, device.id, device.address.String(),
			8*shareScaleDeviceBase+2*offset)
		if device.address6.IsValid() {
			batch.Queue(`INSERT INTO mesh.node_address_lease (id, public_id, workspace_id, network_id, address_realm_id,
                    address_pool_id, network_prefix_id, device_id, address, family, generation, lease_role, state, created_at)
                    OVERRIDING SYSTEM VALUE
                    VALUES ($9, $1::UUID, $2, $3, $4, $5, $6, $7, $8::INET, 6, 1, 'primary', 'active', transaction_timestamp() - interval '1 second')`,
				shareScaleUUID(t), shareScaleWorkspace, networkID, row6.realm, row6.pool, row6.prefixID, device.id, device.address6.String(),
				8*shareScaleDeviceBase+2*offset+1)
		}
	}
	results := tx.SendBatch(ctx, batch)
	for range batch.Len() {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			t.Fatalf("seed share scale Devices in Network %d: %v", networkID, err)
		}
	}
	if err := results.Close(); err != nil {
		t.Fatal(err)
	}
}

// seedShareScaleAliasPools adds alias pools large enough for every share.
func seedShareScaleAliasPools(ctx context.Context, t *testing.T, admin *pgx.Conn, dualStack bool) {
	t.Helper()
	var realmID, version int64
	var realmPublicID string
	if err := admin.QueryRow(ctx, `SELECT id, public_id::TEXT, version + 1 FROM mesh.address_realm
        WHERE deployment_id = 1 AND kind = 'federation_alias' AND state = 'active' ORDER BY id LIMIT 1`).Scan(
		&realmID, &realmPublicID, &version); err != nil {
		t.Fatalf("read the alias realm: %v", err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: shareScaleUUID(t), eventPublicID: shareScaleUUID(t), outboxPublicID: shareScaleUUID(t),
		streamID: 1, aggregateKind: "address_realm", aggregatePublicID: realmPublicID, aggregateVersion: version,
		action: "device_alias.pools_configured", permission: "system.bootstrap", outboxEventClass: "deployment.changed",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE mesh.address_realm SET ipv4_enabled = TRUE, ipv6_enabled = $2,
            version = version + 1, updated_at = clock_timestamp() WHERE id = $1`, realmID, dualStack); err != nil {
			t.Fatal(err)
		}
		// One active pool per family and role: retire the fixture's small ones.
		if _, err := tx.Exec(ctx, `UPDATE mesh.address_pool SET state = 'quarantined', version = version + 1, updated_at = clock_timestamp()
            WHERE address_realm_id = $1 AND state = 'active' AND workspace_id IS NULL
              AND purpose IN ('federation_resource_alias', 'federation_consumer_alias')`, realmID); err != nil {
			t.Fatalf("retire the fixture alias pools: %v", err)
		}
		// Alias pools must not overlap Node overlay or Workspace service pools.
		free := func(candidates ...string) string {
			for _, candidate := range candidates {
				var overlaps bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh.address_pool WHERE deployment_id = 1
                    AND state IN ('reserved', 'active', 'quarantined') AND prefix && $1::CIDR)`, candidate).Scan(&overlaps); err != nil {
					t.Fatal(err)
				}
				if !overlaps {
					return candidate
				}
			}
			t.Fatalf("no free alias pool among %v", candidates)
			return ""
		}
		pools := []struct{ purpose, prefix string }{
			{"federation_resource_alias", free("198.18.0.0/16", "10.200.0.0/16", "172.30.0.0/16")},
			{"federation_consumer_alias", free("198.19.0.0/16", "10.201.0.0/16", "172.31.0.0/16")},
		}
		if dualStack {
			// Activation prefers an IPv6 Resource Alias when a pool offers one.
			pools = append(pools,
				struct{ purpose, prefix string }{"federation_resource_alias", free("fd5c:a1e5:0:1::/96", "fdc5:5ca1:e::/96")},
				struct{ purpose, prefix string }{"federation_consumer_alias", free("fd5c:a1e5:0:2::/96", "fdc5:5ca1:f::/96")})
		}
		for _, pool := range pools {
			family := 4
			if netip.MustParsePrefix(pool.prefix).Addr().Is6() {
				family = 6
			}
			if _, err := tx.Exec(ctx, `INSERT INTO mesh.address_pool (public_id, deployment_id, address_realm_id, purpose, prefix, family, state)
                VALUES ($1::UUID, 1, $2, $3, $4::CIDR, $5, 'active')`, shareScaleUUID(t), realmID, pool.purpose, pool.prefix, family); err != nil {
				t.Fatalf("add alias pool %s: %v", pool.prefix, err)
			}
		}
	})
}

func createShareScaleResources(ctx context.Context, t *testing.T, admin *pgx.Conn, pool *postgresadapter.Pool,
	session accountsession.Session, providers []shareScaleDevice,
) []resource.ID {
	t.Helper()
	scope := resourceAuthorityScope(t, int(shareScaleWorkspace), int(shareScaleProvider))
	service := newIntegrationResourceAuthorityService(t, pool)
	reason := resourceAuthorityReason(t, "share scale load test Device")
	ids := make([]resource.ID, len(providers))
	for index, device := range providers {
		deviceID, err := node.ParseID(device.publicID)
		if err != nil {
			t.Fatal(err)
		}
		inventory, _ := resourceAuthorityRevisions(ctx, t, admin, shareScaleWorkspace, shareScaleProvider)
		definition := resourceAuthorityDeviceDefinition(t, scope, session.PrincipalID(), deviceID, fmt.Sprintf("Scale Device %d", index))
		command, err := authority.NewCreateDeviceCommand(definition, inventory, session, reason, shareScaleProof(t, 1, index))
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Create(ctx, command)
		if err != nil {
			t.Fatalf("create Resource %d: %v", index, err)
		}
		ids[index] = result.ResourceID()
	}
	return ids
}

func createShareScaleShares(ctx context.Context, t *testing.T, pool *postgresadapter.Pool, session accountsession.Session,
	resources []resource.ID,
) []sharing.Contract {
	t.Helper()
	service, err := sharing.NewService(newIntegrationResourceSharingStore(t, pool), sharing.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	provider := resourceAuthorityScope(t, int(shareScaleWorkspace), int(shareScaleProvider))
	consumer := resourceAuthorityScope(t, int(shareScaleWorkspace), int(shareScaleConsumer))
	traffic := integrationSharingTraffic(t)
	reason, err := sharing.NewAuditReason("share scale load test share")
	if err != nil {
		t.Fatal(err)
	}
	contracts := make([]sharing.Contract, len(resources))
	for index, resourceID := range resources {
		label, err := sharing.ParseAccessLabel(fmt.Sprintf("scale-%d", index))
		if err != nil {
			t.Fatal(err)
		}
		create, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
			ProviderScope: provider, ConsumerScope: consumer, ResourceID: resourceID, MaximumTraffic: traffic,
			ExpiresAt: time.Now().UTC().Add(3 * time.Hour), AccessLabel: label, AccountSession: session,
			Reason: reason, Idempotency: shareScaleProof(t, 2, index),
		})
		if err != nil {
			t.Fatal(err)
		}
		created, err := service.CreateOffer(ctx, create)
		if err != nil {
			t.Fatalf("create offer %d: %v", index, err)
		}
		offer, _ := created.Offer()
		token, _ := created.Token()
		name, err := resource.ParseDisplayName(fmt.Sprintf("Scale share %d", index))
		if err != nil {
			t.Fatal(err)
		}
		decide, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
			ProviderScope: provider, ConsumerScope: consumer, OfferID: offer.Offer().ID(),
			ExpectedOfferVersion: offer.Offer().Version(), Token: token, Action: sharing.DecisionActionAccept,
			ImportedDisplayName: name, AccessName: offer.AccessName(), AccountSession: session,
			Reason: reason, Idempotency: shareScaleProof(t, 3, index),
		})
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := service.DecideOffer(ctx, decide)
		if err != nil {
			t.Fatalf("accept offer %d: %v", index, err)
		}
		contract, _ := accepted.Contract()
		activate, err := sharing.NewActivateContract(sharing.ActivateContractParams{
			ProviderScope: provider, ConsumerScope: consumer, ContractID: contract.ID(),
			ExpectedContractVersion: contract.Version(), AccountSession: session, Reason: reason,
			Idempotency: shareScaleProof(t, 4, index),
		})
		if err != nil {
			t.Fatal(err)
		}
		activated, err := service.ActivateContract(ctx, activate)
		if err != nil {
			t.Fatalf("activate share %d: %v", index, err)
		}
		contracts[index], _ = activated.Contract()
	}
	return contracts
}

// seedShareScaleRelease publishes, in the consumer Network, a release whose
// compiled destinations give the consumer Device a rule to every share, and
// records both sides as alias clients. It writes the rows the publication
// writer would, in one statement each.
func seedShareScaleRelease(ctx context.Context, t *testing.T, admin *pgx.Conn, consumer shareScaleDevice, release bool) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, tx)
	releaseID := shareScaleUUID(t)
	for _, statement := range []struct {
		name  string
		query string
		args  []any
	}{
		{"replica", `SET LOCAL session_replication_role = replica`, nil},
		{"client versions", `INSERT INTO mesh.device_alias_client_version(workspace_id, network_id, device_id, session_generation,
            machine_key_epoch, node_key_epoch, node_public_key, alias_version, observed_at)
            SELECT device.workspace_id, device.network_id, device.id, device.session_generation, device.current_machine_key_epoch,
                device.current_node_key_epoch, node_key.public_key, 1, clock_timestamp()
            FROM mesh.device AS device JOIN mesh.device_node_key_epoch AS node_key
              ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
            WHERE device.id >= $1
            ON CONFLICT (workspace_id, network_id, device_id) DO UPDATE SET alias_version = 1`, []any{shareScaleDeviceBase}},
		{"supersede release", `UPDATE mesh.policy_release SET state = 'superseded', superseded_at = clock_timestamp(), version = version + 1
            WHERE workspace_id = $1 AND network_id = $2 AND state = 'active'`, []any{shareScaleWorkspace, shareScaleConsumer}},
		{"advance revisions", `UPDATE mesh_ops.network_revision SET policy_revision = policy_revision + 1,
            network_revision = network_revision + 1, sharing_revision = sharing_revision + 1, updated_at = clock_timestamp()
            WHERE workspace_id = $1 AND network_id = $2`, []any{shareScaleWorkspace, shareScaleConsumer}},
		{"release", `INSERT INTO mesh.policy_release(public_id, workspace_id, network_id, policy_revision, semantic_hash,
            compiler_format_version, state)
            SELECT $1::UUID, workspace_id, network_id, policy_revision, decode(repeat('5c', 32), 'hex'), 4, 'active'
            FROM mesh_ops.network_revision WHERE workspace_id = $2 AND network_id = $3`,
			[]any{releaseID, shareScaleWorkspace, shareScaleConsumer}},
		{"destinations", `INSERT INTO mesh.compiled_policy_imported_resource_destination(public_id, access_rule_public_id,
            workspace_id, network_id, policy_release_id, policy_revision, source_device_id, imported_resource_id,
            imported_resource_version, trust_contract_id, trust_contract_version, resource_export_id, resource_export_version,
            provider_workspace_id, provider_network_id, destination_resource_id, resource_version, target_generation,
            resource_semantic_hash, provider_inventory_revision, provider_sharing_revision, consumer_sharing_revision,
            provider_authority_generation, consumer_authority_generation, recovery_epoch, contract_expires_at, constraint_hash,
            protocol, destination_ports, created_at)
            SELECT pg_catalog.uuidv7(), pg_catalog.uuidv7(), endpoint.consumer_workspace_id,
                endpoint.consumer_network_id, release.id, release.policy_revision, consumer.id, imported.id, imported.version,
                contract.id, contract.version, export.id, export.version, endpoint.provider_workspace_id,
                endpoint.provider_network_id, resource.id, resource.version, resource.target_generation, resource.semantic_hash,
                provider_revision.inventory_revision, provider_revision.sharing_revision, consumer_revision.sharing_revision,
                contract.provider_authority_generation, contract.consumer_authority_generation, contract.recovery_epoch,
                contract.expires_at, contract.constraint_hash, 'tcp', '{[443,444)}'::INT4MULTIRANGE, transaction_timestamp()
            FROM mesh.private_endpoint AS endpoint
            JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
            JOIN mesh.resource_export AS export ON export.id = contract.resource_export_id
            JOIN mesh.resource AS resource ON resource.id = contract.resource_id
            JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
            JOIN mesh.device AS consumer ON consumer.id = $1
            JOIN mesh.policy_release AS release ON release.public_id = $2::UUID
            JOIN mesh_ops.network_revision AS provider_revision ON provider_revision.workspace_id = endpoint.provider_workspace_id
             AND provider_revision.network_id = endpoint.provider_network_id
            JOIN mesh_ops.network_revision AS consumer_revision ON consumer_revision.workspace_id = endpoint.consumer_workspace_id
             AND consumer_revision.network_id = endpoint.consumer_network_id
            WHERE endpoint.consumer_workspace_id = $3 AND endpoint.consumer_network_id = $4
              AND endpoint.state = 'provisioning' AND contract.state = 'active'
              AND EXISTS (SELECT 1 FROM mesh.resource_device_target AS target WHERE target.resource_id = resource.id
                AND target.target_generation = resource.target_generation AND target.device_id >= $5)`,
			[]any{consumer.id, releaseID, shareScaleWorkspace, shareScaleConsumer, shareScaleDeviceBase}},
		{"origin", `SET LOCAL session_replication_role = origin`, nil},
	} {
		if !release && statement.name != "replica" && statement.name != "client versions" && statement.name != "origin" {
			continue
		}
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("share scale release %s: %v", statement.name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit share scale release: %v", err)
	}
}

// publishShareScaleRules gives the consumer Device a rule to every share
// through policy simulation and management publication, as the Console does.
func publishShareScaleRules(ctx context.Context, t *testing.T, pool *postgresadapter.Pool, session accountsession.Session,
	consumer shareScaleDevice, contracts []sharing.Contract,
) {
	t.Helper()
	scope := resourceAuthorityScope(t, int(shareScaleWorkspace), int(shareScaleConsumer))
	baselines, err := postgresadapter.NewPolicySimulationStore(pool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: time.Minute, LockTimeout: 10 * time.Second, IdleTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := baselines.ReadSimulationBaseline(ctx, session, scope, time.Now().UTC())
	if err != nil {
		t.Fatalf("read consumer policy baseline: %v", err)
	}
	source, err := node.ParseID(consumer.publicID)
	if err != nil {
		t.Fatal(err)
	}
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	intents := make([]compilation.RuleIntent, 0, len(contracts))
	for index, contract := range contracts {
		id, err := policy.ParseRuleID(fmt.Sprintf("01890f99-0000-7000-8000-%012x", index+1))
		if err != nil {
			t.Fatal(err)
		}
		intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
			ID: id, Scope: scope, SourceNodeID: source, DestinationImportedResourceID: contract.ImportedResourceID(),
			Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{port},
		})
		if err != nil {
			t.Fatal(err)
		}
		intents = append(intents, intent)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: baseline.RevisionVector().PolicyRevision() + 1, Rules: intents,
	})
	if err != nil {
		t.Fatal(err)
	}
	compiler := newIntegrationPolicyCompiler(t, pool, newIntegrationResourceSharingStore(t, pool))
	simulator, err := simulation.NewService(simulation.Dependencies{Baselines: baselines, Compiler: compiler, Clock: simulation.SystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	added, err := simulator.Simulate(ctx, session, request)
	if err != nil {
		t.Fatalf("simulate %d shared rules: %v", len(intents), err)
	}
	t.Logf("simulate %d shared rules: %v", len(intents), time.Since(started).Round(time.Millisecond))
	reason, err := publication.NewAuditReason("share scale load test rules")
	if err != nil {
		t.Fatal(err)
	}
	command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: added.ProposedCandidate(), BasePolicyRevision: baseline.RevisionVector().PolicyRevision(),
		AccountSession: session, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	if _, err := newIntegrationManagementPolicyPublicationService(t, pool).Publish(ctx, command); err != nil {
		t.Fatalf("publish %d shared rules: %v", len(intents), err)
	}
	t.Logf("publish %d shared rules: %v", len(intents), time.Since(started).Round(time.Millisecond))
}

// readyShareScaleAliases runs the alias worker's reserve and ready for every
// share and returns how long each ready took.
func readyShareScaleAliases(ctx context.Context, t *testing.T, admin *pgx.Conn, workerPool *postgresadapter.Pool,
	consumer shareScaleDevice, contracts []sharing.Contract,
) []time.Duration {
	t.Helper()
	store, err := postgresadapter.NewDeviceAliasWorkerStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	var deploymentPublicID string
	if err := admin.QueryRow(ctx, `SELECT installation_public_id::TEXT FROM mesh.deployment WHERE id = 1`).Scan(&deploymentPublicID); err != nil {
		t.Fatal(err)
	}
	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		t.Fatal(err)
	}
	consumerID, err := node.ParseID(consumer.publicID)
	if err != nil {
		t.Fatal(err)
	}
	times := make([]time.Duration, 0, len(contracts))
	for index, contract := range contracts {
		var endpointPublicID string
		var generation, providerEpoch int64
		if err := admin.QueryRow(ctx, `SELECT endpoint.public_id::TEXT, endpoint.generation, provider.current_node_key_epoch
            FROM mesh.private_endpoint AS endpoint JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
            JOIN mesh.resource_device_target AS target ON target.resource_id = contract.resource_id
             AND target.target_generation = contract.target_generation AND target.state = 'active'
            JOIN mesh.device AS provider ON provider.id = target.device_id
            WHERE contract.public_id = $1::UUID`, contract.ID().String()).Scan(&endpointPublicID, &generation, &providerEpoch); err != nil {
			t.Fatalf("read share %d endpoint: %v", index, err)
		}
		endpointID, err := sharing.ParsePrivateEndpointID(endpointPublicID)
		if err != nil {
			t.Fatal(err)
		}
		intent := devicealias.ChangeIntent{DeploymentID: deploymentID, EndpointID: endpointID, ConsumerID: consumerID,
			EndpointGeneration: generation, ProviderNodeEpoch: providerEpoch, ConsumerNodeEpoch: 1}
		for _, mode := range []devicealias.ChangeMode{devicealias.Reserve, devicealias.Ready} {
			intent.Mode = mode
			started := time.Now()
			if _, err := store.Change(ctx, intent); err != nil {
				t.Fatalf("alias %s for share %d: %v", mode, index, err)
			}
			if mode == devicealias.Ready {
				times = append(times, time.Since(started))
			}
		}
	}
	return times
}

// measureShareScaleReaders times the schema 147 and 149 readers for one
// Device, records them under its role, and requires the schema 149 readers
// to return exactly the schema 147 rows. It returns the legacy v4 reader's
// error past 256 shares.
func measureShareScaleReaders(ctx context.Context, t *testing.T, admin *pgx.Conn, role string, device shareScaleDevice,
	readers map[string]shareScaleReader,
) string {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, tx)
	scope := shareScaleConsumer
	if role == "provider" {
		scope = shareScaleProvider
	}
	setIntegrationScope(ctx, t, tx, shareScaleWorkspace, scope)
	if os.Getenv("MESHTRANSIT_SHARE_SCALE_EXPLAIN") != "" {
		// Log the plans of the statements the readers run, to the server log.
		if _, err := tx.Exec(ctx, `LOAD 'auto_explain'; SET LOCAL auto_explain.log_min_duration = 0;
            SET LOCAL auto_explain.sample_rate = 1; SET LOCAL auto_explain.log_analyze = on;
            SET LOCAL auto_explain.log_buffers = on; SET LOCAL auto_explain.log_nested_statements = on`); err != nil {
			t.Fatalf("enable auto_explain: %v", err)
		}
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	machine, key := device.machine.Fingerprint(), device.key.Bytes()
	read := func(name, function string) []string {
		started := time.Now()
		rows, err := tx.Query(ctx, `SELECT row::TEXT FROM mesh_ops.`+function+`($1::BYTEA, $2::BYTEA, 10000) AS row`,
			machine[:], key[:])
		if err != nil {
			t.Fatalf("%s %s: %v", role, name, err)
		}
		values, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("%s %s: %v", role, name, err)
		}
		readers[role+" "+name] = shareScaleReader{
			Milliseconds: float64(time.Since(started).Microseconds()) / 1000, Rows: len(values),
		}
		return values
	}
	v6 := read("alias v6", "load_device_alias_map_edges_v6")
	if v5 := read("alias v5", "load_device_alias_map_edges_v5"); !slices.Equal(v5, v6) {
		t.Fatalf("%s alias v6 returned %d rows unlike v5's %d", role, len(v6), len(v5))
	}
	if v7 := read("alias v7", "load_device_alias_map_edges_v7"); !slices.Equal(v6, v7) {
		t.Fatalf("%s alias v7 returned %d rows unlike v6's %d", role, len(v7), len(v6))
	}
	v4 := read("dependencies v4", "load_device_sharing_dependencies_v4")
	if v3 := read("dependencies v3", "load_device_sharing_dependencies_v3"); !slices.Equal(v3, v4) {
		t.Fatalf("%s dependencies v4 returned %d rows unlike v3's %d", role, len(v4), len(v3))
	}
	if v5 := read("dependencies v5", "load_device_sharing_dependencies_v5"); !slices.Equal(v4, v5) {
		t.Fatalf("%s dependencies v5 returned %d rows unlike v4's %d", role, len(v5), len(v4))
	}
	if v6 := read("dependencies v6", "load_device_sharing_dependencies_v6"); !slices.Equal(v4, v6) {
		t.Fatalf("%s dependencies v6 returned %d rows unlike v4's %d", role, len(v6), len(v4))
	}
	legacy := ""
	if _, err := tx.Exec(ctx, `SAVEPOINT legacy_reader`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT count(*) FROM mesh_ops.load_device_alias_map_edges_v4($1::BYTEA, $2::BYTEA, 257)`,
		machine[:], key[:]); err != nil {
		legacy = err.Error()
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT legacy_reader`); err != nil {
			t.Fatal(err)
		}
	}
	return legacy
}

func measureShareScaleMap(ctx context.Context, t *testing.T, pool *postgresadapter.Pool, device shareScaleDevice) shareScaleRead {
	t.Helper()
	// Core's default bounds: 3s per statement, 10s per share reader and per
	// map request. A map that needs more fails here as it would in service.
	store, err := postgresadapter.NewMapSessionStore(pool, postgresadapter.MapSessionOptions{
		StatementTimeout: 3 * time.Second, ShareStatementTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
		RelayDirectory: integrationRelayDirectory(t), EnableDeviceAliases: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := control.NewAuthenticatedMachine(device.machine)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := machine.BindNodeKey(device.key)
	if err != nil {
		t.Fatal(err)
	}
	var read shareScaleRead
	for range 3 {
		started := time.Now()
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		snapshot, err := store.Load(requestCtx, identity)
		cancel()
		if err != nil {
			t.Fatalf("load the map of %s: %v", device.publicID, err)
		}
		read.Milliseconds = append(read.Milliseconds, float64(time.Since(started).Microseconds())/1000)
		records, err := snapshot.SharedDNSRecords()
		if err != nil {
			t.Fatal(err)
		}
		read.Projections, read.Peers, read.DNSRecords = snapshot.DirectDeviceProjectionCount(), len(snapshot.AuthorizedPeers()), len(records)
		read.Limited = snapshot.IsPeerLimited()
	}
	return read
}

// shareScaleTimes summarizes durations as milliseconds at the first and
// last tenth and the median, which shows whether the cost grows with N.
func shareScaleTimes(values []time.Duration) map[string]float64 {
	if len(values) == 0 {
		return nil
	}
	tenth := max(len(values)/10, 1)
	mean := func(part []time.Duration) float64 {
		var total time.Duration
		for _, value := range part {
			total += value
		}
		return float64(total.Microseconds()) / float64(len(part)) / 1000
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return map[string]float64{
		"first_tenth_mean": mean(values[:tenth]), "last_tenth_mean": mean(values[len(values)-tenth:]),
		"median": float64(sorted[len(sorted)/2].Microseconds()) / 1000,
		"p99":    float64(sorted[min(len(sorted)-1, len(sorted)*99/100)].Microseconds()) / 1000,
	}
}

// logShareScaleAuthority records the management session and role bindings
// the writers authorize against.
func logShareScaleAuthority(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var session string
	if err := admin.QueryRow(ctx, `SELECT row_to_json(s)::TEXT FROM (SELECT state, version, provider_generation,
        principal_authority_generation, account_session_generation, idle_expires_at, absolute_expires_at
        FROM mesh.account_session WHERE public_id = $1::UUID) AS s`, integrationManagementSessionPublicID).Scan(&session); err != nil {
		t.Logf("management session: %v", err)
	}
	t.Logf("management session: %s", session)
	rows, err := admin.Query(ctx, `SELECT row_to_json(b)::TEXT FROM (SELECT binding.public_id, binding.state, binding.network_id,
        binding.expires_at FROM mesh.role_binding AS binding
        WHERE binding.principal_id = 11 AND binding.workspace_id = $1) AS b`, shareScaleWorkspace)
	if err != nil {
		t.Logf("role bindings: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err == nil {
			t.Logf("role binding: %s", value)
		}
	}
	var principal string
	if err := admin.QueryRow(ctx, `SELECT row_to_json(p)::TEXT FROM (SELECT state, authority_generation FROM mesh.principal WHERE id = 11) AS p`).Scan(&principal); err != nil {
		t.Logf("principal: %v", err)
	}
	t.Logf("principal: %s", principal)
}

// shareScaleSession opens a fresh management Account Session for the
// fixture Principal: the fixture's own session is revoked by the tests that
// ran before. It carries the Principal's, account's and provider's current
// generations, as a login would.
func shareScaleSession(ctx context.Context, t *testing.T, admin *pgx.Conn) accountsession.Session {
	t.Helper()
	publicID := integrationPublicID("01890f5c-0000-7000-8000-", 5812)
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	var providerGeneration, principalGeneration, sessionGeneration, recoveryEpoch int64
	var networkRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_revision WHERE workspace_id = $1 AND network_id = $2`,
		shareScaleWorkspace, shareScaleProvider).Scan(&networkRevision); err != nil {
		t.Fatal(err)
	}
	bindingID := integrationPublicID("01890f5c-0000-7000-8000-", 5844)
	// Earlier tests revoked the fixture Principal's Network 203 binding and
	// its session; this change restores both, as an administrator would.
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: shareScaleUUID(t), eventPublicID: shareScaleUUID(t), outboxPublicID: shareScaleUUID(t),
		streamID: shareScaleProvider, aggregateKind: "role_binding", aggregatePublicID: bindingID, aggregateVersion: 1,
		networkRevision: networkRevision, actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action: "management_rbac.seeded", permission: "system.bootstrap", outboxEventClass: "management_rbac.seeded",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `INSERT INTO mesh.role_binding (id, public_id, deployment_id, workspace_id, network_id,
            principal_id, workspace_membership_id, role_definition_id, state, authority_generation, valid_from)
            OVERRIDING SYSTEM VALUE SELECT 5844, $1::UUID, binding.deployment_id, binding.workspace_id, binding.network_id,
                binding.principal_id, binding.workspace_membership_id, binding.role_definition_id, 'active', 1,
                transaction_timestamp() - interval '1 minute'
            FROM mesh.role_binding AS binding WHERE binding.public_id = '01890f00-0000-7000-8000-000000000844'
              AND NOT EXISTS (SELECT 1 FROM mesh.role_binding AS active WHERE active.principal_id = binding.principal_id
                AND active.network_id = binding.network_id AND active.state = 'active')`, bindingID); err != nil {
			t.Fatalf("restore the Network 203 binding: %v", err)
		}
		if err := tx.QueryRow(ctx, `INSERT INTO mesh.account_session (id, public_id, deployment_id, principal_id,
            identity_provider_id, identity_subject_id, identity_provider_client_id, login_workspace_id,
            token_digest_algorithm, token_digest_key_id, token_digest, provider_generation, authentication_time, acr, amr,
            principal_authority_generation, account_session_generation, deployment_recovery_epoch, issued_at, last_used_at,
            idle_expires_at, absolute_expires_at, state)
            OVERRIDING SYSTEM VALUE
            SELECT 5812, $1::UUID, session.deployment_id, session.principal_id, session.identity_provider_id,
                session.identity_subject_id, session.identity_provider_client_id, session.login_workspace_id,
                session.token_digest_algorithm, session.token_digest_key_id, $2::BYTEA, provider.current_generation,
                transaction_timestamp() - interval '1 minute', session.acr, session.amr, principal.authority_generation,
                account.session_generation, deployment.recovery_epoch, transaction_timestamp(), transaction_timestamp(),
                transaction_timestamp() + interval '30 minutes', transaction_timestamp() + interval '8 hours', 'active'
            FROM mesh.account_session AS session
            JOIN mesh.principal AS principal ON principal.id = session.principal_id
            JOIN mesh.account AS account ON account.principal_id = session.principal_id
            JOIN mesh.identity_provider AS provider ON provider.id = session.identity_provider_id
            JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
            WHERE session.public_id = $3::UUID
            RETURNING provider_generation, principal_authority_generation, account_session_generation, deployment_recovery_epoch`,
			publicID, digest[:], integrationManagementSessionPublicID).Scan(
			&providerGeneration, &principalGeneration, &sessionGeneration, &recoveryEpoch); err != nil {
			t.Fatalf("open a share scale Account Session: %v", err)
		}
	})
	fixture := managementRBACAccountSessionFixture(t)
	sessionID, err := accountsession.ParseID(publicID)
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(integrationIdentitySubjectPublicID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	loginWorkspace, _ := fixture.LoginWorkspaceID()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: fixture.DeploymentID(), PrincipalID: fixture.PrincipalID(),
		IdentitySubjectID: subjectID, LoginWorkspaceID: loginWorkspace, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Minute), ACR: "urn:meshtransit:assurance:mfa", AMR: []string{"pwd", "mfa"},
		Version: 1, PrincipalAuthorityGeneration: principalGeneration, AccountSessionGeneration: sessionGeneration,
		ProviderGeneration: providerGeneration, DeploymentRecoveryEpoch: recoveryEpoch,
		IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}
