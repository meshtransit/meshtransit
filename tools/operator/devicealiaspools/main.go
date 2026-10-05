// Command devicealiaspools configures the Deployment alias realm and its four
// explicit pools (Resource and Consumer Source, IPv4 and IPv6) with audited,
// hash-chained evidence. It is an operator tool, not part of the Core runtime.
//
// Without --apply it validates the Deployment, the requested prefixes and the
// existing configuration, then prints the plan. With --apply it commits the
// realm, the pools and one audit/outbox record per row in one transaction.
// Re-running with the same prefixes is a no-op.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	purposeResource = "federation_resource_alias"
	purposeConsumer = "federation_consumer_alias"
	deploymentAudit = "system.bootstrap"
)

type poolPlan struct {
	purpose string
	prefix  netip.Prefix
}

type options struct {
	deploymentID publicid.ID
	actorID      publicid.ID
	pools        []poolPlan
	apply        bool
}

func main() {
	deployment := flag.String("deployment", "", "Deployment installation public ID")
	actor := flag.String("actor", "", "public ID of the principal recorded as the actor")
	resource4 := flag.String("resource-ipv4", "", "IPv4 Resource Alias pool, for example 198.18.0.0/16")
	consumer4 := flag.String("consumer-ipv4", "", "IPv4 Consumer Source Alias pool, for example 198.19.0.0/16")
	resource6 := flag.String("resource-ipv6", "", "IPv6 Resource Alias pool, /67 to /126")
	consumer6 := flag.String("consumer-ipv6", "", "IPv6 Consumer Source Alias pool, /67 to /126")
	apply := flag.Bool("apply", false, "commit the reviewed configuration")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(errors.New("unexpected arguments"))
	}
	opts, err := parseOptions(*deployment, *actor, *resource4, *consumer4, *resource6, *consumer6)
	if err != nil {
		fail(err)
	}
	opts.apply = *apply
	dsn := os.Getenv("MESHTRANSIT_OPERATOR_DSN")
	if dsn == "" {
		fail(errors.New("MESHTRANSIT_OPERATOR_DSN is required"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fail(errors.New("database connection failed"))
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if connection.Close(cleanup) != nil {
			fail(errors.New("database close failed"))
		}
	}()
	if err := run(ctx, connection, opts); err != nil {
		fail(err)
	}
}

func parseOptions(deployment, actor, resource4, consumer4, resource6, consumer6 string) (options, error) {
	deploymentID, err := publicid.Parse(deployment)
	if err != nil {
		return options{}, errors.New("--deployment must be a UUIDv7 public ID")
	}
	actorID, err := publicid.Parse(actor)
	if err != nil {
		return options{}, errors.New("--actor must be a UUIDv7 public ID")
	}
	pools := make([]poolPlan, 0, 4)
	for _, candidate := range []struct {
		purpose, value string
		family         int
	}{
		{purposeResource, resource4, 4}, {purposeConsumer, consumer4, 4},
		{purposeResource, resource6, 6}, {purposeConsumer, consumer6, 6},
	} {
		prefix, err := parsePoolPrefix(candidate.value, candidate.family)
		if err != nil {
			return options{}, fmt.Errorf("%s IPv%d pool: %w", candidate.purpose, candidate.family, err)
		}
		pools = append(pools, poolPlan{purpose: candidate.purpose, prefix: prefix})
	}
	for left := range pools {
		for right := left + 1; right < len(pools); right++ {
			if pools[left].prefix.Overlaps(pools[right].prefix) {
				return options{}, errors.New("alias pools must not overlap each other")
			}
		}
	}
	return options{deploymentID: deploymentID, actorID: actorID, pools: pools}, nil
}

// parsePoolPrefix applies the same bounds and unsafe-range exclusions as the
// database allocator, so a configuration that passes here can be allocated.
func parsePoolPrefix(value string, family int) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("must be a canonical network prefix")
	}
	address := prefix.Addr()
	switch {
	case family == 4 && (!address.Is4() || prefix.Bits() < 8 || prefix.Bits() > 30):
		return netip.Prefix{}, errors.New("must be an IPv4 prefix between /8 and /30")
	case family == 6 && (!address.Is6() || address.Is4In6() || prefix.Bits() < 67 || prefix.Bits() > 126):
		return netip.Prefix{}, errors.New("must be an IPv6 prefix between /67 and /126")
	}
	for _, unsafe := range []string{
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "fe80::/10", "ff00::/8",
	} {
		if prefix.Overlaps(netip.MustParsePrefix(unsafe)) {
			return netip.Prefix{}, fmt.Errorf("overlaps reserved range %s", unsafe)
		}
	}
	return prefix, nil
}

func run(ctx context.Context, connection *pgx.Conn, opts options) (resultErr error) {
	tx, err := connection.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, errors.New("rollback failed"))
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='3s'`); err != nil {
		return err
	}
	var deploymentRow int64
	if err := tx.QueryRow(ctx, `SELECT id FROM mesh.deployment
        WHERE installation_public_id=$1::UUID AND state='active' FOR UPDATE`, opts.deploymentID.String()).Scan(&deploymentRow); err != nil {
		return errors.New("active Deployment is unavailable")
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('mesh.device_alias_deployment_id', $1, TRUE)`,
		fmt.Sprint(deploymentRow)); err != nil {
		return err
	}
	var overlapping []string
	for _, pool := range opts.pools {
		var conflict string
		err := tx.QueryRow(ctx, `SELECT purpose || ' ' || prefix::TEXT FROM mesh.address_pool
            WHERE deployment_id=$1 AND purpose IN ('node_overlay','workspace_service')
              AND state IN ('reserved','active','quarantined') AND prefix && $2::CIDR LIMIT 1`,
			deploymentRow, pool.prefix.String()).Scan(&conflict)
		if err == nil {
			overlapping = append(overlapping, pool.prefix.String()+" overlaps "+conflict)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	if len(overlapping) != 0 {
		return fmt.Errorf("alias pools overlap Workspace pools: %v", overlapping)
	}
	existing, err := existingConfiguration(ctx, tx, deploymentRow)
	if err != nil {
		return err
	}
	if existing.realm {
		if existing.matches(opts.pools) {
			fmt.Println("Device alias realm and pools already match; nothing to do")
			return nil
		}
		return errors.New("a different Device alias configuration exists; change it through a separate reviewed procedure")
	}
	if !opts.apply {
		fmt.Printf("Plan for Deployment %s: create federation_alias realm (IPv4 and IPv6)\n", opts.deploymentID)
		for _, pool := range opts.pools {
			fmt.Printf("  %s %s\n", pool.purpose, pool.prefix)
		}
		fmt.Println("Re-run with --apply to commit.")
		return nil
	}
	return applyConfiguration(ctx, tx, deploymentRow, opts)
}

type configuration struct {
	realm bool
	pools map[string]string
}

func (existing configuration) matches(pools []poolPlan) bool {
	if len(existing.pools) != len(pools) {
		return false
	}
	for _, pool := range pools {
		if existing.pools[pool.purpose+" "+pool.prefix.String()] == "" {
			return false
		}
	}
	return true
}

func existingConfiguration(ctx context.Context, tx pgx.Tx, deploymentRow int64) (configuration, error) {
	result := configuration{pools: make(map[string]string)}
	var realms int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh.address_realm
        WHERE deployment_id=$1 AND kind='federation_alias' AND deleted_at IS NULL`, deploymentRow).Scan(&realms); err != nil {
		return configuration{}, err
	}
	result.realm = realms != 0
	rows, err := tx.Query(ctx, `SELECT pool.purpose, pool.prefix::TEXT, pool.state FROM mesh.address_pool AS pool
        JOIN mesh.address_realm AS realm ON realm.id=pool.address_realm_id
        WHERE pool.deployment_id=$1 AND realm.kind='federation_alias' AND pool.deleted_at IS NULL`, deploymentRow)
	if err != nil {
		return configuration{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var purpose, prefix, state string
		if err := rows.Scan(&purpose, &prefix, &state); err != nil {
			return configuration{}, err
		}
		result.pools[purpose+" "+prefix] = state
	}
	return result, rows.Err()
}

type authorityRow struct {
	kind string
	id   publicid.ID
	what string
}

func applyConfiguration(ctx context.Context, tx pgx.Tx, deploymentRow int64, opts options) error {
	changeID, err := publicid.New()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('mesh.change_public_id',$1,TRUE)`, changeID.String()); err != nil {
		return err
	}
	realmID, err := publicid.New()
	if err != nil {
		return err
	}
	var realmRow int64
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.address_realm
        (public_id,deployment_id,workspace_id,kind,ipv4_enabled,ipv6_enabled,state)
        VALUES ($1::UUID,$2,NULL,'federation_alias',TRUE,TRUE,'active') RETURNING id`,
		realmID.String(), deploymentRow).Scan(&realmRow); err != nil {
		return fmt.Errorf("create alias realm: %w", err)
	}
	rows := []authorityRow{{kind: "address_realm", id: realmID, what: "federation_alias realm"}}
	for _, pool := range opts.pools {
		poolID, err := publicid.New()
		if err != nil {
			return err
		}
		family := 4
		if pool.prefix.Addr().Is6() {
			family = 6
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mesh.address_pool
            (public_id,deployment_id,workspace_id,address_realm_id,purpose,prefix,family,state)
            VALUES ($1::UUID,$2,NULL,$3,$4,$5::CIDR,$6,'active')`,
			poolID.String(), deploymentRow, realmRow, pool.purpose, pool.prefix.String(), family); err != nil {
			return fmt.Errorf("create %s pool: %w", pool.purpose, err)
		}
		rows = append(rows, authorityRow{kind: "address_pool", id: poolID, what: pool.purpose + " " + pool.prefix.String()})
	}
	var stream, sequence int64
	var previousBytes []byte
	if err := tx.QueryRow(ctx, `SELECT id, next_sequence, latest_event_hash FROM mesh_audit.audit_stream
        WHERE deployment_id=$1 AND workspace_id IS NULL AND network_id IS NULL FOR UPDATE`,
		deploymentRow).Scan(&stream, &sequence, &previousBytes); err != nil || len(previousBytes) != sha256.Size {
		return errors.New("deployment audit stream is unavailable")
	}
	var previous [sha256.Size]byte
	copy(previous[:], previousBytes)
	for _, row := range rows {
		previous, err = appendEvidence(ctx, tx, stream, sequence, previous, changeID, opts.actorID, row)
		if err != nil {
			return err
		}
		sequence++
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("commit could not be confirmed; re-run without --apply to inspect")
	}
	fmt.Printf("Committed Device alias realm %s with %d pools and %d audit/outbox records\n",
		realmID, len(opts.pools), len(rows))
	return nil
}

func appendEvidence(ctx context.Context, tx pgx.Tx, stream, sequence int64, previous [sha256.Size]byte,
	changeID, actorID publicid.ID, row authorityRow,
) ([sha256.Size]byte, error) {
	eventID, err := publicid.New()
	if err != nil {
		return previous, err
	}
	outboxID, err := publicid.New()
	if err != nil {
		return previous, err
	}
	payload, err := json.Marshal(struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Detail string `json:"detail"`
	}{Source: "device_alias_pools_operator", Target: row.id.String(), Detail: row.what})
	if err != nil {
		return previous, err
	}
	semanticHash := sha256.Sum256(payload)
	action := row.kind + ".created"
	hash, err := audit.HashEvent(audit.EventHashMaterial{PreviousHash: previous, EventID: eventID,
		ChangeID: changeID, AggregateKind: row.kind, AggregateID: row.id, AggregateVersion: 1,
		ActorPrincipalID: actorID, Action: action, Permission: deploymentAudit,
		CorrelationID: changeID, AfterSemanticHash: semanticHash, AuditPayloadHash: semanticHash,
		OutboxEventClass: "deployment.changed", OutboxPayloadHash: semanticHash})
	if err != nil {
		return previous, err
	}
	var appended int64
	if err := tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
$1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,$7::TEXT,$8::UUID,1,NULL::BIGINT,
$9::UUID,$10::TEXT,$11::TEXT,$12::UUID,NULL::BYTEA,$13::BYTEA,$14::JSONB,'deployment.changed',$14::JSONB)`,
		stream, eventID.String(), outboxID.String(), sequence, previous[:], hash[:], row.kind,
		row.id.String(), actorID.String(), action, deploymentAudit, changeID.String(), semanticHash[:], payload,
	).Scan(&appended); err != nil || appended != sequence {
		return previous, fmt.Errorf("append %s evidence failed: %w", row.kind, err)
	}
	return hash, nil
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
