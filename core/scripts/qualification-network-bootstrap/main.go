// Command qualification-network-bootstrap creates one audited Network without
// packet allow rules in a disposable qualification installation. It is not a
// serving API and requires the database operator login, never a runtime login.
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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/publicid"
)

type plan struct {
	deployment, workspace, owner publicid.ID
	name                         string
	prefixes                     []netip.Prefix
	apply                        bool
}

type mutation struct {
	kind              string
	id, event, outbox publicid.ID
}

func main() {
	deployment := flag.String("deployment-id", "", "qualification Deployment public ID")
	workspace := flag.String("workspace-id", "", "existing qualification Workspace public ID")
	owner := flag.String("owner-id", "", "existing Workspace owner's public ID")
	name := flag.String("name", "", "new qualification Network name")
	ipv4 := flag.String("ipv4-prefix", "", "disjoint IPv4 Network prefix")
	ipv6 := flag.String("ipv6-prefix", "", "disjoint IPv6 Network prefix")
	apply := flag.Bool("apply", false, "commit the reviewed qualification Network")
	flag.Parse()
	p, err := parsePlan(*deployment, *workspace, *owner, *name, *ipv4, *ipv6, *apply)
	if err != nil || flag.NArg() != 0 {
		fail(errors.New("invalid qualification plan"))
	}
	dsn := os.Getenv("MESHTRANSIT_QUALIFICATION_DSN")
	if dsn == "" {
		fail(errors.New("MESHTRANSIT_QUALIFICATION_DSN is required"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fail(errors.New("qualification database connection failed"))
	}
	err = run(ctx, conn, p)
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	closeErr := conn.Close(cleanup)
	stop()
	if err != nil {
		fail(err)
	}
	if closeErr != nil {
		fail(errors.New("qualification database close failed"))
	}
}

func parsePlan(deployment, workspace, owner, name, ipv4, ipv6 string, apply bool) (plan, error) {
	p := plan{name: strings.TrimSpace(name), apply: apply}
	var err error
	for _, field := range []struct {
		text string
		id   *publicid.ID
	}{{deployment, &p.deployment}, {workspace, &p.workspace}, {owner, &p.owner}} {
		*field.id, err = publicid.Parse(field.text)
		if err != nil {
			return plan{}, err
		}
	}
	if len(p.name) < 1 || len(p.name) > 80 || !utf8.ValidString(p.name) || strings.ContainsFunc(p.name, unicode.IsControl) {
		return plan{}, errors.New("invalid name")
	}
	for family, value := range []string{ipv4, ipv6} {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Is4() != (family == 0) ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() ||
			(family == 0 && (prefix.Bits() < 24 || prefix.Bits() > 30)) || (family == 1 && (prefix.Bits() < 64 || prefix.Bits() > 120)) {
			return plan{}, errors.New("invalid qualification prefix")
		}
		p.prefixes = append(p.prefixes, prefix)
	}
	return p, nil
}

func run(ctx context.Context, conn *pgx.Conn, p plan) (resultErr error) {
	change, err := publicid.New()
	if err != nil {
		return err
	}
	changes := make([]mutation, 0, 5)
	for _, kind := range []string{"network", "network_prefix", "network_prefix", "network_membership", "enrollment_profile"} {
		m := mutation{kind: kind}
		for _, field := range []*publicid.ID{&m.id, &m.event, &m.outbox} {
			*field, err = publicid.New()
			if err != nil {
				return err
			}
		}
		changes = append(changes, m)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return errors.New("qualification transaction failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, errors.New("qualification rollback failed"))
		}
	}()
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='15s'`); err != nil {
		return err
	}
	var user string
	var schema int64
	var operator bool
	if err = tx.QueryRow(ctx, `SELECT current_user,(SELECT max(version) FROM mesh_ops.schema_migration),rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&user, &schema, &operator); err != nil {
		return err
	}
	if !operator || schema != 87 {
		return errors.New("qualification requires the operator login and reviewed schema 87")
	}
	var deployment, workspace, owner, membership int64
	err = tx.QueryRow(ctx, `SELECT d.id,w.id,p.id,m.id FROM mesh.deployment d
JOIN mesh.workspace w ON w.deployment_id=d.id JOIN mesh.principal p ON p.id=w.owner_principal_id
JOIN mesh.workspace_membership m ON m.deployment_id=d.id AND m.workspace_id=w.id AND m.principal_id=p.id
WHERE d.installation_public_id=$1::UUID AND w.public_id=$2::UUID AND p.public_id=$3::UUID
AND d.state='active' AND d.recovery_state='verified' AND w.state='active' AND p.state='active'
AND m.state='active' AND m.valid_from<=clock_timestamp() AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp())
FOR UPDATE OF w,m`, p.deployment.String(), p.workspace.String(), p.owner.String()).Scan(&deployment, &workspace, &owner, &membership)
	if err != nil {
		return errors.New("exact active qualification owner and Workspace membership are unavailable")
	}
	var pools, realms [2]int64
	for index, prefix := range p.prefixes {
		family := 6
		if prefix.Addr().Is4() {
			family = 4
		}
		var poolCount int64
		err = tx.QueryRow(ctx, `SELECT count(*),COALESCE(min(pool.id),0),COALESCE(min(pool.address_realm_id),0)
FROM mesh.address_pool pool JOIN mesh.address_realm realm ON realm.id=pool.address_realm_id
WHERE pool.deployment_id=$1 AND pool.workspace_id=$2 AND pool.purpose='node_overlay' AND pool.family=$3
AND pool.state='active' AND realm.state='active' AND realm.kind='workspace_overlay' AND $4::CIDR <<= pool.prefix`, deployment, workspace, family, prefix.String()).Scan(&poolCount, &pools[index], &realms[index])
		if err != nil {
			return err
		}
		if poolCount != 1 {
			return errors.New("qualification prefix has no unambiguous active overlay pool")
		}
	}
	var network, stream int64
	if err = tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('mesh.network','id'))`).Scan(&network); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('mesh.workspace_id',$1,TRUE),set_config('mesh.network_id',$2,TRUE),set_config('mesh.change_public_id',$3,TRUE)`, fmt.Sprint(workspace), fmt.Sprint(network), change.String()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mesh.network (id,public_id,workspace_id,display_name,name_key,node_limit,state) OVERRIDING SYSTEM VALUE VALUES ($1,$2::UUID,$3,$4,$5,100,'active')`, network, changes[0].id.String(), workspace, p.name, strings.ToLower(p.name)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mesh_ops.network_revision(workspace_id,network_id) VALUES ($1,$2)`, workspace, network); err != nil {
		return err
	}
	for index, prefix := range p.prefixes {
		family := 6
		if prefix.Addr().Is4() {
			family = 4
		}
		if _, err = tx.Exec(ctx, `INSERT INTO mesh.network_prefix(public_id,workspace_id,network_id,address_realm_id,address_pool_id,prefix,family,state) VALUES ($1::UUID,$2,$3,$4,$5,$6::CIDR,$7,'active')`, changes[index+1].id.String(), workspace, network, realms[index], pools[index], prefix.String(), family); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mesh.network_membership(public_id,deployment_id,workspace_id,network_id,principal_id,workspace_membership_id,state,valid_from) VALUES ($1::UUID,$2,$3,$4,$5,$6,'active',clock_timestamp())`, changes[3].id.String(), deployment, workspace, network, owner, membership); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mesh.enrollment_profile(public_id,workspace_id,network_id,created_by_principal_id,display_name,name_key,node_lifetime_seconds,ephemeral_mode,credential_use_policy,state,interactive_authorization_enabled) VALUES ($1::UUID,$2,$3,$4,'Qualification browser login','qualification-browser-login',2592000,'persistent','unlimited','active',TRUE)`, changes[4].id.String(), workspace, network, owner); err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO mesh_audit.audit_stream(deployment_id,workspace_id,network_id,scope_kind) VALUES ($1,$2,$3,'network') RETURNING id`, deployment, workspace, network).Scan(&stream); err != nil {
		return err
	}
	var previous [sha256.Size]byte
	for index, m := range changes {
		previous, err = appendEvidence(ctx, tx, p, change, m, stream, int64(index+1), previous)
		if err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		return err
	}
	if !p.apply {
		fmt.Println("Plan valid: complete scoped Network, disjoint prefixes, owner membership and interactive enrollment evidence checked; transaction rolls back. No packet rule, RBAC binding or credential is created.")
		return nil
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.New("qualification commit unknown; reconcile by Network name before retrying")
	}
	fmt.Println("Committed audited qualification Network", changes[0].id.String(), "without packet allow rules or issued credentials")
	return nil
}

func appendEvidence(ctx context.Context, tx pgx.Tx, p plan, change publicid.ID, m mutation, stream, sequence int64, previous [sha256.Size]byte) ([sha256.Size]byte, error) {
	payload, err := json.Marshal(struct{ Source, Target, NetworkName string }{"qualification_network_bootstrap", m.id.String(), p.name})
	if err != nil {
		return previous, err
	}
	semantic := sha256.Sum256(payload)
	action := m.kind + ".created"
	hash, err := audit.HashEvent(audit.EventHashMaterial{PreviousHash: previous, EventID: m.event, ChangeID: change, AggregateKind: m.kind, AggregateID: m.id, AggregateVersion: 1, NetworkRevision: 1, ActorPrincipalID: p.owner, Action: action, Permission: "system.bootstrap", CorrelationID: change, AfterSemanticHash: semantic, AuditPayloadHash: semantic, OutboxEventClass: action, OutboxPayloadHash: semantic})
	if err != nil {
		return previous, err
	}
	var appended int64
	err = tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence($1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,$7::TEXT,$8::UUID,1,1,$9::UUID,$10::TEXT,'system.bootstrap',$11::UUID,NULL::BYTEA,$12::BYTEA,$13::JSONB,$10::TEXT,$13::JSONB)`, stream, m.event.String(), m.outbox.String(), sequence, previous[:], hash[:], m.kind, m.id.String(), p.owner.String(), action, change.String(), semantic[:], payload).Scan(&appended)
	if err != nil {
		return previous, err
	}
	if appended != sequence {
		return previous, errors.New("qualification evidence sequence mismatch")
	}
	return hash, nil
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
