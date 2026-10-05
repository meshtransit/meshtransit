// Command qualification-profile-lifetime changes one exact qualification
// enrollment profile with an audit/outbox record. It requires an operator DB
// login and rolls back unless --apply is supplied.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

type plan struct {
	deployment publicid.ID
	network    publicid.ID
	profile    publicid.ID
	from       int64
	to         int64
	apply      bool
}

func main() {
	deployment := flag.String("deployment-id", "", "exact Deployment public ID")
	network := flag.String("network-id", "", "exact qualification Network public ID")
	profile := flag.String("profile-id", "", "exact enrollment Profile public ID")
	from := flag.Int64("from-seconds", 0, "expected current Device lifetime")
	to := flag.Int64("to-seconds", 0, "new Device lifetime, up to 30 days")
	apply := flag.Bool("apply", false, "commit the audited change")
	flag.Parse()
	if flag.NArg() != 0 || *from < 3600 || *to <= *from || *to > 30*24*3600 {
		fail(errors.New("invalid qualification lifetime plan"))
	}
	p := plan{from: *from, to: *to, apply: *apply}
	var err error
	if p.deployment, err = publicid.Parse(*deployment); err != nil {
		fail(err)
	}
	if p.network, err = publicid.Parse(*network); err != nil {
		fail(err)
	}
	if p.profile, err = publicid.Parse(*profile); err != nil {
		fail(err)
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

func run(ctx context.Context, conn *pgx.Conn, p plan) (resultErr error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='15s'`); err != nil {
		return err
	}
	var schema int64
	var operator bool
	if err := tx.QueryRow(ctx, `SELECT (SELECT max(version) FROM mesh_ops.schema_migration), rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&schema, &operator); err != nil || !operator || schema < 90 {
		return errors.New("qualification requires operator login and schema 90 or newer")
	}
	var workspaceID, networkID, profileID, version, lifetime, revision, streamID, sequence int64
	var actorText string
	var previousBytes []byte
	err = tx.QueryRow(ctx, `SELECT w.id,n.id,p.id,p.version,p.node_lifetime_seconds,r.network_revision,s.id,s.next_sequence,s.latest_event_hash,owner.public_id::TEXT
FROM mesh.enrollment_profile AS p
JOIN mesh.network AS n ON n.id=p.network_id AND n.workspace_id=p.workspace_id
JOIN mesh.workspace AS w ON w.id=n.workspace_id
JOIN mesh.deployment AS d ON d.id=w.deployment_id
JOIN mesh.principal AS owner ON owner.id=w.owner_principal_id
JOIN mesh_ops.network_revision AS r ON r.workspace_id=w.id AND r.network_id=n.id
JOIN mesh_audit.audit_stream AS s ON s.deployment_id=d.id AND s.workspace_id=w.id AND s.network_id=n.id
WHERE d.installation_public_id=$1::UUID AND n.public_id=$2::UUID AND p.public_id=$3::UUID
AND d.state='active' AND w.state='active' AND n.state='active' AND p.state='active'
AND p.ephemeral_mode='persistent' AND p.interactive_authorization_enabled
FOR UPDATE OF p,r,s`, p.deployment.String(), p.network.String(), p.profile.String()).Scan(
		&workspaceID, &networkID, &profileID, &version, &lifetime, &revision, &streamID, &sequence, &previousBytes, &actorText)
	if err != nil || lifetime != p.from || version < 1 || revision < 1 || sequence < 1 || len(previousBytes) != sha256.Size {
		return errors.New("exact qualification Profile, expected lifetime, revision or audit stream unavailable")
	}
	actor, err := publicid.Parse(actorText)
	if err != nil {
		return err
	}
	if !p.apply {
		fmt.Printf("Plan valid: Profile %s in Network %s, lifetime %d -> %d seconds; transaction rolled back\n", p.profile, p.network, p.from, p.to)
		return nil
	}
	change, err := publicid.New()
	if err != nil {
		return err
	}
	event, err := publicid.New()
	if err != nil {
		return err
	}
	outbox, err := publicid.New()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('mesh.workspace_id',$1,TRUE),set_config('mesh.network_id',$2,TRUE),set_config('mesh.change_public_id',$3,TRUE)`, fmt.Sprint(workspaceID), fmt.Sprint(networkID), change.String()); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `UPDATE mesh.enrollment_profile SET node_lifetime_seconds=$1,version=version+1,updated_at=clock_timestamp() WHERE id=$2 AND version=$3 AND node_lifetime_seconds=$4`, p.to, profileID, version, p.from)
	if err != nil || result.RowsAffected() != 1 {
		return errors.New("exact qualification Profile update failed")
	}
	payload, err := json.Marshal(struct {
		Source, Profile, Network string
		From, To                 int64
	}{"qualification_profile_lifetime", p.profile.String(), p.network.String(), p.from, p.to})
	if err != nil {
		return err
	}
	semantic := sha256.Sum256(payload)
	var previous [sha256.Size]byte
	copy(previous[:], previousBytes)
	const action = "enrollment_profile.updated"
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previous, EventID: event, ChangeID: change,
		AggregateKind: "enrollment_profile", AggregateID: p.profile, AggregateVersion: version + 1,
		NetworkRevision: revision, ActorPrincipalID: actor, Action: action, Permission: "system.bootstrap",
		CorrelationID: change, AfterSemanticHash: semantic, AuditPayloadHash: semantic,
		OutboxEventClass: action, OutboxPayloadHash: semantic,
	})
	if err != nil {
		return err
	}
	var appended int64
	err = tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence($1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,'enrollment_profile',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,'system.bootstrap',$12::UUID,NULL::BYTEA,$13::BYTEA,$14::JSONB,$11::TEXT,$14::JSONB)`,
		streamID, event.String(), outbox.String(), sequence, previous[:], hash[:], p.profile.String(), version+1, revision, actor.String(), action, change.String(), semantic[:], payload).Scan(&appended)
	if err != nil || appended != sequence {
		return errors.New("qualification Profile evidence append failed")
	}
	if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("qualification Profile commit unknown; reconcile before retrying")
	}
	fmt.Printf("Committed Profile %s lifetime %d -> %d seconds with audit/outbox evidence\n", p.profile, p.from, p.to)
	return nil
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
