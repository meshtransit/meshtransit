package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/publicid"
)

// WorkspaceFeatureConnectionLogs is the paid connection log feature
// (connection logs design §16b C22).
const WorkspaceFeatureConnectionLogs = "connection_logs"

var (
	// ErrWorkspaceFeatureInvalid reports an unknown feature, Workspace ID
	// or a note out of bounds.
	ErrWorkspaceFeatureInvalid = errors.New("postgres: invalid workspace feature change")
	// ErrWorkspaceNotFound reports an unknown Workspace.
	ErrWorkspaceNotFound = errors.New("postgres: workspace not found")
	// ErrWorkspaceFeatureUnavailable reports a database failure.
	ErrWorkspaceFeatureUnavailable = errors.New("postgres: workspace features unavailable")
)

const (
	lookupFeatureWorkspaceSQL = `SELECT workspace.id, deployment.installation_public_id::TEXT
FROM mesh.workspace AS workspace JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
WHERE workspace.public_id = $1::UUID`
	grantWorkspaceFeatureSQL = `INSERT INTO mesh.workspace_feature (public_id, workspace_id, feature, note, granted_at, version)
VALUES ($1::UUID, $2::BIGINT, $3::TEXT, $4::TEXT, pg_catalog.transaction_timestamp(), 1)
ON CONFLICT (workspace_id, feature) DO NOTHING
RETURNING public_id::TEXT, version`
	revokeWorkspaceFeatureSQL = `DELETE FROM mesh.workspace_feature AS feature
WHERE feature.workspace_id = $1::BIGINT AND feature.feature = $2::TEXT
RETURNING feature.public_id::TEXT, feature.version`
	// Networks that keep logging on after a revoke: they stop getting
	// tickets at their next renewal (s4b), so the operator sees how many.
	enabledConnectionLogNetworksSQL = `SELECT pg_catalog.count(*) FROM mesh.network_connection_log AS settings
WHERE settings.workspace_id = $1::BIGINT AND settings.enabled`
	appendWorkspaceFeatureEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'workspace_feature',$7::UUID,$8::BIGINT,NULL::BIGINT,NULL::UUID,$9::TEXT,
 'system.operator',$10::UUID,NULL::BYTEA,$11::BYTEA,$12::JSONB,$9::TEXT,$12::JSONB)`
	// workspaceFeaturePermission marks an operator's change in the audit
	// trail, as for an operator's CA change.
	workspaceFeaturePermission = "system.operator"
	listWorkspaceFeaturesSQL   = `SELECT feature.feature, feature.note, feature.granted_at FROM mesh.workspace_feature AS feature
WHERE feature.workspace_id = $1::BIGINT ORDER BY feature.feature`
)

// WorkspaceFeature is one feature an operator granted a Workspace.
type WorkspaceFeature struct {
	Feature   string
	Note      string
	GrantedAt time.Time
}

// WorkspaceFeatureReport is a Workspace's features after a change, and
// whether the change changed anything.
type WorkspaceFeatureReport struct {
	Changed  bool
	Features []WorkspaceFeature
	// EnabledNetworks counts the Workspace's Networks with logging on.
	EnabledNetworks int64
}

// workspaceFeatureChange is one grant or revoke as the audit event names
// it.
type workspaceFeatureChange struct {
	workspaceID publicid.ID
	deployment  string
	feature     string
	note        string
	grant       bool
	actor       string
	release     string
}

// ChangeWorkspaceFeature grants (grant) or revokes a feature of a
// Workspace as the migration role, with the migration database
// credentials; never through the API (C22). The table's authority capture
// records the change under its change ID. note says why (a ticket, an
// order) and is required to grant.
func ChangeWorkspaceFeature(ctx context.Context, options MigrationOptions, workspaceID publicid.ID, feature string,
	grant bool, note string,
) (WorkspaceFeatureReport, error) {
	if feature != WorkspaceFeatureConnectionLogs || grant && !validFeatureNote(note) {
		return WorkspaceFeatureReport{}, ErrWorkspaceFeatureInvalid
	}
	return runWorkspaceFeature(ctx, options, workspaceID, func(tx pgx.Tx, workspace int64, deployment string) (bool, error) {
		changeID, err := publicid.New()
		if err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`,
			changeID.String()); err != nil {
			return false, err
		}
		var row pgx.Row
		if grant {
			rowID, err := publicid.New()
			if err != nil {
				return false, err
			}
			row = tx.QueryRow(ctx, grantWorkspaceFeatureSQL, rowID.String(), workspace, feature, note)
		} else {
			row = tx.QueryRow(ctx, revokeWorkspaceFeatureSQL, workspace, feature)
		}
		var rowText string
		var version int64
		if err := row.Scan(&rowText, &version); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		aggregate, err := publicid.Parse(rowText)
		if err != nil || version < 1 {
			return false, ErrWorkspaceFeatureUnavailable
		}
		return true, appendWorkspaceFeatureEvidence(ctx, tx, workspaceFeatureChange{
			workspaceID: workspaceID, deployment: deployment, feature: feature, note: note, grant: grant,
			actor: options.Actor, release: options.CodeRelease,
		}, changeID, aggregate, version)
	})
}

// appendWorkspaceFeatureEvidence appends the change's sealed event to the
// Workspace's stream: who ran it is in the payload, with no principal.
func appendWorkspaceFeatureEvidence(ctx context.Context, tx pgx.Tx, change workspaceFeatureChange,
	changeID, aggregate publicid.ID, version int64,
) error {
	event, eventErr := publicid.New()
	outbox, outboxErr := publicid.New()
	if eventErr != nil || outboxErr != nil {
		return errors.Join(eventErr, outboxErr)
	}
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, lockWorkspaceStreamHeadSQL, change.deployment, change.workspaceID.String()).
		Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return ErrWorkspaceFeatureUnavailable
	}
	action := "workspace_feature.revoked"
	if change.grant {
		action = "workspace_feature.granted"
	}
	payload, err := json.Marshal(struct {
		WorkspaceID string `json:"workspace_id"`
		Feature     string `json:"feature"`
		Note        string `json:"note,omitempty"`
		ChangedBy   string `json:"changed_by"`
		CodeRelease string `json:"code_release"`
	}{change.workspaceID.String(), change.feature, change.note, change.actor, change.release})
	if err != nil {
		return err
	}
	after := sha256.Sum256(payload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [sha256.Size]byte(previous), EventID: event, ChangeID: changeID,
		AggregateKind: "workspace_feature", AggregateID: aggregate, AggregateVersion: version,
		Action: action, Permission: workspaceFeaturePermission, CorrelationID: changeID,
		AfterSemanticHash: after, AuditPayloadHash: after, OutboxEventClass: action, OutboxPayloadHash: after,
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendWorkspaceFeatureEvidenceSQL, streamID, event.String(), outbox.String(),
		sequence, previous, eventHash[:], aggregate.String(), version, action, changeID.String(), after[:],
		payload).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return ErrWorkspaceFeatureUnavailable
	}
	return nil
}

// ListWorkspaceFeatures lists a Workspace's features as the migration role.
func ListWorkspaceFeatures(ctx context.Context, options MigrationOptions, workspaceID publicid.ID,
) (WorkspaceFeatureReport, error) {
	return runWorkspaceFeature(ctx, options, workspaceID, func(pgx.Tx, int64, string) (bool, error) { return false, nil })
}

func validFeatureNote(note string) bool {
	return len(note) > 0 && len(note) <= 200 && strings.TrimSpace(note) == note &&
		!strings.ContainsFunc(note, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func runWorkspaceFeature(ctx context.Context, options MigrationOptions, workspaceID publicid.ID,
	change func(tx pgx.Tx, workspace int64, deployment string) (bool, error),
) (_ WorkspaceFeatureReport, resultErr error) {
	if ctx == nil || !workspaceID.IsValid() || !validMigrationMetadata(options.Actor) ||
		!validMigrationMetadata(options.CodeRelease) {
		return WorkspaceFeatureReport{}, ErrWorkspaceFeatureInvalid
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(options, password, caPEM)
	if err != nil {
		return WorkspaceFeatureReport{}, err
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-workspace-feature"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(closeContext))
	}()
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	defer func() {
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(rollbackContext); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('lock_timeout', $1, TRUE),
 pg_catalog.set_config('statement_timeout', $2, TRUE)`,
		postgresTimeoutValue(options.LockTimeout), postgresTimeoutValue(options.StatementTimeout)); err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	// The exact ID sets the Workspace's row scope; it grants nothing.
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.requested_workspace_public_id', $1, TRUE)`,
		workspaceID.String()); err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	var workspace int64
	var deployment string
	if err := tx.QueryRow(ctx, lookupFeatureWorkspaceSQL, workspaceID.String()).Scan(&workspace, &deployment); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return WorkspaceFeatureReport{}, ErrWorkspaceNotFound
		}
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', $1, TRUE)`,
		strconv.FormatInt(workspace, 10)); err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	changed, err := change(tx, workspace, deployment)
	if err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	rows, err := tx.Query(ctx, listWorkspaceFeaturesSQL, workspace)
	if err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	report := WorkspaceFeatureReport{Changed: changed, Features: []WorkspaceFeature{}}
	for rows.Next() {
		var item WorkspaceFeature
		if err := rows.Scan(&item.Feature, &item.Note, &item.GrantedAt); err != nil {
			rows.Close()
			return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
		}
		item.GrantedAt = item.GrantedAt.UTC()
		report.Features = append(report.Features, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	if err := tx.QueryRow(ctx, enabledConnectionLogNetworksSQL, workspace).Scan(&report.EnabledNetworks); err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return WorkspaceFeatureReport{}, errors.Join(ErrWorkspaceFeatureUnavailable, err)
	}
	slices.SortFunc(report.Features, func(a, b WorkspaceFeature) int { return strings.Compare(a.Feature, b.Feature) })
	return report, nil
}
