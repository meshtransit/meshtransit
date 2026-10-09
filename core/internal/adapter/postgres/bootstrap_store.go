package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/platform/bootstrap"
)

const (
	bootstrapMinimumSchema = 98
	bootstrapPermission    = "system.bootstrap"
	bootstrapCredentialRef = "secret://meshtransit/private-login/client-secret"
)

var (
	// ErrBootstrapConflict reports existing rows that differ from the plan.
	// Bootstrap never changes existing authority.
	ErrBootstrapConflict = errors.New("postgres: bootstrap conflicts with existing authority")
	// ErrBootstrapUnavailable reports an unavailable or uncertain apply.
	ErrBootstrapUnavailable = errors.New("postgres: bootstrap unavailable")
)

// BootstrapReport counts created rows. Existing rows are verified only.
type BootstrapReport struct {
	DeploymentCreated, ProviderCreated bool
	AccountsCreated, AccountsExisting  int
	WorkspacesCreated                  int
}

// ApplyBootstrap applies one plan in one transaction as the migration role.
// With commit false the complete transaction runs, every check and deferred
// constraint is evaluated, and it rolls back.
func ApplyBootstrap(ctx context.Context, options MigrationOptions, plan bootstrap.Plan, commit bool) (
	_ BootstrapReport, resultErr error) {
	// bootstrap.NewPlan already decides whether a plan may omit Accounts
	// (Cloud may, self-hosted may not).
	if ctx == nil || !plan.Profile.IsValid() || !plan.Route.IsValid() {
		return BootstrapReport{}, ErrInvalidMigrationOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return BootstrapReport{}, errors.Join(ErrBootstrapUnavailable, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return BootstrapReport{}, errors.Join(ErrBootstrapUnavailable, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(options, password, caPEM)
	if err != nil {
		return BootstrapReport{}, err
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-bootstrap"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return BootstrapReport{}, errors.Join(ErrBootstrapUnavailable, err)
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(closeContext))
	}()
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return BootstrapReport{}, errors.Join(ErrBootstrapUnavailable, err)
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
		return BootstrapReport{}, errors.Join(ErrBootstrapUnavailable, err)
	}
	report, err := applyBootstrapPlan(ctx, tx, plan)
	if err != nil {
		return BootstrapReport{}, err
	}
	if !commit {
		// Deferred evidence constraints run at commit; force them now.
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			return BootstrapReport{}, errors.Join(ErrBootstrapConflict, err)
		}
		return report, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return BootstrapReport{}, errors.Join(ErrBootstrapUnavailable, ErrMigrationCommitUncertain, err)
	}
	return report, nil
}

func applyBootstrapPlan(ctx context.Context, tx pgx.Tx, plan bootstrap.Plan) (BootstrapReport, error) {
	var schema int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM mesh_ops.schema_migration`).Scan(&schema); err != nil {
		return BootstrapReport{}, errors.Join(ErrBootstrapUnavailable, err)
	}
	if schema < bootstrapMinimumSchema {
		return BootstrapReport{}, fmt.Errorf("%w: schema %d is older than %d", ErrBootstrapConflict, schema, bootstrapMinimumSchema)
	}
	var report BootstrapReport
	deploymentID, created, err := ensureBootstrapDeployment(ctx, tx, plan)
	if err != nil {
		return BootstrapReport{}, err
	}
	report.DeploymentCreated = created
	providerID, clientID, created, err := ensureBootstrapProvider(ctx, tx, plan, deploymentID)
	if err != nil {
		return BootstrapReport{}, err
	}
	report.ProviderCreated = created
	for _, account := range plan.Accounts {
		principalID, created, err := ensureBootstrapAccount(ctx, tx, plan, deploymentID, providerID, account)
		if err != nil {
			return BootstrapReport{}, err
		}
		if !created {
			report.AccountsExisting++
			continue
		}
		report.AccountsCreated++
		workspaceID, err := publicid.New()
		if err != nil {
			return BootstrapReport{}, ErrBootstrapUnavailable
		}
		if err := provisionBootstrapWorkspace(ctx, tx, plan, deploymentID, principalID, providerID, clientID,
			workspaceID, account.WorkspaceName); err != nil {
			return BootstrapReport{}, err
		}
		report.WorkspacesCreated++
	}
	return report, nil
}

type bootstrapChange struct {
	change, event, outbox publicid.ID
}

func newBootstrapChange(ctx context.Context, tx pgx.Tx) (bootstrapChange, error) {
	var ids [3]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return bootstrapChange{}, ErrBootstrapUnavailable
		}
		ids[index] = id
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`, ids[0].String()); err != nil {
		return bootstrapChange{}, errors.Join(ErrBootstrapUnavailable, err)
	}
	return bootstrapChange{change: ids[0], event: ids[1], outbox: ids[2]}, nil
}

// appendBootstrapEvidence records one system.bootstrap audit/outbox event for
// the change's main aggregate on the Deployment stream, or on the new
// Workspace's own stream when the aggregate is that Workspace.
func appendBootstrapEvidence(ctx context.Context, tx pgx.Tx, deploymentPublicID string, ids bootstrapChange,
	kind string, aggregate publicid.ID, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var streamID, sequence int64
	var previous []byte
	headSQL, headArguments := `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_deployment_stream_head($1::UUID)`, []any{deploymentPublicID}
	if kind == "workspace" {
		headSQL, headArguments = lockWorkspaceStreamHeadSQL, []any{deploymentPublicID, aggregate.String()}
	}
	if err := tx.QueryRow(ctx, headSQL, headArguments...).Scan(&streamID, &sequence, &previous); err != nil {
		return errors.Join(ErrBootstrapUnavailable, err)
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return ErrBootstrapUnavailable
	}
	action := kind + ".created"
	after := sha256.Sum256(encoded)
	var previousHash [32]byte
	copy(previousHash[:], previous)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: ids.event, ChangeID: ids.change,
		AggregateKind: kind, AggregateID: aggregate, AggregateVersion: 1,
		Action: action, Permission: bootstrapPermission, CorrelationID: ids.change,
		AfterSemanticHash: after, AuditPayloadHash: after,
		OutboxEventClass: action, OutboxPayloadHash: after,
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,$7::TEXT,$8::UUID,1,NULL::BIGINT,NULL::UUID,
 $9::TEXT,'system.bootstrap',$10::UUID,NULL::BYTEA,$11::BYTEA,$12::JSONB,$9::TEXT,$12::JSONB)`,
		streamID, ids.event.String(), ids.outbox.String(), sequence, previousHash[:], eventHash[:], kind,
		aggregate.String(), action, ids.change.String(), after[:], encoded).Scan(&appended); err != nil {
		return errors.Join(ErrBootstrapUnavailable, err)
	}
	return nil
}

func ensureBootstrapDeployment(ctx context.Context, tx pgx.Tx, plan bootstrap.Plan) (int64, bool, error) {
	publicID := plan.Route.DeploymentID().String()
	var id, epoch int64
	var profile, state, recovery string
	err := tx.QueryRow(ctx, `SELECT id, profile, state, recovery_state, recovery_epoch
FROM mesh.deployment WHERE installation_public_id = $1::UUID`, publicID).Scan(&id, &profile, &state, &recovery, &epoch)
	if err == nil {
		if profile != string(plan.Profile) || state != "active" || recovery != "verified" ||
			epoch != plan.Route.RecoveryEpoch() {
			return 0, false, fmt.Errorf("%w: Deployment profile, state or recovery epoch differs", ErrBootstrapConflict)
		}
		return id, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, false, errors.Join(ErrBootstrapUnavailable, err)
	}
	ids, err := newBootstrapChange(ctx, tx)
	if err != nil {
		return 0, false, err
	}
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.deployment (
 installation_public_id, profile, state, schema_epoch, authority_generation, recovery_epoch, recovery_state
) VALUES ($1::UUID, $2, 'active', 1, 1, $3, 'verified') RETURNING id`,
		publicID, string(plan.Profile), plan.Route.RecoveryEpoch()).Scan(&id); err != nil {
		return 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mesh_audit.audit_stream (deployment_id, scope_kind)
VALUES ($1, 'deployment')`, id); err != nil {
		return 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if err := appendBootstrapEvidence(ctx, tx, publicID, ids, "deployment",
		publicid.ID(plan.Route.DeploymentID()), map[string]any{"profile": plan.Profile}); err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func ensureBootstrapProvider(ctx context.Context, tx pgx.Tx, plan bootstrap.Plan, deploymentID int64) (
	int64, int64, bool, error) {
	route := plan.Route
	var providerID, clientID, generation int64
	var issuer, discovery, authorization, token, jwks, oidcClientID string
	var scopes, algorithms, redirects []string
	err := tx.QueryRow(ctx, `SELECT p.id, c.id, p.current_generation, p.issuer, p.discovery_uri,
 COALESCE(p.authorization_endpoint,''), COALESCE(p.token_endpoint,''), p.jwks_uri,
 c.client_id, c.allowed_scopes, c.allowed_algorithms, c.redirect_uris
FROM mesh.identity_provider p
JOIN mesh.identity_provider_client c ON c.deployment_id = p.deployment_id AND c.identity_provider_id = p.id
WHERE p.deployment_id = $1 AND p.public_id = $2::UUID AND c.public_id = $3::UUID`,
		deploymentID, route.ProviderID().String(), route.ClientID().String()).Scan(&providerID, &clientID,
		&generation, &issuer, &discovery, &authorization, &token, &jwks, &oidcClientID, &scopes, &algorithms, &redirects)
	if err == nil {
		if generation != route.ProviderGeneration() || issuer != route.Issuer() || discovery != route.DiscoveryURI() ||
			authorization != route.AuthorizationEndpoint() || token != route.TokenEndpoint() || jwks != route.JWKSURI() ||
			oidcClientID != route.OIDCClientID() || !slices.Equal(scopes, route.Scopes()) ||
			!slices.Equal(algorithms, route.AllowedAlgorithms()) || !slices.Contains(redirects, route.RedirectURI()) {
			return 0, 0, false, fmt.Errorf("%w: identity provider or client differs from the login route", ErrBootstrapConflict)
		}
		return providerID, clientID, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, false, errors.Join(ErrBootstrapUnavailable, err)
	}
	if route.ProviderGeneration() != 1 {
		return 0, 0, false, fmt.Errorf("%w: a new provider starts at generation 1", ErrBootstrapConflict)
	}
	ids, err := newBootstrapChange(ctx, tx)
	if err != nil {
		return 0, 0, false, err
	}
	// No runtime path reads issuer_digest; it is keyed by a discarded random
	// key so it identifies nothing outside this row.
	issuerDigest, err := unrecoverableDigest(route.Issuer())
	if err != nil {
		return 0, 0, false, err
	}
	trust, err := json.Marshal(struct {
		Issuer, Discovery, Authorization, Token, JWKS string
	}{route.Issuer(), route.DiscoveryURI(), route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI()})
	if err != nil {
		return 0, 0, false, err
	}
	trustHash := sha256.Sum256(trust)
	generationID, err := publicid.New()
	if err != nil {
		return 0, 0, false, ErrBootstrapUnavailable
	}
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.identity_provider (
 public_id, deployment_id, issuer, issuer_digest_algorithm, issuer_digest_key_id, issuer_digest,
 protocol, authority_kind, discovery_uri, authorization_endpoint, token_endpoint, jwks_uri,
 current_generation, recovery_state, state
) VALUES ($1::UUID, $2, $3, 'hmac-sha256-v1', 'bootstrap-unrecoverable-v1', $4,
 'oidc', 'external_oidc', $5, $6, $7, $8, 1, 'verified', 'active') RETURNING id`,
		route.ProviderID().String(), deploymentID, route.Issuer(), issuerDigest[:], route.DiscoveryURI(),
		route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI()).Scan(&providerID); err != nil {
		return 0, 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mesh.identity_provider_generation (
 public_id, deployment_id, identity_provider_id, generation, trust_configuration_semantic_hash,
 recovery_mode, valid_from, state
) VALUES ($1::UUID, $2, $3, 1, $4, 'initial', pg_catalog.transaction_timestamp(), 'current')`,
		generationID.String(), deploymentID, providerID, trustHash[:]); err != nil {
		return 0, 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.identity_provider_client (
 public_id, deployment_id, identity_provider_id, client_kind, client_id, allowed_flows, allowed_scopes,
 allowed_algorithms, redirect_uris, post_logout_redirect_uris, pkce_s256_required, client_auth_method,
 credential_reference, state
) VALUES ($1::UUID, $2, $3, 'confidential', $4, ARRAY['authorization_code'], $5::TEXT[], $6::TEXT[],
 ARRAY[$7]::TEXT[], ARRAY[]::TEXT[], TRUE, 'client_secret_basic', $8, 'active') RETURNING id`,
		route.ClientID().String(), deploymentID, providerID, route.OIDCClientID(), route.Scopes(),
		route.AllowedAlgorithms(), route.RedirectURI(), bootstrapCredentialRef).Scan(&clientID); err != nil {
		return 0, 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if err := appendBootstrapEvidence(ctx, tx, route.DeploymentID().String(), ids, "identity_provider",
		publicid.ID(route.ProviderID()), map[string]any{
			"issuer": route.Issuer(), "client_id": route.ClientID().String(), "generation": 1,
		}); err != nil {
		return 0, 0, false, err
	}
	return providerID, clientID, true, nil
}

func unrecoverableDigest(value string) ([32]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return [32]byte{}, ErrBootstrapUnavailable
	}
	defer clear(key)
	digest := hmac.New(sha256.New, key)
	digest.Write([]byte(value))
	return [32]byte(digest.Sum(nil)), nil
}

func ensureBootstrapAccount(ctx context.Context, tx pgx.Tx, plan bootstrap.Plan, deploymentID, providerID int64,
	account bootstrap.Account) (int64, bool, error) {
	digest := account.SubjectDigest.Bytes()
	keyID := account.SubjectDigest.KeyID().String()
	var principalID int64
	err := tx.QueryRow(ctx, `SELECT principal_id FROM mesh.identity_subject
WHERE deployment_id = $1 AND identity_provider_id = $2 AND subject_digest_algorithm = 'hmac-sha256-v1'
  AND subject_digest_key_id = $3 AND subject_digest = $4 AND state <> 'deleted'`,
		deploymentID, providerID, keyID, digest[:]).Scan(&principalID)
	if err == nil {
		return principalID, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, false, errors.Join(ErrBootstrapUnavailable, err)
	}
	ids, err := newBootstrapChange(ctx, tx)
	if err != nil {
		return 0, false, err
	}
	var publicIDs [3]publicid.ID
	for index := range publicIDs {
		if publicIDs[index], err = publicid.New(); err != nil {
			return 0, false, ErrBootstrapUnavailable
		}
	}
	principalPublic, accountPublic, subjectPublic := publicIDs[0], publicIDs[1], publicIDs[2]
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.principal (public_id, deployment_id, kind, state)
VALUES ($1::UUID, $2, 'account', 'active') RETURNING id`, principalPublic.String(), deploymentID).Scan(&principalID); err != nil {
		return 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mesh.account (public_id, deployment_id, principal_id, display_name, recovery_state)
VALUES ($1::UUID, $2, $3, $4, 'verified')`, accountPublic.String(), deploymentID, principalID, account.DisplayName); err != nil {
		return 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mesh.identity_subject (
 public_id, deployment_id, identity_provider_id, principal_id, subject_digest_algorithm,
 subject_digest_key_id, subject_digest, last_seen_at, state
) VALUES ($1::UUID, $2, $3, $4, 'hmac-sha256-v1', $5, $6, pg_catalog.transaction_timestamp(), 'active')`,
		subjectPublic.String(), deploymentID, providerID, principalID, keyID, digest[:]); err != nil {
		return 0, false, errors.Join(ErrBootstrapConflict, err)
	}
	if err := appendBootstrapEvidence(ctx, tx, plan.Route.DeploymentID().String(), ids, "account", accountPublic,
		map[string]any{"principal_id": principalPublic.String(), "subject_id": subjectPublic.String()}); err != nil {
		return 0, false, err
	}
	return principalID, true, nil
}

func provisionBootstrapWorkspace(ctx context.Context, tx pgx.Tx, plan bootstrap.Plan, deploymentID, principalID,
	providerID, clientID int64, workspaceID publicid.ID, name string) error {
	ids, err := newBootstrapChange(ctx, tx)
	if err != nil {
		return err
	}
	var rowIDs [5]publicid.ID
	for index := range rowIDs {
		if rowIDs[index], err = publicid.New(); err != nil {
			return ErrBootstrapUnavailable
		}
	}
	prefix, err := randomWorkspaceULA()
	if err != nil {
		return err
	}
	var assurance any
	if plan.MinimumAssurance != "" {
		assurance = plan.MinimumAssurance
	}
	var created int64
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.provision_workspace_v1(
 $1, $2, $3::UUID, $4, $5::UUID, $6::UUID, $7, $8, $9, $10::UUID, $11::UUID, $12::UUID, $13::CIDR,
 pg_catalog.transaction_timestamp())`,
		deploymentID, principalID, workspaceID.String(), name, rowIDs[0].String(), rowIDs[1].String(), providerID,
		clientID, assurance, rowIDs[2].String(), rowIDs[3].String(), rowIDs[4].String(), prefix.String()).Scan(&created); err != nil {
		return errors.Join(ErrBootstrapConflict, err)
	}
	return appendBootstrapEvidence(ctx, tx, plan.Route.DeploymentID().String(), ids, "workspace", workspaceID,
		map[string]any{"ipv6_overlay": prefix.String()})
}

// randomWorkspaceULA picks an RFC 4193 /48 with a random 40-bit global ID.
func randomWorkspaceULA() (netip.Prefix, error) {
	var address [16]byte
	address[0] = 0xfd
	if _, err := rand.Read(address[1:6]); err != nil {
		return netip.Prefix{}, ErrBootstrapUnavailable
	}
	return netip.PrefixFrom(netip.AddrFrom16(address), 48), nil
}
