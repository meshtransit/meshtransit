package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	seedTimeout        = 30 * time.Second
	seedCleanupTimeout = 2 * time.Second

	qualificationIssuer       = "https://idp.qualification.example"
	qualificationDiscoveryURI = qualificationIssuer + "/.well-known/openid-configuration"
	qualificationJWKSURI      = qualificationIssuer + "/jwks"

	deviceManagePermission = "device.manage"
	maximumFixtureSessions = 16
)

type seedScope struct {
	deploymentInternalID         int64
	deploymentProfile            string
	recoveryEpoch                int64
	deploymentState              string
	deploymentRecoveryState      string
	principalInternalID          int64
	principalKind                string
	principalState               string
	principalAuthorityGeneration int64
	workspaceInternalID          int64
	workspaceState               string
	workspaceAuthorityGeneration int64
	networkInternalID            int64
	networkState                 string
	networkAuthorityGeneration   int64
	networkRevision              int64
}

type seedIDs struct {
	change             publicid.ID
	event              publicid.ID
	outbox             publicid.ID
	account            publicid.ID
	provider           publicid.ID
	providerGeneration publicid.ID
	providerClient     publicid.ID
	subject            publicid.ID
	session            publicid.ID
	membership         publicid.ID
	roleDefinition     publicid.ID
	rolePermission     publicid.ID
	roleBinding        publicid.ID
}

type seedAuthorityCounts struct {
	account            int64
	provider           int64
	providerGeneration int64
	providerClient     int64
	subject            int64
	session            int64
	membership         int64
	roleDefinition     int64
	rolePermission     int64
	roleBinding        int64
}

type seedAuditPayload struct {
	AuditReason       string `json:"audit_reason"`
	QualificationOnly bool   `json:"qualification_only"`
	SessionID         string `json:"account_session_public_id"`
	IdentitySubjectID string `json:"identity_subject_public_id"`
	MembershipID      string `json:"workspace_membership_public_id"`
	RoleDefinitionID  string `json:"role_definition_public_id"`
	RoleBindingID     string `json:"role_binding_public_id"`
	Permission        string `json:"permission"`
	ExpiresAt         string `json:"expires_at"`
}

type seedOutboxPayload struct {
	NetworkRevision int64  `json:"network_revision"`
	Fixture         string `json:"fixture"`
	ExpiresAt       string `json:"expires_at"`
}

type seedIdentityMaterial struct {
	issuerDigest  []byte
	subjectDigest []byte
	trustHash     [sha256.Size]byte
}

type publicIDGenerator func() (publicid.ID, error)

func executeSeed(
	ctx context.Context,
	spec seedSpec,
	database databaseSettings,
	entropy io.Reader,
) (output seedOutput, resultErr error) {
	if ctx == nil || !spec.isValid() || entropy == nil {
		return seedOutput{}, errInvalidInput
	}
	operationCtx, cancel := context.WithTimeout(ctx, seedTimeout)
	defer cancel()

	connection, err := openAdminDatabase(operationCtx, database)
	if err != nil {
		return seedOutput{}, err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			seedCleanupTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, connection.Close(cleanupCtx))
	}()

	initialScope, err := loadSeedScope(operationCtx, connection, loadSeedScopeSQL, spec)
	if err != nil {
		return seedOutput{}, err
	}
	if !initialScope.isValid() {
		return seedOutput{}, errInvalidInput
	}
	ids, err := newSeedIDs(publicid.New)
	if err != nil {
		return seedOutput{}, err
	}
	var material seedIdentityMaterial
	if !spec.renewExpiredFixture {
		material, err = newSeedIdentityMaterial(entropy)
		if err != nil {
			return seedOutput{}, err
		}
	}
	_, digest, bearerFile, err := prepareBearer(
		spec,
		database,
		initialScope.recoveryEpoch,
		entropy,
	)
	if err != nil {
		return seedOutput{}, err
	}
	keepBearer := false
	defer func() {
		if keepBearer {
			return
		}
		resultErr = errors.Join(resultErr, bearerFile.discard())
	}()

	transaction, err := connection.BeginTx(operationCtx, pgx.TxOptions{
		IsoLevel: pgx.Serializable,
	})
	if err != nil {
		return seedOutput{}, fmt.Errorf("begin qualification seed transaction: %w", err)
	}
	transactionClosed := false
	defer func() {
		if transactionClosed {
			return
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			seedCleanupTimeout,
		)
		defer rollbackCancel()
		resultErr = errors.Join(resultErr, transaction.Rollback(rollbackCtx))
	}()
	if _, err := transaction.Exec(operationCtx, configureSeedTransactionSQL); err != nil {
		return seedOutput{}, fmt.Errorf("configure qualification transaction: %w", err)
	}
	lockedScope, err := loadSeedScope(operationCtx, transaction, lockSeedScopeSQL, spec)
	if err != nil {
		return seedOutput{}, err
	}
	if lockedScope != initialScope || !lockedScope.isValid() {
		return seedOutput{}, errInvalidInput
	}
	counts, err := loadSeedAuthorityCounts(operationCtx, transaction, lockedScope)
	if err != nil {
		return seedOutput{}, err
	}
	if spec.renewExpiredFixture && !counts.isRenewable() {
		return seedOutput{}, errors.New("qualification identity authority is not renewable")
	}
	if !spec.renewExpiredFixture && !counts.isPristine() {
		return seedOutput{}, errors.New("qualification identity authority is not pristine")
	}
	var fixture renewalFixture
	var evaluatedAt time.Time
	if spec.renewExpiredFixture {
		fixture, evaluatedAt, err = loadRenewalFixture(
			operationCtx,
			transaction,
			lockedScope,
			spec,
			database,
		)
		if err != nil {
			return seedOutput{}, err
		}
	}
	if _, err := transaction.Exec(operationCtx, setSeedChangeSQL, ids.change.String()); err != nil {
		return seedOutput{}, fmt.Errorf("set qualification authority change: %w", err)
	}
	digestBytes := digest.Bytes()
	var result seedOutput
	if spec.renewExpiredFixture {
		renewal, renewalErr := renewFixtureAuthority(
			operationCtx,
			transaction,
			spec,
			database,
			lockedScope,
			fixture,
			ids.session,
			digestBytes,
			evaluatedAt,
		)
		if renewalErr != nil {
			return seedOutput{}, renewalErr
		}
		if renewalErr := appendRenewalEvidence(
			operationCtx,
			transaction,
			spec,
			lockedScope,
			ids,
			fixture,
			renewal,
		); renewalErr != nil {
			return seedOutput{}, renewalErr
		}
		result = seedOutput{
			Operation:         "renewed",
			SessionID:         ids.session.String(),
			IdentitySubjectID: fixture.subjectPublicID.String(),
			MembershipID:      fixture.membershipPublicID.String(),
			RoleDefinitionID:  fixture.roleDefinitionPublicID.String(),
			RoleBindingID:     fixture.bindingPublicID.String(),
			ExpiresAt:         renewal.expiresAt,
			Permission:        deviceManagePermission,
		}
	} else {
		expiresAt, insertErr := insertSeedAuthority(
			operationCtx,
			transaction,
			spec,
			database,
			lockedScope,
			ids,
			digestBytes,
			material,
		)
		if insertErr != nil {
			return seedOutput{}, insertErr
		}
		if evidenceErr := appendSeedEvidence(
			operationCtx,
			transaction,
			spec,
			lockedScope,
			ids,
			expiresAt,
		); evidenceErr != nil {
			return seedOutput{}, evidenceErr
		}
		result = seedOutput{
			Operation:         "seeded",
			SessionID:         ids.session.String(),
			IdentitySubjectID: ids.subject.String(),
			MembershipID:      ids.membership.String(),
			RoleDefinitionID:  ids.roleDefinition.String(),
			RoleBindingID:     ids.roleBinding.String(),
			ExpiresAt:         expiresAt.UTC(),
			Permission:        deviceManagePermission,
		}
	}
	if err := transaction.Commit(operationCtx); err != nil {
		return seedOutput{}, fmt.Errorf("commit qualification seed: %w", err)
	}
	transactionClosed = true
	if err := bearerFile.keep(); err != nil {
		return seedOutput{}, fmt.Errorf("retain bearer output: %w", err)
	}
	keepBearer = true
	return result, nil
}

type seedRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadSeedScope(
	ctx context.Context,
	database seedRowQuerier,
	query string,
	spec seedSpec,
) (seedScope, error) {
	var scope seedScope
	if database == nil || !spec.isValid() {
		return seedScope{}, errInvalidInput
	}
	err := database.QueryRow(
		ctx,
		query,
		spec.deploymentID.String(),
		spec.scope.WorkspaceID().String(),
		spec.scope.NetworkID().String(),
		spec.principalID.String(),
	).Scan(
		&scope.deploymentInternalID,
		&scope.deploymentProfile,
		&scope.recoveryEpoch,
		&scope.deploymentState,
		&scope.deploymentRecoveryState,
		&scope.principalInternalID,
		&scope.principalKind,
		&scope.principalState,
		&scope.principalAuthorityGeneration,
		&scope.workspaceInternalID,
		&scope.workspaceState,
		&scope.workspaceAuthorityGeneration,
		&scope.networkInternalID,
		&scope.networkState,
		&scope.networkAuthorityGeneration,
		&scope.networkRevision,
	)
	if err != nil {
		return seedScope{}, fmt.Errorf("resolve exact qualification scope: %w", err)
	}
	return scope, nil
}

func (scope seedScope) isValid() bool {
	return validPositiveInt64(scope.deploymentInternalID) &&
		scope.deploymentProfile == "self_hosted" &&
		validPositiveInt64(scope.recoveryEpoch) &&
		scope.deploymentState == "active" &&
		scope.deploymentRecoveryState == "verified" &&
		validPositiveInt64(scope.principalInternalID) &&
		scope.principalKind == "account" &&
		scope.principalState == "active" &&
		validPositiveInt64(scope.principalAuthorityGeneration) &&
		validPositiveInt64(scope.workspaceInternalID) &&
		scope.workspaceState == "active" &&
		validPositiveInt64(scope.workspaceAuthorityGeneration) &&
		validPositiveInt64(scope.networkInternalID) &&
		scope.networkState == "active" &&
		validPositiveInt64(scope.networkAuthorityGeneration) &&
		validPositiveInt64(scope.networkRevision)
}

func loadSeedAuthorityCounts(
	ctx context.Context,
	database seedRowQuerier,
	scope seedScope,
) (seedAuthorityCounts, error) {
	var counts seedAuthorityCounts
	err := database.QueryRow(
		ctx,
		countSeedAuthoritySQL,
		scope.deploymentInternalID,
		scope.workspaceInternalID,
	).Scan(
		&counts.account,
		&counts.provider,
		&counts.providerGeneration,
		&counts.providerClient,
		&counts.subject,
		&counts.session,
		&counts.membership,
		&counts.roleDefinition,
		&counts.rolePermission,
		&counts.roleBinding,
	)
	if err != nil {
		return seedAuthorityCounts{}, fmt.Errorf("inspect qualification authority baseline: %w", err)
	}
	return counts, nil
}

func (counts seedAuthorityCounts) isPristine() bool {
	return counts == seedAuthorityCounts{}
}

func (counts seedAuthorityCounts) isRenewable() bool {
	return counts.account == 1 && counts.provider == 1 &&
		counts.providerGeneration == 1 && counts.providerClient == 1 &&
		counts.subject == 1 && counts.session >= 1 &&
		counts.session <= maximumFixtureSessions && counts.membership == 1 &&
		counts.roleDefinition == 1 && counts.rolePermission == 1 &&
		counts.roleBinding == 1
}

func newSeedIDs(generator publicIDGenerator) (seedIDs, error) {
	if generator == nil {
		return seedIDs{}, errInvalidInput
	}
	values := make([]publicid.ID, 13)
	seen := make(map[string]struct{}, len(values))
	for index := range values {
		value, err := generator()
		if err != nil || !value.IsValid() {
			return seedIDs{}, fmt.Errorf("generate qualification public id: %w", err)
		}
		if _, found := seen[value.String()]; found {
			return seedIDs{}, errInvalidInput
		}
		seen[value.String()] = struct{}{}
		values[index] = value
	}
	return seedIDs{
		change: values[0], event: values[1], outbox: values[2],
		account: values[3], provider: values[4], providerGeneration: values[5],
		providerClient: values[6], subject: values[7], session: values[8],
		membership: values[9], roleDefinition: values[10],
		rolePermission: values[11], roleBinding: values[12],
	}, nil
}

func newSeedIdentityMaterial(entropy io.Reader) (seedIdentityMaterial, error) {
	key := make([]byte, sha256.Size)
	defer clear(key)
	if _, err := io.ReadFull(entropy, key); err != nil {
		return seedIdentityMaterial{}, fmt.Errorf("read synthetic identity entropy: %w", err)
	}
	allZero := true
	for _, value := range key {
		allZero = allZero && value == 0
	}
	if allZero {
		return seedIdentityMaterial{}, errInvalidInput
	}
	issuerDigest := qualificationHMAC(key, "issuer", qualificationIssuer)
	subjectDigest := qualificationHMAC(key, "subject", "qualification-subject")
	trustHash := qualificationTrustHash()
	return seedIdentityMaterial{
		issuerDigest: issuerDigest, subjectDigest: subjectDigest, trustHash: trustHash,
	}, nil
}

func qualificationTrustHash() [sha256.Size]byte {
	return sha256.Sum256([]byte(
		qualificationIssuer + "\x00" + qualificationDiscoveryURI + "\x00" +
			qualificationJWKSURI + "\x00meshtransit-qualification",
	))
}

func qualificationHMAC(key []byte, purpose, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("meshtransit/qualification-synthetic-identity/v1\x00"))
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
