package postgres

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/flowlog"
)

// Schema 266: connection logs; schema 272: push destinations (v2).
const (
	listStorageCredentialsSQL = `SELECT mesh_ops.list_storage_credentials_v2(` + sessionArguments + `,
 $10::UUID)::TEXT`
	putStorageCredentialSQL = `SELECT mesh_ops.put_storage_credential_v2(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::TEXT,$14::TEXT,$15::TEXT,$16::JSONB,$17::TEXT,$18::BYTEA,$19::TEXT,$20::UUID[],
 $21::UUID)::TEXT`
	deleteStorageCredentialSQL = `SELECT mesh_ops.delete_storage_credential_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::UUID)::TEXT`
	readNetworkConnectionLogSQL = `SELECT mesh_ops.read_network_connection_log_v2(` + sessionArguments + `,
 $10::UUID,$11::UUID)::TEXT`
	replaceNetworkConnectionLogSQL = `SELECT mesh_ops.replace_network_connection_log_v2(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::BOOLEAN,$14::UUID,$15::TEXT,$16::TEXT,$17::TEXT,$18::BOOLEAN,$19::INTEGER,
 $20::TEXT,$21::TEXT,$22::TEXT,$23::TEXT,$24::TEXT[],$25::TEXT,$26::UUID)::TEXT`
)

// CredentialSealer seals storage secrets to the connection log receiver's
// credential key (design §16b C24); Core has no way to open them.
type CredentialSealer struct {
	KeyID string
	Key   *ecdh.PublicKey
}

// ConnectionLogStore keeps storage credentials and Network connection log
// settings.
type ConnectionLogStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
	// sealer is nil on a deployment without a receiver: credentials then
	// cannot be created or rotated.
	sealer *CredentialSealer
}

// NewConnectionLogStore uses the runtime pool.
func NewConnectionLogStore(pool *Pool, options AccountSessionOptions, sealer *CredentialSealer,
) (*ConnectionLogStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) ||
		sealer != nil && (sealer.Key == nil || !validSealingKeyID(sealer.KeyID)) {
		return nil, connectionlog.ErrInvalid
	}
	return &ConnectionLogStore{database: pool.workspaceRenameDatabase, options: options, sealer: sealer}, nil
}

func validSealingKeyID(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for _, r := range id {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !letter && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func connectionLogDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501", "23503":
			return connectionlog.ErrForbidden
		case "54000":
			return connectionlog.ErrLimit
		case "P0002":
			return connectionlog.ErrNotFound
		case "23505":
			if pgError.ConstraintName == "storage_credential_name_unique" {
				return connectionlog.ErrNameTaken
			}
			return connectionlog.ErrConflict
		case "40001", "40P01":
			return connectionlog.ErrConflict
		case "55006":
			return connectionlog.ErrInUse
		case "55000":
			return connectionlog.ErrNotAllowed
		case "22023", "22P02", "23514":
			return connectionlog.ErrInvalid
		}
	}
	return errors.Join(connectionlog.ErrUnavailable, err)
}

func (store *ConnectionLogStore) begin(ctx context.Context) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, connectionlog.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(connectionlog.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(connectionlog.ErrUnavailable, err)
	}
	return tx, nil
}

// beginNetwork also sets the Network scope the schema's checks read.
func (store *ConnectionLogStore) beginNetwork(ctx context.Context, scope network.Scope,
) (accountSessionTransaction, error) {
	tx, err := store.begin(ctx)
	if err != nil {
		return tx, err
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return tx, connectionLogDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return tx, connectionlog.ErrForbidden
	}
	return tx, nil
}

type storageCredentialDocument struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Provider  string  `json:"provider"`
	AccountID *string `json:"account_id"`
	// Config is absent from the delete function's v1 document.
	Config          *destinationConfig `json:"config,omitempty"`
	AccessKeySuffix string             `json:"access_key_suffix"`
	Version         int64              `json:"version"`
	SealedVersion   int64              `json:"sealed_version"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
	Networks        []string           `json:"networks"`
	UsedBy          []string           `json:"used_by"`
}

func (document storageCredentialDocument) credential() (connectionlog.Credential, error) {
	id, err := publicid.Parse(document.ID)
	if err != nil || !connectionlog.ValidName(document.Name) || document.Version < 1 ||
		document.SealedVersion < 1 || document.SealedVersion > document.Version ||
		len(document.AccessKeySuffix) != 4 || document.Networks == nil || document.UsedBy == nil {
		return connectionlog.Credential{}, connectionlog.ErrInvalid
	}
	credential := connectionlog.Credential{
		ID: connectionlog.CredentialID(id), Name: document.Name, Provider: document.Provider,
		AccessKeySuffix: document.AccessKeySuffix, Version: document.Version, SealedVersion: document.SealedVersion,
		CreatedAt: document.CreatedAt.UTC(), UpdatedAt: document.UpdatedAt.UTC(),
	}
	if document.AccountID != nil {
		credential.AccountID = *document.AccountID
	}
	if (credential.Provider == flowlog.ProviderR2) != connectionlog.ValidAccountID(credential.AccountID) ||
		!connectionlog.Storage(credential.Provider) && !connectionlog.Push(credential.Provider) {
		return connectionlog.Credential{}, connectionlog.ErrInvalid
	}
	if document.Config != nil {
		credential.Destination = document.Config.destination()
		check := credential.Destination
		check.CASHA256 = ""
		if check.Check(credential.Provider) != nil ||
			credential.Destination.CASHA256 != "" && !validCAHash(credential.Destination.CASHA256) {
			return connectionlog.Credential{}, connectionlog.ErrInvalid
		}
	} else if connectionlog.Push(credential.Provider) {
		return connectionlog.Credential{}, connectionlog.ErrInvalid
	}
	for _, list := range []struct {
		from []string
		to   *[]network.ID
	}{{document.Networks, &credential.Networks}, {document.UsedBy, &credential.UsedBy}} {
		*list.to = make([]network.ID, 0, len(list.from))
		for _, text := range list.from {
			id, err := network.ParseID(text)
			if err != nil {
				return connectionlog.Credential{}, connectionlog.ErrInvalid
			}
			*list.to = append(*list.to, id)
		}
	}
	return credential, nil
}

// destinationConfig is storage_credential.config (schema 272): a push
// credential's non-secret fields. The CA PEM goes in, never comes back.
type destinationConfig struct {
	URL       string `json:"url,omitempty"`
	Flavor    string `json:"flavor,omitempty"`
	CAPEM     string `json:"ca_pem,omitempty"`
	CASHA256  string `json:"ca_sha256,omitempty"`
	Site      string `json:"site,omitempty"`
	Region    string `json:"region,omitempty"`
	StreamARN string `json:"stream_arn,omitempty"`
}

func newDestinationConfig(destination connectionlog.Destination) destinationConfig {
	return destinationConfig{
		URL: destination.URL, Flavor: destination.Flavor, CAPEM: string(destination.CAPEM),
		CASHA256: flowlog.CAHash(destination.CAPEM), Site: destination.Site, Region: destination.Region,
		StreamARN: destination.StreamARN,
	}
}

func (config destinationConfig) destination() connectionlog.Destination {
	return connectionlog.Destination{
		URL: config.URL, Flavor: config.Flavor, CASHA256: config.CASHA256, Site: config.Site, Region: config.Region,
		StreamARN: config.StreamARN,
	}
}

func validCAHash(hash string) bool {
	decoded, err := hex.DecodeString(hash)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == hash
}

// ListCredentials lists a Workspace's credentials (workspace.read).
func (store *ConnectionLogStore) ListCredentials(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID,
) (_ connectionlog.Credentials, resultErr error) {
	if !session.IsValid() || !workspaceID.IsValid() {
		return connectionlog.Credentials{}, connectionlog.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return connectionlog.Credentials{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, listStorageCredentialsSQL,
		append(sessionQueryArguments(session), workspaceID.String())...).Scan(&encoded); err != nil {
		return connectionlog.Credentials{}, connectionLogDatabaseError(err)
	}
	var envelope struct {
		Feature     bool                        `json:"feature"`
		Credentials []storageCredentialDocument `json:"credentials"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil || envelope.Credentials == nil {
		return connectionlog.Credentials{}, connectionlog.ErrInvalid
	}
	listing := connectionlog.Credentials{
		Feature:     envelope.Feature,
		Credentials: make([]connectionlog.Credential, 0, len(envelope.Credentials)),
	}
	for _, document := range envelope.Credentials {
		credential, err := document.credential()
		if err != nil {
			return connectionlog.Credentials{}, err
		}
		listing.Credentials = append(listing.Credentials, credential)
	}
	return listing, nil
}

// PutCredential creates, rotates or re-scopes a credential and records the
// Workspace event, in one transaction. A secret is sealed here, bound to
// the Workspace, credential, version and provider; it never reaches the
// database or the event in clear.
func (store *ConnectionLogStore) PutCredential(ctx context.Context, put connectionlog.CredentialPut,
) (_ connectionlog.Credential, resultErr error) {
	if !put.Session.IsValid() || !put.Workspace.IsValid() || !publicid.ID(put.ID).IsValid() ||
		!put.CorrelationID.IsValid() || put.Check() != nil {
		return connectionlog.Credential{}, connectionlog.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return connectionlog.Credential{}, connectionlog.ErrUnavailable
	}
	var account, suffix, keyID, config any
	var sealed any
	if put.AccountID != "" {
		account = put.AccountID
	}
	if put.Secret != nil || put.PushSecret != nil {
		if store.sealer == nil {
			return connectionlog.Credential{}, connectionlog.ErrNotConfigured
		}
		box, shown, err := store.seal(put)
		if err != nil {
			return connectionlog.Credential{}, connectionlog.ErrInvalid
		}
		sealed, suffix, keyID = box, shown, store.sealer.KeyID
		// The config is bound into the secret: it goes with it, or not at
		// all (NULL keeps the stored one).
		encoded, err := json.Marshal(newDestinationConfig(put.Destination))
		if err != nil {
			return connectionlog.Credential{}, connectionlog.ErrInvalid
		}
		config = string(encoded)
	}
	networks := make([]string, len(put.Networks))
	for index, id := range put.Networks {
		networks[index] = id.String()
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return connectionlog.Credential{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, putStorageCredentialSQL, append(sessionQueryArguments(put.Session),
		put.Workspace.String(), put.ID.String(), put.ExpectedVersion, put.Name, put.Provider, account, config,
		suffix, sealed, keyID, networks, changeID.String())...).Scan(&encoded); err != nil {
		return connectionlog.Credential{}, connectionLogDatabaseError(err)
	}
	var record struct {
		WorkspaceID string                     `json:"workspace_id"`
		Rotated     bool                       `json:"rotated"`
		Before      *storageCredentialDocument `json:"before"`
		Credential  storageCredentialDocument  `json:"credential"`
		Authority   *catalogAuthority          `json:"authority"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
		record.WorkspaceID != put.Workspace.String() || record.Authority == nil {
		return connectionlog.Credential{}, connectionlog.ErrInvalid
	}
	saved, err := record.Credential.credential()
	if err != nil || saved.ID != put.ID || saved.Version != put.ExpectedVersion+1 ||
		(record.Before == nil) != (put.ExpectedVersion == 0) ||
		(put.Secret != nil || put.PushSecret != nil) != (saved.SealedVersion == saved.Version) {
		return connectionlog.Credential{}, connectionlog.ErrInvalid
	}
	if put.PushSecret != nil && !sameDestination(saved.Destination, put.Destination) {
		// What is stored is what the secret was sealed to (review p1b L10).
		return connectionlog.Credential{}, connectionlog.ErrInvalid
	}
	action := "storage_credential.updated"
	switch {
	case put.ExpectedVersion == 0:
		action = "storage_credential.created"
	case record.Rotated:
		action = "storage_credential.rotated"
	}
	if err := appendStorageCredentialEvent(ctx, tx, put.Session, put.CorrelationID, put.Workspace, changeID,
		action, record.Before, &record.Credential, *record.Authority); err != nil {
		return connectionlog.Credential{}, errors.Join(connectionlog.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return connectionlog.Credential{}, errors.Join(connectionlog.ErrUnavailable, err)
	}
	return saved, nil
}

// seal seals a put's secret for the version the put makes: an S3/R2
// secret under the v1 binding, a push secret under the v2 binding with
// the destination it may be sent to. It returns what Core shows of it.
func (store *ConnectionLogStore) seal(put connectionlog.CredentialPut) ([]byte, string, error) {
	if put.Secret != nil {
		box, err := flowlog.SealCredential(store.sealer.Key, *put.Secret, flowlog.CredentialBinding{
			WorkspaceID: put.Workspace.String(), CredentialID: put.ID.String(), Version: put.ExpectedVersion + 1,
			Provider: put.Provider, AccountID: put.AccountID,
		})
		return box, put.Secret.Suffix(), err
	}
	destination := put.Destination
	box, err := flowlog.SealSecret(store.sealer.Key, *put.PushSecret, flowlog.DestinationBinding{
		WorkspaceID: put.Workspace.String(), CredentialID: put.ID.String(), Version: put.ExpectedVersion + 1,
		Provider: put.Provider, URL: destination.URL, Flavor: destination.Flavor, CAPEM: destination.CAPEM,
		Site: destination.Site, Region: destination.Region, StreamARN: destination.StreamARN,
	})
	return box, put.PushSecret.Suffix(), err
}

// DeleteCredential deletes a credential no Network sends with.
func (store *ConnectionLogStore) DeleteCredential(ctx context.Context, deletion connectionlog.CredentialDeletion,
) (resultErr error) {
	if !deletion.Session.IsValid() || !deletion.Workspace.IsValid() || !publicid.ID(deletion.ID).IsValid() ||
		!deletion.CorrelationID.IsValid() || deletion.ExpectedVersion < 1 {
		return connectionlog.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return connectionlog.ErrUnavailable
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return err
	}
	var encoded string
	if err := tx.QueryRow(ctx, deleteStorageCredentialSQL, append(sessionQueryArguments(deletion.Session),
		deletion.Workspace.String(), deletion.ID.String(), deletion.ExpectedVersion,
		changeID.String())...).Scan(&encoded); err != nil {
		return connectionLogDatabaseError(err)
	}
	var record struct {
		WorkspaceID string                     `json:"workspace_id"`
		Before      *storageCredentialDocument `json:"before"`
		Authority   *catalogAuthority          `json:"authority"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
		record.WorkspaceID != deletion.Workspace.String() || record.Before == nil || record.Authority == nil ||
		record.Before.ID != deletion.ID.String() {
		return connectionlog.ErrInvalid
	}
	if err := appendStorageCredentialEvent(ctx, tx, deletion.Session, deletion.CorrelationID, deletion.Workspace,
		changeID, "storage_credential.deleted", record.Before, nil, *record.Authority); err != nil {
		return errors.Join(connectionlog.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(connectionlog.ErrUnavailable, err)
	}
	return nil
}

// storageCredentialAudited is what the evidence records of a credential:
// never its secret, never more of the access key than its suffix.
type storageCredentialAudited struct {
	CredentialID string  `json:"credential_id"`
	Name         string  `json:"name"`
	Provider     string  `json:"provider"`
	AccountID    *string `json:"account_id"`
	// Config is the push destination, without its CA (schema 272).
	Config          *destinationConfig `json:"config,omitempty"`
	AccessKeySuffix string             `json:"access_key_suffix"`
	Version         int64              `json:"version"`
	Networks        []string           `json:"networks"`
}

func auditedCredential(document *storageCredentialDocument) *storageCredentialAudited {
	if document == nil {
		return nil
	}
	return &storageCredentialAudited{
		CredentialID: document.ID, Name: document.Name, Provider: document.Provider, AccountID: document.AccountID,
		Config: auditedConfig(document.Config), AccessKeySuffix: document.AccessKeySuffix, Version: document.Version, Networks: slices.Clone(document.Networks),
	}
}

// auditedConfig is a push destination as events record it: no CA, and
// nothing for S3 and R2.
func auditedConfig(config *destinationConfig) *destinationConfig {
	if config == nil || *config == (destinationConfig{}) {
		return nil
	}
	audited := *config
	audited.CAPEM = ""
	return &audited
}

func appendStorageCredentialEvent(ctx context.Context, tx accountSessionTransaction, session accountsession.Session,
	correlationID publicid.ID, workspaceID workspace.ID, changeID publicid.ID, action string,
	before, after *storageCredentialDocument, authority catalogAuthority,
) error {
	beforeAudited, afterAudited := auditedCredential(before), auditedCredential(after)
	subject := afterAudited
	if subject == nil {
		subject = beforeAudited
	}
	aggregate, err := publicid.Parse(subject.CredentialID)
	if err != nil {
		return err
	}
	afterHash, err := kubernetesSemanticHash(afterAudited)
	if err != nil {
		return err
	}
	event := catalogEvent{
		session: session, correlationID: correlationID, changeID: changeID,
		aggregateKind: "storage_credential", aggregateID: aggregate, version: subject.Version, action: action,
		permission: "storage_credential.manage", after: afterHash, outboxClass: action,
		outbox: struct {
			WorkspaceID  string `json:"workspace_id"`
			CredentialID string `json:"credential_id"`
			Version      int64  `json:"version"`
		}{workspaceID.String(), subject.CredentialID, subject.Version},
		payload: struct {
			WorkspaceID string                    `json:"workspace_id"`
			SessionID   string                    `json:"session_id"`
			Before      *storageCredentialAudited `json:"before"`
			After       *storageCredentialAudited `json:"after"`
			Authority   catalogAuthority          `json:"authority"`
		}{workspaceID.String(), session.ID().String(), beforeAudited, afterAudited, authority},
	}
	if beforeAudited != nil {
		hash, err := kubernetesSemanticHash(beforeAudited)
		if err != nil {
			return err
		}
		event.before = &hash
	}
	return appendWorkspaceCatalogEvent(ctx, tx, workspaceID, event)
}

type networkConnectionLogDocument struct {
	Enabled       bool    `json:"enabled"`
	CredentialID  *string `json:"credential_id"`
	Bucket        string  `json:"bucket"`
	Region        string  `json:"region"`
	Prefix        string  `json:"prefix"`
	Forwarded     bool    `json:"forwarded"`
	WindowSeconds int     `json:"window_seconds"`
	BucketOwner   *string `json:"expected_bucket_owner"`
	// Schema 272: the push destination's fields, absent for S3 and R2.
	Target       *string    `json:"target,omitempty"`
	TargetKind   *string    `json:"target_kind,omitempty"`
	Service      *string    `json:"service,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	RecordFormat *string    `json:"record_format,omitempty"`
	Version      int64      `json:"version"`
	UpdatedAt    *time.Time `json:"updated_at"`
}

func (document networkConnectionLogDocument) settings() (connectionlog.Settings, error) {
	settings := connectionlog.Settings{
		Enabled: document.Enabled, Bucket: document.Bucket, Region: document.Region, Prefix: document.Prefix,
		Forwarded: document.Forwarded, WindowSeconds: document.WindowSeconds, Version: document.Version,
	}
	if document.BucketOwner != nil {
		if !connectionlog.ValidBucketOwner(*document.BucketOwner) {
			return connectionlog.Settings{}, connectionlog.ErrInvalid
		}
		settings.ExpectedBucketOwner = *document.BucketOwner
	}
	if document.CredentialID != nil {
		id, err := publicid.Parse(*document.CredentialID)
		if err != nil {
			return connectionlog.Settings{}, connectionlog.ErrInvalid
		}
		credential := connectionlog.CredentialID(id)
		settings.Credential = &credential
	}
	for _, field := range []struct {
		from *string
		to   *string
	}{
		{document.Target, &settings.Target}, {document.TargetKind, &settings.TargetKind},
		{document.Service, &settings.Service}, {document.RecordFormat, &settings.RecordFormat},
	} {
		if field.from != nil {
			if *field.from == "" {
				return connectionlog.Settings{}, connectionlog.ErrInvalid
			}
			*field.to = *field.from
		}
	}
	settings.Tags = slices.Clone(document.Tags)
	if document.UpdatedAt != nil {
		settings.UpdatedAt = document.UpdatedAt.UTC()
	}
	if document.Version < 0 || (document.Version == 0) != (document.UpdatedAt == nil) ||
		(connectionlog.SettingsReplacement{Settings: settings}).Check() != nil {
		return connectionlog.Settings{}, connectionlog.ErrInvalid
	}
	return settings, nil
}

// ReadSettings reads a Network's connection log settings (network.read).
func (store *ConnectionLogStore) ReadSettings(ctx context.Context, session accountsession.Session,
	scope network.Scope,
) (_ connectionlog.NetworkSettings, resultErr error) {
	if !session.IsValid() {
		return connectionlog.NetworkSettings{}, connectionlog.ErrInvalid
	}
	tx, err := store.beginNetwork(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return connectionlog.NetworkSettings{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, readNetworkConnectionLogSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String())...).Scan(&encoded); err != nil {
		return connectionlog.NetworkSettings{}, connectionLogDatabaseError(err)
	}
	var envelope struct {
		Feature  bool                         `json:"feature"`
		Settings networkConnectionLogDocument `json:"settings"`
		Status   connectionLogStatusDocument  `json:"status"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil {
		return connectionlog.NetworkSettings{}, connectionlog.ErrInvalid
	}
	settings, err := envelope.Settings.settings()
	if err != nil {
		return connectionlog.NetworkSettings{}, err
	}
	status, err := envelope.Status.rows()
	if err != nil {
		return connectionlog.NetworkSettings{}, err
	}
	return connectionlog.NetworkSettings{Feature: envelope.Feature, Settings: settings, Status: status}, nil
}

// connectionLogStatusDocument is the status part of the settings read
// (schema 271).
type connectionLogStatusDocument struct {
	Report *struct {
		TestedETag    *string    `json:"tested_etag"`
		TestResult    string     `json:"test_result"`
		TestedAt      *time.Time `json:"tested_at"`
		DeliveredAt   *time.Time `json:"delivered_at"`
		DeliveryError string     `json:"delivery_error"`
		ReceivedAt    time.Time  `json:"received_at"`
	} `json:"report"`
	ReceiverAt    *time.Time `json:"receiver_at"`
	SealedVersion *int64     `json:"sealed_version"`
	SealingKeyID  *string    `json:"sealing_key_id"`
}

func (document connectionLogStatusDocument) rows() (connectionlog.StatusRows, error) {
	rows := connectionlog.StatusRows{ReceiverAt: document.ReceiverAt}
	if document.SealedVersion != nil {
		rows.SealedVersion = *document.SealedVersion
	}
	if document.SealingKeyID != nil {
		rows.SealingKeyID = *document.SealingKeyID
	}
	report := document.Report
	if report == nil {
		return rows, nil
	}
	row := &connectionlog.ReportRow{
		TestResult: report.TestResult, TestedAt: report.TestedAt, DeliveredAt: report.DeliveredAt,
		DeliveryError: report.DeliveryError, ReceivedAt: report.ReceivedAt,
	}
	if report.TestedETag != nil {
		tag, err := hex.DecodeString(*report.TestedETag)
		if err != nil {
			return connectionlog.StatusRows{}, connectionlog.ErrInvalid
		}
		row.TestedETag = tag
	}
	rows.Report = row
	return rows, nil
}

// ReplaceSettings replaces a Network's settings, advancing its revision so
// map sessions grant or withdraw tickets, and records the Network event.
func (store *ConnectionLogStore) ReplaceSettings(ctx context.Context, replacement connectionlog.SettingsReplacement,
) (_ connectionlog.SettingsResult, resultErr error) {
	if !replacement.Session.IsValid() || !replacement.CorrelationID.IsValid() || replacement.Check() != nil {
		return connectionlog.SettingsResult{}, connectionlog.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return connectionlog.SettingsResult{}, connectionlog.ErrUnavailable
	}
	settings := replacement.Settings
	var credential any
	if settings.Credential != nil {
		credential = settings.Credential.String()
	}
	scope := replacement.Scope
	tx, err := store.beginNetwork(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return connectionlog.SettingsResult{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, replaceNetworkConnectionLogSQL, append(sessionQueryArguments(replacement.Session),
		scope.WorkspaceID().String(), scope.NetworkID().String(), replacement.ExpectedVersion, settings.Enabled,
		credential, settings.Bucket, settings.Region, settings.Prefix, settings.Forwarded, settings.WindowSeconds,
		optionalText(settings.ExpectedBucketOwner), optionalText(settings.Target), optionalText(settings.TargetKind),
		optionalText(settings.Service), optionalTags(settings.Tags), optionalText(settings.RecordFormat),
		changeID.String())...).Scan(&encoded); err != nil {
		return connectionlog.SettingsResult{}, connectionLogDatabaseError(err)
	}
	var record struct {
		NetworkID       string                        `json:"network_id"`
		NetworkRevision *int64                        `json:"network_revision"`
		Changed         bool                          `json:"changed"`
		Feature         bool                          `json:"feature"`
		Before          *networkConnectionLogDocument `json:"before"`
		Settings        networkConnectionLogDocument  `json:"settings"`
		Authority       *catalogAuthority             `json:"authority"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
		record.NetworkID != scope.NetworkID().String() {
		return connectionlog.SettingsResult{}, connectionlog.ErrInvalid
	}
	saved, err := record.Settings.settings()
	if err != nil {
		return connectionlog.SettingsResult{}, err
	}
	result := connectionlog.SettingsResult{Settings: saved, Changed: record.Changed, Feature: record.Feature}
	if !record.Changed {
		return result, nil
	}
	if record.NetworkRevision == nil || *record.NetworkRevision < 1 || record.Authority == nil ||
		saved.Version != replacement.ExpectedVersion+1 || (record.Before == nil) != (saved.Version == 1) {
		return connectionlog.SettingsResult{}, connectionlog.ErrInvalid
	}
	if err := appendConnectionLogSettingsEvent(ctx, tx, replacement, changeID, *record.NetworkRevision,
		*record.Authority, record.Before, record.Settings); err != nil {
		return connectionlog.SettingsResult{}, errors.Join(connectionlog.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return connectionlog.SettingsResult{}, errors.Join(connectionlog.ErrUnavailable, err)
	}
	return result, nil
}

func appendConnectionLogSettingsEvent(ctx context.Context, tx accountSessionTransaction,
	replacement connectionlog.SettingsReplacement, changeID publicid.ID, networkRevision int64,
	authority catalogAuthority, before *networkConnectionLogDocument, after networkConnectionLogDocument,
) error {
	networkID := replacement.Scope.NetworkID().String()
	afterHash, err := kubernetesSemanticHash(after)
	if err != nil {
		return err
	}
	event := catalogEvent{
		session: replacement.Session, correlationID: replacement.CorrelationID, changeID: changeID,
		aggregateKind: "network_connection_log", aggregateID: publicid.ID(replacement.Scope.NetworkID()),
		version: after.Version, networkVersion: networkRevision, action: "connection_log.settings_replaced",
		permission: "connection_log.manage", after: afterHash, outboxClass: "network.revision.advanced",
		outbox: struct {
			NetworkID       string `json:"network_id"`
			Version         int64  `json:"version"`
			NetworkRevision int64  `json:"network_revision"`
		}{networkID, after.Version, networkRevision},
		payload: struct {
			NetworkID string                        `json:"network_id"`
			SessionID string                        `json:"session_id"`
			Before    *networkConnectionLogDocument `json:"before"`
			After     networkConnectionLogDocument  `json:"after"`
			Authority catalogAuthority              `json:"authority"`
		}{networkID, replacement.Session.ID().String(), before, after, authority},
	}
	if before != nil {
		hash, err := kubernetesSemanticHash(*before)
		if err != nil {
			return err
		}
		event.before = &hash
	}
	return appendNetworkMemberEvent(ctx, tx, event)
}

// optionalText is NULL for an empty string.
func optionalText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// optionalTags is NULL for no tags: Core stores no empty array.
func optionalTags(tags []string) any {
	if len(tags) == 0 {
		return nil
	}
	return tags
}

// sameDestination reports the stored destination is the one sent, its CA
// by hash.
func sameDestination(saved, sent connectionlog.Destination) bool {
	return saved.URL == sent.URL && saved.Flavor == sent.Flavor && saved.CASHA256 == flowlog.CAHash(sent.CAPEM) &&
		saved.Site == sent.Site && saved.Region == sent.Region && saved.StreamARN == sent.StreamARN
}
