//go:build integration

package integration

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/shared/flowlog"
)

// pushTestCA is a self-signed certificate in PEM, made once.
var pushTestCA = func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "integration CA"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Unix(1_800_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}()

// assertConnectionLogPushDestinations qualifies schema 272 (push
// destinations design §5 S1, §6): push credentials store their destination
// beside a secret bound to it, never show the CA, change the destination
// only with a new secret, and a Network's settings take exactly the fields
// of its credential's type. The Network's settings are at version and off.
func assertConnectionLogPushDestinations(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.ConnectionLogStore, receiver *ecdh.PrivateKey, owner accountsession.Session,
	scope network.Scope, version int64,
) {
	t.Helper()
	workspaceID := scope.WorkspaceID()
	networks := []network.ID{scope.NetworkID()}
	type pushCase struct {
		provider    string
		secret      flowlog.Secret
		destination connectionlog.Destination
		settings    connectionlog.Settings
		suffix      string
	}
	cases := []pushCase{
		{flowlog.ProviderElasticsearch,
			flowlog.Secret{Kind: flowlog.SecretBasic, ID: "meshtransit-writer", Key: "integration-push"},
			connectionlog.Destination{URL: "https://es.example.com:9243/es", Flavor: flowlog.FlavorOpenSearch,
				CAPEM: []byte(pushTestCA)},
			connectionlog.Settings{Target: "meshtransit-connections", TargetKind: connectionlog.TargetKindIndex},
			"iter"},
		{flowlog.ProviderDatadog,
			flowlog.Secret{Kind: flowlog.SecretDatadogKey, Key: strings.Repeat("c0", 16)},
			connectionlog.Destination{Site: "datadoghq.eu"},
			connectionlog.Settings{Service: connectionlog.DefaultDatadogService, Tags: []string{"env:poc"}},
			"c0c0"},
		{flowlog.ProviderKinesis,
			flowlog.Secret{Kind: flowlog.SecretAWSKeys, ID: "TESTINTEGRATIONKEY02", Key: "integration/kinesis"},
			connectionlog.Destination{Region: "eu-west-1",
				StreamARN: "arn:aws:kinesis:eu-west-1:123456789012:stream/flow-logs"},
			connectionlog.Settings{RecordFormat: connectionlog.RecordFormatNDJSONBatch},
			"EY02"},
	}
	for _, test := range cases {
		id := connectionlog.CredentialID(newConnectionLogID(t))
		secret := test.secret
		created, err := store.PutCredential(ctx, connectionlog.CredentialPut{
			Session: owner, Workspace: workspaceID, ID: id, Name: "Push " + test.provider, Provider: test.provider,
			PushSecret: &secret, Destination: test.destination, Networks: networks, CorrelationID: newCorrelationID(t),
		})
		want := test.destination
		want.CAPEM, want.CASHA256 = nil, flowlog.CAHash(test.destination.CAPEM)
		if err != nil || created.Destination.URL != want.URL || created.Destination.CASHA256 != want.CASHA256 ||
			created.Destination.Site != want.Site || created.Destination.StreamARN != want.StreamARN ||
			len(created.Destination.CAPEM) != 0 || created.AccessKeySuffix != test.suffix {
			t.Fatalf("%s: created %+v, %v", test.provider, created, err)
		}
		// What the receiver will do: rebuild the binding from the stored
		// config and open the secret.
		opened := openStoredPushSecret(ctx, t, admin, receiver, workspaceID.String(), id, test.provider, 1)
		if opened.Kind != secret.Kind || opened.ID != secret.ID || opened.Key != secret.Key {
			t.Fatalf("%s: the stored secret did not open to the secret", test.provider)
		}
		// A rename keeps the destination and the sealed version.
		renamed, err := store.PutCredential(ctx, connectionlog.CredentialPut{
			Session: owner, Workspace: workspaceID, ID: id, ExpectedVersion: 1, Name: "Renamed " + test.provider,
			Provider: test.provider, Networks: networks, CorrelationID: newCorrelationID(t),
		})
		if err != nil || renamed.SealedVersion != 1 || renamed.Destination.CASHA256 != want.CASHA256 ||
			renamed.Destination.URL != want.URL || renamed.Destination.StreamARN != want.StreamARN {
			t.Fatalf("%s: renamed %+v, %v", test.provider, renamed, err)
		}
		// Each test credential is used once in the settings below.
		settings := test.settings
		settings.Enabled, settings.Credential, settings.WindowSeconds = true, &id, 60
		on, err := store.ReplaceSettings(ctx, connectionlog.SettingsReplacement{
			Session: owner, Scope: scope, ExpectedVersion: version, Settings: settings, CorrelationID: newCorrelationID(t),
		})
		if err != nil || !on.Changed || on.Settings.Target != settings.Target || on.Settings.Service != settings.Service ||
			on.Settings.RecordFormat != settings.RecordFormat || len(on.Settings.Tags) != len(settings.Tags) {
			t.Fatalf("%s: settings %+v, %v", test.provider, on, err)
		}
		version = on.Settings.Version
		// A schema 271 pod's v1 write cannot leave push fields beside a
		// bucket: the table refuses it (review p1b H2).
		if _, err := admin.Exec(ctx, `UPDATE mesh.network_connection_log SET bucket = 'meshtransit-logs',
region = 'eu-central-1' WHERE public_id = $1::UUID`, scope.NetworkID().String()); err == nil {
			t.Fatalf("%s: push fields beside a bucket", test.provider)
		}
		read, err := store.ReadSettings(ctx, owner, scope)
		if err != nil || read.Settings.Target != settings.Target || read.Settings.RecordFormat != settings.RecordFormat {
			t.Fatalf("%s: read %+v, %v", test.provider, read, err)
		}
		// Fields of another type, or an S3 bucket, do not fit.
		for name, edit := range map[string]func(*connectionlog.Settings){
			"a bucket": func(s *connectionlog.Settings) { s.Bucket, s.Region = "meshtransit-logs", "eu-central-1" },
			"a prefix": func(s *connectionlog.Settings) { s.Prefix = "mesh" },
			"another type's field": func(s *connectionlog.Settings) {
				if s.RecordFormat == "" {
					s.RecordFormat = connectionlog.RecordFormatJSONLine
				} else {
					s.Service = "svc"
				}
			},
			"no field of its type": func(s *connectionlog.Settings) {
				s.Target, s.TargetKind, s.Service, s.Tags, s.RecordFormat = "", "", "", nil, ""
			},
		} {
			wrong := settings
			edit(&wrong)
			if _, err := store.ReplaceSettings(ctx, connectionlog.SettingsReplacement{
				Session: owner, Scope: scope, ExpectedVersion: version, Settings: wrong, CorrelationID: newCorrelationID(t),
			}); !errors.Is(err, connectionlog.ErrInvalid) {
				t.Errorf("%s: %s: %v", test.provider, name, err)
			}
		}
		off, err := store.ReplaceSettings(ctx, connectionlog.SettingsReplacement{
			Session: owner, Scope: scope, ExpectedVersion: version,
			Settings: connectionlog.Settings{WindowSeconds: 60}, CorrelationID: newCorrelationID(t),
		})
		if err != nil {
			t.Fatalf("%s: off: %v", test.provider, err)
		}
		version = off.Settings.Version
		if err := store.DeleteCredential(ctx, connectionlog.CredentialDeletion{
			Session: owner, Workspace: workspaceID, ID: id, ExpectedVersion: 2, CorrelationID: newCorrelationID(t),
		}); err != nil {
			t.Fatalf("%s: delete: %v", test.provider, err)
		}
		// The key is nowhere in clear (its ID may be shown in part).
		assertNoConnectionLogSecret(ctx, t, admin,
			flowlog.Credential{AccessKeyID: secret.Key, SecretAccessKey: secret.Key})
	}
	assertPushConfigNeedsSecret(ctx, t, admin, store, owner, scope)
}

// assertPushConfigNeedsSecret writes the v2 function directly: a config
// changed without a sealed secret is refused by the schema itself.
func assertPushConfigNeedsSecret(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.ConnectionLogStore, owner accountsession.Session, scope network.Scope,
) {
	t.Helper()
	id := connectionlog.CredentialID(newConnectionLogID(t))
	secret := flowlog.Secret{Kind: flowlog.SecretDatadogKey, Key: strings.Repeat("d1", 16)}
	if _, err := store.PutCredential(ctx, connectionlog.CredentialPut{
		Session: owner, Workspace: scope.WorkspaceID(), ID: id, Name: "Datadog guard", Provider: flowlog.ProviderDatadog,
		PushSecret: &secret, Destination: connectionlog.Destination{Site: "datadoghq.com"},
		Networks: []network.ID{}, CorrelationID: newCorrelationID(t),
	}); err != nil {
		t.Fatal(err)
	}
	// The table's own check refuses a config of another provider's shape,
	// or one missing its keys (review p1b H1).
	for _, config := range []string{`{"url":"https://evil.example.com:443"}`, `{}`, `{"site":null}`} {
		if _, err := admin.Exec(ctx, `UPDATE mesh.storage_credential SET config = $2::JSONB WHERE public_id = $1::UUID`,
			id.String(), config); err == nil {
			t.Fatalf("a Datadog credential took config %s", config)
		}
	}
	var function string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.pg_get_functiondef(
'mesh_ops.put_storage_credential_v2(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid,uuid,bigint,text,text,text,jsonb,text,bytea,text,uuid[],uuid)'::regprocedure)`).
		Scan(&function); err != nil || !strings.Contains(function, "changes its endpoint only with its secret") {
		t.Fatalf("put_storage_credential_v2 guard: %v", err)
	}
	if err := store.DeleteCredential(ctx, connectionlog.CredentialDeletion{
		Session: owner, Workspace: scope.WorkspaceID(), ID: id, ExpectedVersion: 1, CorrelationID: newCorrelationID(t),
	}); err != nil {
		t.Fatal(err)
	}
}

// openStoredPushSecret opens a stored push secret as the receiver will:
// the binding comes from the stored config, the CA from its PEM.
func openStoredPushSecret(ctx context.Context, t *testing.T, admin *pgx.Conn, receiver *ecdh.PrivateKey,
	workspace string, credential connectionlog.CredentialID, provider string, version int64,
) flowlog.Secret {
	t.Helper()
	var sealed, encoded []byte
	if err := admin.QueryRow(ctx, `SELECT sealed, config::TEXT FROM mesh.storage_credential
WHERE public_id = $1::UUID AND sealed_version = $2`, credential.String(), version).Scan(&sealed, &encoded); err != nil {
		t.Fatalf("stored push credential: %v", err)
	}
	var config struct {
		URL       string `json:"url"`
		Flavor    string `json:"flavor"`
		CAPEM     string `json:"ca_pem"`
		Site      string `json:"site"`
		Region    string `json:"region"`
		StreamARN string `json:"stream_arn"`
	}
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	binding := flowlog.DestinationBinding{
		WorkspaceID: workspace, CredentialID: credential.String(), Version: version, Provider: provider,
		URL: config.URL, Flavor: config.Flavor, Site: config.Site, Region: config.Region, StreamARN: config.StreamARN,
	}
	if config.CAPEM != "" {
		binding.CAPEM = []byte(config.CAPEM)
	}
	opened, err := flowlog.OpenSecret(receiver, sealed, binding)
	if err != nil {
		t.Fatalf("OpenSecret(): %v", err)
	}
	// Another URL does not open it.
	if binding.URL != "" {
		moved := binding
		moved.URL = "https://attacker.example.com:443"
		if _, err := flowlog.OpenSecret(receiver, sealed, moved); err == nil {
			t.Fatal("the secret opened for another URL")
		}
	}
	return opened
}
