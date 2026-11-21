package main

import (
	"context"
	"errors"
	"testing"

	"meshtransit.net/core/internal/adapter/kubeapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/installsecrets"
)

const (
	dbProvider  = "01995d00-0000-7000-8000-000000000011"
	dbClient    = "01995d00-0000-7000-8000-000000000012"
	newLoginID  = "01995d00-0000-7000-8000-0000000000aa"
	newLoginID2 = "01995d00-0000-7000-8000-0000000000ab"
	otherClient = "01995d00-0000-7000-8000-000000000099"
)

func loginPlan() installsecrets.Plan {
	return installsecrets.Plan{Fullname: "mt", Login: &installsecrets.LoginPlan{
		Issuer: "https://id.example.test/oauth2", OIDCClientID: "meshcore-bff"}}
}

func ownConfigMap(name string, data map[string]string) kubeapi.ConfigMap {
	return kubeapi.ConfigMap{Metadata: kubeapi.Metadata{Name: name,
		Labels: map[string]string{installManagedByLabel: installManagedBy}}, Data: data}
}

func TestEnsureLoginIdentity(t *testing.T) {
	t.Parallel()
	database := postgresadapter.LoginIdentityRecord{ProviderID: dbProvider, ClientID: dbClient,
		ProviderGeneration: 2, RecoveryEpoch: 3}
	generated := []string{newLoginID, newLoginID2}
	newID := func() (string, error) {
		id := generated[0]
		generated = append(generated[1:], generated[0])
		return id, nil
	}
	for _, test := range []struct {
		name       string
		inDatabase bool
		recorded   map[string]string
		wantIDs    map[string]string
		wantState  map[string]string
		err        error
	}{
		{name: "from the database", inDatabase: true,
			wantIDs:   map[string]string{loginProviderIDKey: dbProvider, loginClientIDKey: dbClient},
			wantState: map[string]string{loginGenerationKey: "2", loginEpochKey: "3"}},
		{name: "recorded equal to the database", inDatabase: true,
			recorded:  map[string]string{loginProviderIDKey: dbProvider, loginClientIDKey: dbClient},
			wantIDs:   map[string]string{loginProviderIDKey: dbProvider, loginClientIDKey: dbClient},
			wantState: map[string]string{loginGenerationKey: "2", loginEpochKey: "3"}},
		{name: "recorded differs from the database", inDatabase: true,
			recorded: map[string]string{loginProviderIDKey: dbProvider, loginClientIDKey: otherClient}, err: errInstallLoginIDs},
		{name: "new installation",
			wantIDs:   map[string]string{loginProviderIDKey: newLoginID, loginClientIDKey: newLoginID2},
			wantState: map[string]string{loginGenerationKey: "1", loginEpochKey: "1"}},
		{name: "recorded before the deployment exists",
			recorded:  map[string]string{loginProviderIDKey: dbProvider, loginClientIDKey: dbClient},
			wantIDs:   map[string]string{loginProviderIDKey: dbProvider, loginClientIDKey: dbClient},
			wantState: map[string]string{loginGenerationKey: "1", loginEpochKey: "1"}},
		{name: "recorded but invalid", recorded: map[string]string{loginProviderIDKey: "x", loginClientIDKey: dbClient},
			err: errInstallNotOurs},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeSecretStore()
			if test.recorded != nil {
				store.configMaps["mt-login-ids"] = ownConfigMap("mt-login-ids", test.recorded)
			}
			_, err := ensureLoginIdentity(context.Background(), store, loginIdentityInput{
				plan: loginPlan(), database: database, inDatabase: test.inDatabase, newID: newID})
			if !errors.Is(err, test.err) {
				t.Fatalf("err = %v", err)
			}
			if test.err != nil {
				return
			}
			ids := store.configMaps["mt-login-ids"]
			if ids.Data[loginProviderIDKey] != test.wantIDs[loginProviderIDKey] ||
				ids.Data[loginClientIDKey] != test.wantIDs[loginClientIDKey] {
				t.Fatalf("ids = %v", ids.Data)
			}
			if test.recorded == nil && (ids.Immutable == nil || !*ids.Immutable) {
				t.Fatal("the IDs are not immutable")
			}
			if state := store.configMaps["mt-login-state"].Data; state[loginGenerationKey] != test.wantState[loginGenerationKey] ||
				state[loginEpochKey] != test.wantState[loginEpochKey] {
				t.Fatalf("state = %v", state)
			}
		})
	}
}

// The state follows the database; no login plan writes nothing.
func TestEnsureLoginIdentityStateFollowsTheDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeSecretStore()
	record := postgresadapter.LoginIdentityRecord{ProviderID: dbProvider, ClientID: dbClient, ProviderGeneration: 1, RecoveryEpoch: 1}
	newID := func() (string, error) { return newLoginID, nil }
	input := loginIdentityInput{plan: loginPlan(), database: record, inDatabase: true, newID: newID}
	if _, err := ensureLoginIdentity(ctx, store, input); err != nil {
		t.Fatal(err)
	}
	input.database.ProviderGeneration = 2
	report, err := ensureLoginIdentity(ctx, store, input)
	if err != nil || report.State != "updated" || report.IDsRecorded ||
		store.configMaps["mt-login-state"].Data[loginGenerationKey] != "2" {
		t.Fatalf("report = %+v, %v, state %v", report, err, store.configMaps["mt-login-state"].Data)
	}
	empty := newFakeSecretStore()
	if report, err := ensureLoginIdentity(ctx, empty, loginIdentityInput{plan: installsecrets.Plan{Fullname: "mt"},
		database: record, inDatabase: true, newID: newID}); err != nil ||
		report != (installLoginReport{}) || len(empty.configMaps) != 0 {
		t.Fatalf("no login plan: %+v %v", report, err)
	}
}
