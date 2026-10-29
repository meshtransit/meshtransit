package kubecluster_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/kubejoin"
)

func mustID(t *testing.T, suffix string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type fixedClock time.Time

func (clock fixedClock) Now() time.Time { return time.Time(clock) }

type sequentialSecrets struct{ issued byte }

func (secrets *sequentialSecrets) NewToken() (enrollment.CredentialToken, error) {
	secrets.issued++
	var secret [32]byte
	secret[0] = secrets.issued
	return enrollment.NewCredentialToken(secret)
}

func (*sequentialSecrets) NewCredentialID() (enrollment.CredentialID, error) {
	id, err := publicid.Parse("01890f00-0000-7000-8000-000000000401")
	return enrollment.CredentialID(id), err
}

// recordingStore records what reaches it and answers plausibly.
type recordingStore struct {
	issues       []kubecluster.KeyIssue
	decisions    []kubecluster.Decision
	creations    []kubecluster.Creation
	signingReads []kubecluster.ID
	replacements []kubecluster.TrustReplacement
	pages        []kubecluster.PageQuery
	operations   []kubecluster.OperationQuery
}

func (store *recordingStore) ListJoinKeys(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.JoinKeyPage, error) {
	store.pages = append(store.pages, query)
	return kubecluster.JoinKeyPage{}, nil
}

func (*recordingStore) ReadJoinKey(context.Context, accountsession.Session, network.Scope, kubecluster.ID,
	enrollment.CredentialID) (kubecluster.JoinKey, error) {
	return kubecluster.JoinKey{}, nil
}

func (store *recordingStore) ListReplicaRequests(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.RequestPage, error) {
	store.pages = append(store.pages, query)
	return kubecluster.RequestPage{}, nil
}

func (*recordingStore) ReadReplicaRequest(context.Context, accountsession.Session, network.Scope, kubecluster.ID,
	kubecluster.RequestID) (kubecluster.ReplicaRequestView, error) {
	return kubecluster.ReplicaRequestView{}, nil
}

func (store *recordingStore) ListReplicas(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.ReplicaPage, error) {
	store.pages = append(store.pages, query)
	return kubecluster.ReplicaPage{}, nil
}

func (*recordingStore) ReadReplica(context.Context, accountsession.Session, network.Scope, kubecluster.ID,
	node.ID) (kubecluster.Replica, error) {
	return kubecluster.Replica{}, nil
}

func (store *recordingStore) ListCertificateAuthorities(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.CAPage, error) {
	store.pages = append(store.pages, query)
	return kubecluster.CAPage{}, nil
}

func (*recordingStore) ReadCertificateAuthority(context.Context, accountsession.Session, network.Scope,
	kubecluster.ID, publicid.ID) (kubecluster.CertificateAuthority, error) {
	return kubecluster.CertificateAuthority{}, nil
}

func (store *recordingStore) ListOperations(_ context.Context,
	query kubecluster.OperationQuery) (kubecluster.OperationPage, error) {
	store.operations = append(store.operations, query)
	return kubecluster.OperationPage{}, nil
}

func (*recordingStore) ReadOperation(context.Context, accountsession.Session, network.Scope, kubecluster.ID,
	publicid.ID) (kubecluster.Operation, error) {
	return kubecluster.Operation{}, nil
}

func (*recordingStore) CountDenials(context.Context, accountsession.Session, network.Scope, kubecluster.ID,
	time.Time, time.Time) (kubecluster.DenialSums, error) {
	return kubecluster.DenialSums{}, nil
}

func (store *recordingStore) ReplaceSigningTrust(_ context.Context,
	replacement kubecluster.TrustReplacement) (kubecluster.TrustReplacementResult, error) {
	store.replacements = append(store.replacements, replacement)
	return kubecluster.TrustReplacementResult{}, nil
}

func (store *recordingStore) CreateCluster(_ context.Context, creation kubecluster.Creation) (kubecluster.Cluster, error) {
	store.creations = append(store.creations, creation)
	return kubecluster.Cluster{}, nil
}

func (*recordingStore) DeleteCluster(context.Context, kubecluster.Deletion) (kubecluster.Cluster, error) {
	return kubecluster.Cluster{}, nil
}

func (*recordingStore) ListClusters(context.Context, accountsession.Session, network.Scope) ([]kubecluster.Cluster, error) {
	return nil, nil
}

func (*recordingStore) ReadCluster(context.Context, accountsession.Session, network.Scope,
	kubecluster.ID) (kubecluster.Detail, error) {
	return kubecluster.Detail{}, nil
}

func (store *recordingStore) ReadClusterSigning(_ context.Context, _ accountsession.Session, _ network.Scope,
	id kubecluster.ID) (kubecluster.Signing, error) {
	store.signingReads = append(store.signingReads, id)
	return kubecluster.Signing{}, nil
}

func (store *recordingStore) IssueJoinKey(_ context.Context, issue kubecluster.KeyIssue) (kubecluster.JoinKey, error) {
	store.issues = append(store.issues, issue)
	created := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	return kubecluster.NewJoinKey(kubecluster.JoinKeyParams{
		ID: issue.KeyID, IssuedBy: issue.Session.PrincipalID(), CreatedAt: created,
		ExpiresAt: created.Add(issue.Lifetime), Uses: issue.Uses, State: kubecluster.KeyActive, Version: 1,
	})
}

func (*recordingStore) RevokeJoinKey(context.Context, kubecluster.KeyRevocation) (kubecluster.JoinKey, error) {
	return kubecluster.JoinKey{}, nil
}

func (store *recordingStore) DecideReplicaRequest(_ context.Context,
	decision kubecluster.Decision) (kubecluster.ReplicaRequestView, error) {
	store.decisions = append(store.decisions, decision)
	return kubecluster.ReplicaRequestView{}, nil
}

func activeSession(t *testing.T, now time.Time) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: identity.PrincipalID(mustID(t, "000000000011")),
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func serviceFixture(t *testing.T) (*kubecluster.Service, *recordingStore, accountsession.Session, network.Scope,
	time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	service, err := kubecluster.NewService(store, fixedClock(now), &sequentialSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, now)
	workspaceID, _ := session.LoginWorkspaceID()
	scope, err := network.NewScope(workspaceID, network.ID(mustID(t, "000000000203")))
	if err != nil {
		t.Fatal(err)
	}
	return service, store, session, scope, now
}

// A key defaults to an hour and is presented as mtk1; invalid requests
// never reach the store.
func TestServiceIssueJoinKey(t *testing.T) {
	t.Parallel()
	service, store, session, scope, _ := serviceFixture(t)
	cluster := kubecluster.ID(mustID(t, "000000000301"))
	issued, err := service.IssueJoinKey(context.Background(), kubecluster.KeyRequest{
		Session: session, Scope: scope, ClusterID: cluster, Uses: 2, CorrelationID: mustID(t, "000000000901"),
	})
	if err != nil {
		t.Fatalf("IssueJoinKey() error = %v", err)
	}
	if len(store.issues) != 1 || store.issues[0].Lifetime != time.Hour || store.issues[0].Uses != 2 ||
		!strings.HasPrefix(issued.Presentation.Reveal(), "mtk1.") ||
		issued.Presentation.Token() != store.issues[0].Token || issued.Key.ID() != store.issues[0].KeyID {
		t.Fatalf("issued %+v after %d store calls", issued.Key, len(store.issues))
	}
	for name, request := range map[string]kubecluster.KeyRequest{
		"over an hour":   {Session: session, Scope: scope, ClusterID: cluster, Lifetime: 2 * time.Hour, Uses: 1, CorrelationID: mustID(t, "000000000902")},
		"no use":         {Session: session, Scope: scope, ClusterID: cluster, CorrelationID: mustID(t, "000000000903")},
		"no cluster":     {Session: session, Scope: scope, Uses: 1, CorrelationID: mustID(t, "000000000904")},
		"no correlation": {Session: session, Scope: scope, ClusterID: cluster, Uses: 1},
		"no scope":       {Session: session, ClusterID: cluster, Uses: 1, CorrelationID: mustID(t, "000000000905")},
	} {
		if _, err := service.IssueJoinKey(context.Background(), request); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: IssueJoinKey() error = %v, want ErrInvalid", name, err)
		}
	}
	if len(store.issues) != 1 {
		t.Fatalf("invalid requests reached the store: %d calls", len(store.issues))
	}
}

// A malformed code is refused before the store and so is not counted; a
// well-formed one reaches the store parsed, as an approval.
func TestServiceApproveParsesTheCode(t *testing.T) {
	t.Parallel()
	service, store, session, scope, _ := serviceFixture(t)
	decision := kubecluster.Decision{
		Session: session, Scope: scope, ClusterID: kubecluster.ID(mustID(t, "000000000301")),
		RequestID: kubecluster.RequestID(mustID(t, "000000000701")), CorrelationID: mustID(t, "000000000901"),
	}
	for _, typed := range []string{"", "abc", "4KH7I-REC20", "4KH7I-REC2BB"} {
		if _, err := service.Approve(context.Background(), decision, typed); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("Approve(%q) error = %v, want ErrInvalid", typed, err)
		}
	}
	if len(store.decisions) != 0 {
		t.Fatalf("malformed codes reached the store: %d", len(store.decisions))
	}
	if _, err := service.Approve(context.Background(), decision, "4kh7i rec2b"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if _, err := service.Reject(context.Background(), decision); err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	if len(store.decisions) != 2 || store.decisions[0].Kind != kubecluster.DecisionApprove ||
		store.decisions[0].Code.String() != "4KH7I-REC2B" || store.decisions[1].Kind != kubecluster.DecisionReject ||
		store.decisions[1].Code.String() != "" {
		t.Fatalf("decisions = %+v", store.decisions)
	}
}

// An ended session never reaches the store; names and descriptions are
// checked first.
func TestServiceCreateAdmission(t *testing.T) {
	t.Parallel()
	service, store, session, scope, now := serviceFixture(t)
	creation := kubecluster.Creation{Session: session, Scope: scope, ID: kubecluster.ID(mustID(t, "000000000301")),
		Name: "prod", CorrelationID: mustID(t, "000000000901")}
	if _, err := service.Create(context.Background(), creation); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	for name, mutate := range map[string]func(*kubecluster.Creation){
		"upper-case name":    func(c *kubecluster.Creation) { c.Name = "Prod" },
		"padded description": func(c *kubecluster.Creation) { c.Description = " x" },
		"no ID":              func(c *kubecluster.Creation) { c.ID = kubecluster.ID{} },
	} {
		invalid := creation
		mutate(&invalid)
		if _, err := service.Create(context.Background(), invalid); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: Create() error = %v, want ErrInvalid", name, err)
		}
	}
	ended, err := kubecluster.NewService(store, fixedClock(now.Add(48*time.Hour)), &sequentialSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ended.Create(context.Background(), creation); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("an ended session created a cluster: %v", err)
	}
	if len(store.creations) != 1 {
		t.Fatalf("store calls = %d, want 1", len(store.creations))
	}
}

func TestWrongCodeErrorIsErrWrongCode(t *testing.T) {
	t.Parallel()
	var err error = &kubecluster.WrongCodeError{Remaining: 2}
	if !errors.Is(err, kubecluster.ErrWrongCode) {
		t.Fatal("WrongCodeError does not match ErrWrongCode")
	}
}

func TestCanonicalReported(t *testing.T) {
	t.Parallel()
	canonical, err := kubecluster.CanonicalReported([]byte(` {"pod": "meshgw-0", "namespace":"mt-kube"} `))
	if err != nil || string(canonical) != `{"namespace":"mt-kube","pod":"meshgw-0"}` {
		t.Fatalf("CanonicalReported() = %s, %v", canonical, err)
	}
	many := "{"
	for index := range kubecluster.MaximumReportedFields + 1 {
		if index > 0 {
			many += ","
		}
		many += `"k` + strings.Repeat("x", index) + `":"v"`
	}
	many += "}"
	for name, raw := range map[string]string{
		"not an object":    `["a"]`,
		"null":             `null`,
		"nested":           `{"a":{"b":"c"}}`,
		"a number":         `{"a":1}`,
		"an empty key":     `{"":"x"}`,
		"a long key":       `{"` + strings.Repeat("k", kubecluster.MaximumReportedKey+1) + `":"x"}`,
		"a long value":     `{"k":"` + strings.Repeat("v", kubecluster.MaximumReportedValue+1) + `"}`,
		"too many fields":  many,
		"trailing garbage": `{"a":"b"} x`,
	} {
		if _, err := kubecluster.CanonicalReported([]byte(raw)); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: CanonicalReported() error = %v, want ErrInvalid", name, err)
		}
	}
}

func TestSystemSecretsProposeRequests(t *testing.T) {
	t.Parallel()
	secrets := kubecluster.SystemSecrets{}
	first, err := secrets.NewRequestID()
	if err != nil || !first.IsValid() {
		t.Fatalf("NewRequestID() = %v, %v", first, err)
	}
	second, err := secrets.NewRequestID()
	if err != nil || second == first {
		t.Fatalf("NewRequestID() repeated %v, %v", second, err)
	}
	nonce, err := secrets.NewRequestNonce()
	if err != nil || nonce == ([32]byte{}) {
		t.Fatalf("NewRequestNonce() = %x, %v", nonce, err)
	}
	other, err := secrets.NewRequestNonce()
	if err != nil || other == nonce {
		t.Fatalf("NewRequestNonce() repeated %x, %v", other, err)
	}
}

// The replica parses the cluster ID Core sends into the bytes Core binds in
// the code.
func TestClusterIDCrossesToKubejoin(t *testing.T) {
	t.Parallel()
	for range 32 {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := kubejoin.ParseClusterID(id.String())
		if err != nil || parsed != [16]byte(id) {
			t.Fatalf("ParseClusterID(%s) = %x, %v", id, parsed, err)
		}
	}
}

// A signing read needs a live session and a cluster ID before the store.
func TestServiceReadSigning(t *testing.T) {
	t.Parallel()
	service, store, session, scope, now := serviceFixture(t)
	id := kubecluster.ID(mustID(t, "000000000301"))
	if _, err := service.ReadSigning(context.Background(), session, scope, id); err != nil {
		t.Fatalf("ReadSigning() error = %v", err)
	}
	if _, err := service.ReadSigning(context.Background(), session, scope, kubecluster.ID{}); !errors.Is(err,
		kubecluster.ErrInvalid) {
		t.Fatalf("ReadSigning(no ID) error = %v, want ErrInvalid", err)
	}
	ended, err := kubecluster.NewService(store, fixedClock(now.Add(48*time.Hour)), &sequentialSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ended.ReadSigning(context.Background(), session, scope, id); !errors.Is(err,
		kubecluster.ErrForbidden) {
		t.Fatalf("an ended session read signing: %v", err)
	}
	if len(store.signingReads) != 1 || store.signingReads[0] != id {
		t.Fatalf("store reads = %v", store.signingReads)
	}
}

// A page asks for 1 to 100 rows after a whole cursor or none; anything
// else never reaches the store (K1d d1a).
func TestServicePages(t *testing.T) {
	t.Parallel()
	service, store, session, scope, now := serviceFixture(t)
	cluster := kubecluster.ID(mustID(t, "000000000301"))
	after := kubecluster.PageCursor{At: now, ID: mustID(t, "000000000b02")}
	for name, query := range map[string]kubecluster.PageQuery{
		"no rows":         {Limit: 0},
		"too many rows":   {Limit: kubecluster.MaximumPageSize + 1},
		"no cluster":      {Limit: 1, ClusterID: kubecluster.ID{}},
		"a time, no ID":   {Limit: 1, After: kubecluster.PageCursor{At: now}},
		"an ID, no time":  {Limit: 1, After: kubecluster.PageCursor{ID: after.ID}},
		"another network": {Limit: 1, Scope: network.Scope{}},
	} {
		query.Session = session
		if query.ClusterID == (kubecluster.ID{}) && name != "no cluster" {
			query.ClusterID = cluster
		}
		if name != "another network" {
			query.Scope = scope
		}
		if _, err := service.ListJoinKeys(context.Background(), query); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: ListJoinKeys() error = %v", name, err)
		}
		if _, err := service.ListReplicaRequests(context.Background(), query); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: ListReplicaRequests() error = %v", name, err)
		}
	}
	if len(store.pages) != 0 {
		t.Fatalf("invalid pages reached the store: %+v", store.pages)
	}
	for _, query := range []kubecluster.PageQuery{
		{Session: session, Scope: scope, ClusterID: cluster, Limit: 1},
		{Session: session, Scope: scope, ClusterID: cluster, Limit: kubecluster.MaximumPageSize, After: after},
	} {
		if _, err := service.ListJoinKeys(context.Background(), query); err != nil {
			t.Fatalf("ListJoinKeys(%+v) error = %v", query, err)
		}
	}
	if _, err := service.ReadJoinKey(context.Background(), session, scope, cluster,
		enrollment.CredentialID{}); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("ReadJoinKey() without a key: %v", err)
	}
	if _, err := service.ReadReplicaRequest(context.Background(), session, scope, kubecluster.ID{},
		kubecluster.RequestID(mustID(t, "000000000b03"))); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("ReadReplicaRequest() without a cluster: %v", err)
	}
}

// An operations page asks for a range of at most 31 days, 1 day with a
// filter, a known class; anything else never reaches the store (K1d d1c).
func TestServiceOperations(t *testing.T) {
	t.Parallel()
	service, store, session, scope, now := serviceFixture(t)
	cluster := kubecluster.ID(mustID(t, "000000000301"))
	base := kubecluster.OperationQuery{Session: session, Scope: scope, ClusterID: cluster,
		From: now.Add(-kubecluster.MaximumOperationRange), To: now, Limit: 10}
	for name, change := range map[string]func(*kubecluster.OperationQuery){
		"empty range":         func(query *kubecluster.OperationQuery) { query.From = query.To },
		"over 31 days":        func(query *kubecluster.OperationQuery) { query.From = query.From.Add(-time.Second) },
		"a filter over a day": func(query *kubecluster.OperationQuery) { query.Class = "write" },
		"an unknown class":    func(query *kubecluster.OperationQuery) { query.From, query.Class = now.Add(-time.Hour), "read" },
		"a long person": func(query *kubecluster.OperationQuery) {
			query.From, query.OwnerRef = now.Add(-time.Hour), strings.Repeat("a", 1025)
		},
		"no rows":       func(query *kubecluster.OperationQuery) { query.Limit = 0 },
		"a half cursor": func(query *kubecluster.OperationQuery) { query.After = kubecluster.PageCursor{At: now} },
	} {
		query := base
		change(&query)
		if _, err := service.ListOperations(context.Background(), query); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: ListOperations() error = %v", name, err)
		}
	}
	if len(store.operations) != 0 {
		t.Fatalf("invalid queries reached the store: %+v", store.operations)
	}
	filtered := base
	filtered.From, filtered.Class = now.Add(-kubecluster.MaximumFilteredOperationRange), "exec"
	for _, query := range []kubecluster.OperationQuery{base, filtered} {
		if _, err := service.ListOperations(context.Background(), query); err != nil {
			t.Fatalf("ListOperations(%+v) error = %v", query, err)
		}
	}
	if _, err := service.CountDenials(context.Background(), session, scope, cluster, now.Add(-32*24*time.Hour),
		now); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("CountDenials() over 31 days: %v", err)
	}
}
