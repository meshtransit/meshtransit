package invitation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

var testNow = time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)

func testSession(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: testNow.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: testNow.Add(time.Hour), AbsoluteExpiresAt: testNow.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

type clock struct{}

func (clock) Now() time.Time { return testNow }

type fakeStore struct {
	changes []Change
	fail    map[Action]error
}

func (store *fakeStore) Change(_ context.Context, change Change) (ChangeResult, error) {
	store.changes = append(store.changes, change)
	if err := store.fail[change.Action]; err != nil {
		return ChangeResult{}, err
	}
	delivery := map[Action]string{
		ActionDelivered: "sent", ActionDeliveryFailed: "failed", ActionNotConfigured: "not_configured",
	}[change.Action]
	if delivery == "" {
		delivery = "pending"
	}
	email := change.Email
	if email == "" {
		email = "member@example.com"
	}
	return ChangeResult{
		Invitation: Invitation{
			ID: change.InvitationID, Email: email, Role: change.Role, State: "pending",
			ExpiresAt: testNow.Add(Lifetime), DeliveryState: delivery, Version: int64(len(store.changes)),
			InvitedBy: Person{DisplayName: "Lan <script>"},
		},
		WorkspaceName: "Test & Co",
	}, nil
}

func (store *fakeStore) PreviewInvitation(context.Context, [32]byte, time.Time) (Preview, error) {
	return Preview{WorkspaceName: "Test", Email: "member@example.com", ExpiresAt: testNow.Add(Lifetime)}, nil
}

func (store *fakeStore) List(context.Context, accountsession.Session, workspace.ID, time.Time) ([]Invitation, error) {
	return []Invitation{}, nil
}

type fakeMailer struct {
	mails []Mail
	err   error
}

func (mailer *fakeMailer) Send(_ context.Context, mail Mail) error {
	mailer.mails = append(mailer.mails, mail)
	return mailer.err
}

func newService(t *testing.T, store Store, mailer Mailer) *Service {
	t.Helper()
	options := Options{
		Store: store, Clock: clock{}, ConsoleOrigin: "https://console.example.com", SendTimeout: time.Second,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mailer != nil {
		options.Mailer = mailer
	}
	service, err := NewService(options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func createRequest() CreateRequest {
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	correlation, _ := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	return CreateRequest{WorkspaceID: workspaceID, Email: " Member@Example.com ", Role: "auditor",
		CorrelationID: correlation}
}

func TestTokensAreRandomCanonicalAndDomainSeparated(t *testing.T) {
	t.Parallel()
	first, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NewToken()
	if first == second || len(first.String()) != 43 {
		t.Fatalf("tokens = %q, %q", first, second)
	}
	parsed, ok := ParseToken(first.String())
	if !ok || parsed.Digest() != first.Digest() {
		t.Fatal("a token must round-trip to the same digest")
	}
	for _, bad := range []string{"", "short", first.String() + "A", strings.ToUpper(first.String()) + "="} {
		if _, ok := ParseToken(bad); ok {
			t.Errorf("ParseToken(%q) accepted", bad)
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		" Member@Example.com ": "member@example.com", "a.b+c@sub.example.org": "a.b+c@sub.example.org",
		"Member <m@example.com>": "", "nodomain@local": "", "two@@example.com": "", "a b@example.com": "",
		"": "",
	} {
		got, ok := NormalizeEmail(input)
		if got != want || ok != (want != "") {
			t.Errorf("NormalizeEmail(%q) = %q, %t; want %q", input, got, ok, want)
		}
	}
}

func TestCreateEmailsTheLinkAndRecordsDelivery(t *testing.T) {
	t.Parallel()
	store, mailer := &fakeStore{}, &fakeMailer{}
	sent, err := newService(t, store, mailer).Create(context.Background(), testSession(t), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(store.changes) != 2 || store.changes[0].Action != ActionCreate || store.changes[1].Action != ActionDelivered ||
		store.changes[0].Email != "member@example.com" || store.changes[1].ExpectedVersion != 1 {
		t.Fatalf("store changes = %+v", store.changes)
	}
	if sent.Invitation.DeliveryState != "sent" || !strings.HasPrefix(sent.Link, "https://console.example.com/join#invite=") {
		t.Fatalf("sent = %+v", sent)
	}
	token, ok := ParseToken(strings.TrimPrefix(sent.Link, "https://console.example.com/join#invite="))
	if !ok || token.Digest() != *store.changes[0].TokenDigest {
		t.Fatal("the stored digest must be the emailed token's")
	}
	if len(mailer.mails) != 1 || mailer.mails[0].To != "member@example.com" ||
		!strings.Contains(mailer.mails[0].Text, sent.Link) || !strings.Contains(mailer.mails[0].Text, "as Auditor") ||
		strings.Contains(mailer.mails[0].HTML, "<script>") || !strings.Contains(mailer.mails[0].HTML, "Test &amp; Co") ||
		!strings.Contains(mailer.mails[0].HTML, `<a ses:no-track href="`+sent.Link+`"`) {
		t.Fatalf("mail = %+v", mailer.mails)
	}
}

func TestDeliveryFailureAndMissingMailerKeepTheInvitation(t *testing.T) {
	t.Parallel()
	failing := &fakeStore{}
	sent, err := newService(t, failing, &fakeMailer{err: errors.New("down")}).
		Create(context.Background(), testSession(t), createRequest())
	if err != nil || sent.Invitation.DeliveryState != "failed" || failing.changes[1].Action != ActionDeliveryFailed {
		t.Fatalf("failed delivery = %+v, %v", sent, err)
	}
	quiet := &fakeStore{}
	sent, err = newService(t, quiet, nil).Create(context.Background(), testSession(t), createRequest())
	if err != nil || sent.Invitation.DeliveryState != "not_configured" || sent.Link == "" {
		t.Fatalf("no mailer = %+v, %v", sent, err)
	}
	late := &fakeStore{fail: map[Action]error{ActionDelivered: ErrUnavailable}}
	sent, err = newService(t, late, &fakeMailer{}).Create(context.Background(), testSession(t), createRequest())
	if err != nil || sent.Link == "" {
		t.Fatalf("an unrecorded delivery must still return the link: %+v, %v", sent, err)
	}
}

func TestCreateRejectsBadInputAndRefusedChanges(t *testing.T) {
	t.Parallel()
	service := newService(t, &fakeStore{fail: map[Action]error{ActionCreate: ErrAlreadyInvited}}, &fakeMailer{})
	for name, mutate := range map[string]func(*CreateRequest){
		"bad email": func(request *CreateRequest) { request.Email = "not an address" },
		"bad role":  func(request *CreateRequest) { request.Role = "owner" },
	} {
		request := createRequest()
		mutate(&request)
		if _, err := service.Create(context.Background(), testSession(t), request); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Create() error = %v", name, err)
		}
	}
	if _, err := service.Create(context.Background(), testSession(t), createRequest()); !errors.Is(err, ErrAlreadyInvited) {
		t.Fatalf("Create() error = %v, want already invited", err)
	}
}

func TestNewServiceRequiresAnHTTPSOrigin(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{"http://console.example.com", "https://console.example.com/app",
		"https://user@console.example.com", ""} {
		if _, err := NewService(Options{Store: &fakeStore{}, Clock: clock{}, ConsoleOrigin: origin,
			SendTimeout: time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); !errors.Is(err, ErrInvalid) {
			t.Errorf("origin %q accepted", origin)
		}
	}
}

type reasonedFailure string

func (failure reasonedFailure) Error() string  { return "delivery failed" }
func (failure reasonedFailure) Reason() string { return string(failure) }

func TestDeliveryReasonIsBounded(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		err  error
		want string
	}{
		"ses code":     {fmt.Errorf("send: %w", reasonedFailure("AccessDeniedException")), "AccessDeniedException"},
		"joined":       {errors.Join(ErrMailRejected, reasonedFailure("reply_550")), "reply_550"},
		"no reason":    {errors.New("down"), "unknown"},
		"empty":        {reasonedFailure(""), "unknown"},
		"address text": {reasonedFailure("member@example.com"), "unknown"},
		"too long":     {reasonedFailure(strings.Repeat("A", 65)), "unknown"},
	} {
		if got := deliveryReason(test.err); got != test.want {
			t.Errorf("%s: deliveryReason() = %q, want %q", name, got, test.want)
		}
	}
}
