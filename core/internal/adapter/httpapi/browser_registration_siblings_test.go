package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
)

type browserPageSiblingFake struct {
	browserPageMoverFake
	devices   []control.BrowserSiblingDevice
	joinCalls int
	joined    string
}

func (fake *browserPageSiblingFake) LookupSiblingDevices(_ context.Context, digest accountsession.Digest,
	token string,
) ([]control.BrowserSiblingDevice, error) {
	if digest != fake.wantDigest || token != browserPageTestToken {
		return nil, nil
	}
	return append([]control.BrowserSiblingDevice(nil), fake.devices...), nil
}

func (fake *browserPageSiblingFake) JoinExistingDevice(_ context.Context, digest accountsession.Digest,
	token string, device publicid.ID,
) (bool, error) {
	fake.joinCalls++
	fake.joined = device.String()
	return digest == fake.wantDigest && token == browserPageTestToken, nil
}

const (
	siblingTestDevice  = "01890f00-0000-7000-8000-00000000d101"
	siblingTestNetwork = "01890f00-0000-7000-8000-00000000e101"
)

type siblingPageFixture struct {
	page    *BrowserRegistrationPage
	fake    *browserPageSiblingFake
	cookie  string
	path    string
	network string
	space   string
}

func newSiblingPageFixture(t *testing.T, source control.BrowserMoveSource,
	devices ...control.BrowserSiblingDevice,
) siblingPageFixture {
	t.Helper()
	page, reader, _ := browserRegistrationPageFixture(t)
	management, _ := newBrowserManagementFixture(t)
	boundToken, err := accountsession.ParseToken(managementTokenFixture)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := page.keys.ActiveDigest(boundToken)
	if err != nil {
		t.Fatal(err)
	}
	reader.want = digest
	selected := reader.page.Choices.Networks[0].NetworkID
	fake := &browserPageSiblingFake{devices: devices, browserPageMoverFake: browserPageMoverFake{
		source: source,
		browserPageApprovalFake: browserPageApprovalFake{
			wantDigest: digest, wantNetwork: selected,
			wantWorkspace: reader.page.Choices.WorkspaceID,
		},
	}}
	page, err = NewBrowserRegistrationPage(BrowserRegistrationPageOptions{
		Origin: management.origin, SessionKeys: page.keys, Choices: reader, Management: management,
		Approval: fake, Timeout: 5 * time.Second, Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return siblingPageFixture{
		page: page, fake: fake, cookie: boundToken.Encoded(),
		path: browserRegistrationPagePrefix + browserPageTestToken, network: selected.String(),
		space: reader.page.Choices.WorkspaceID.String(),
	}
}

func (fixture siblingPageFixture) sibling(state string) control.BrowserSiblingDevice {
	return control.BrowserSiblingDevice{
		DeviceID: siblingTestDevice, Hostname: "laptop-2", State: state,
		WorkspaceID: fixture.space, NetworkID: fixture.network, NetworkName: "Provider Net",
	}
}

func (fixture siblingPageFixture) post(form url.Values) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	fixture.page.ServeHTTP(response, browserRegistrationPostRequest(fixture.path, fixture.cookie, form))
	return response
}

func pageProof(body string) string {
	_, after, _ := strings.Cut(body, `name="csrf" value="`)
	proof, _, _ := strings.Cut(after, `"`)
	return proof
}

// The approval page names the person's Device already on this machine in a
// Network (duplicate-device design §7) and never offers that Network again.
func TestBrowserRegistrationPageNamesSiblingDevices(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, state, says, button string
	}{
		{
			name: "active", state: control.SiblingActive, says: "Member Workspace · laptop-2</span>",
			button: ">Use this account</button>",
		},
		{
			name: "signed out", state: control.SiblingSignedOut, says: "Member Workspace · laptop-2, signed out",
			button: ">Sign back in</button>",
		},
		{
			name: "expired", state: control.SiblingExpired, says: "Member Workspace · laptop-2, signed out",
			button: ">Sign back in</button>",
		},
		{name: "suspended", state: control.SiblingSuspended, says: "Member Workspace · suspended</span>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSiblingPageFixture(t, control.BrowserMoveSource{})
			fixture.fake.devices = []control.BrowserSiblingDevice{fixture.sibling(test.state)}
			landing := serveBrowserRegistrationPage(fixture.page, fixture.path, fixture.cookie)
			body := landing.Body.String()
			if landing.Code != http.StatusOK ||
				!strings.Contains(body, "Already on this computer, under other accounts") ||
				!strings.Contains(body, "<strong>Provider Net</strong>") ||
				!strings.Contains(body, test.says) ||
				strings.Contains(body, `value="`+fixture.network+`"`) ||
				!strings.Contains(body, "that this computer is not in already.") ||
				strings.Contains(body, `id="registration-confirm"`) {
				t.Fatalf("landing = (%d, %q)", landing.Code, body)
			}
			joinForm := `name="join" value="` + siblingTestDevice + `"`
			if strings.Contains(body, joinForm) != (test.button != "") ||
				(test.button != "" && !strings.Contains(body, test.button)) {
				t.Fatalf("join button = %q", body)
			}
		})
	}
}

// Signing the sign-in's own Device back in comes first (design §8.1): a
// sibling in that same Network is not named and the Network stays a choice.
func TestBrowserRegistrationPageResumeComesBeforeSibling(t *testing.T) {
	t.Parallel()
	fixture := newSiblingPageFixture(t, control.BrowserMoveSource{})
	fixture.fake.source = control.BrowserMoveSource{
		Kind: "resume", Hostname: "laptop",
		NetworkID: fixture.network, NetworkName: "Provider Net",
	}
	fixture.fake.devices = []control.BrowserSiblingDevice{fixture.sibling(control.SiblingActive)}
	landing := serveBrowserRegistrationPage(fixture.page, fixture.path, fixture.cookie)
	body := landing.Body.String()
	if landing.Code != http.StatusOK || strings.Contains(body, "Already on this computer") ||
		strings.Contains(body, `name="join"`) || !strings.Contains(body, `id="registration-confirm"`) {
		t.Fatalf("landing = (%d, %q)", landing.Code, body)
	}
	approved := fixture.post(url.Values{
		"csrf": {pageProof(body)}, "workspace": {fixture.space},
		"network": {fixture.network},
	})
	if approved.Code != http.StatusOK || fixture.fake.calls != 1 {
		t.Fatalf("resume = (%d, approve=%d)", approved.Code, fixture.fake.calls)
	}
}

// "Use that account" ends the sign-in and says where the app switches to;
// a suspended Device, an unknown one or a malformed form never joins.
func TestBrowserRegistrationPageJoinsExistingDevice(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		state  string
		form   func(proof string) url.Values
		code   int
		joins  int
		saying string
	}{
		{
			name: "active", state: control.SiblingActive, code: http.StatusOK, joins: 1,
			form:   func(proof string) url.Values { return url.Values{"csrf": {proof}, "join": {siblingTestDevice}} },
			saying: "It switches to the account already in <strong>Provider Net</strong>. You can close this tab.",
		},
		{
			name: "signed out", state: control.SiblingSignedOut, code: http.StatusOK, joins: 1,
			form:   func(proof string) url.Values { return url.Values{"csrf": {proof}, "join": {siblingTestDevice}} },
			saying: "and asks you to sign it back in",
		},
		{
			name: "suspended", state: control.SiblingSuspended, code: http.StatusNotFound,
			form: func(proof string) url.Values { return url.Values{"csrf": {proof}, "join": {siblingTestDevice}} },
		},
		{
			name: "another Device", state: control.SiblingActive, code: http.StatusNotFound,
			form: func(proof string) url.Values {
				return url.Values{"csrf": {proof}, "join": {"01890f00-0000-7000-8000-00000000d199"}}
			},
		},
		{
			name: "with a Network", state: control.SiblingActive, code: http.StatusBadRequest,
			form: func(proof string) url.Values {
				return url.Values{"csrf": {proof}, "join": {siblingTestDevice}, "network": {siblingTestNetwork}}
			},
		},
		{
			name: "malformed Device", state: control.SiblingActive, code: http.StatusBadRequest,
			form: func(proof string) url.Values { return url.Values{"csrf": {proof}, "join": {"laptop-2"}} },
		},
		{
			name: "no proof", state: control.SiblingActive, code: http.StatusForbidden,
			form: func(string) url.Values { return url.Values{"csrf": {"forged"}, "join": {siblingTestDevice}} },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSiblingPageFixture(t, control.BrowserMoveSource{})
			fixture.fake.devices = []control.BrowserSiblingDevice{fixture.sibling(test.state)}
			landing := serveBrowserRegistrationPage(fixture.page, fixture.path, fixture.cookie)
			response := fixture.post(test.form(pageProof(landing.Body.String())))
			if response.Code != test.code || fixture.fake.joinCalls != test.joins || fixture.fake.calls != 0 ||
				!strings.Contains(response.Body.String(), test.saying) {
				t.Fatalf("join = (%d, joins=%d, approvals=%d, %q)", response.Code, fixture.fake.joinCalls,
					fixture.fake.calls, response.Body.String())
			}
			if test.joins == 1 && fixture.fake.joined != siblingTestDevice {
				t.Fatalf("joined %q", fixture.fake.joined)
			}
		})
	}
}

// An approval for a Network where the machine already is the person's
// Device under another account (an older page, or the API) is refused
// before the store, and the page asks again (design §8.3); this wins over
// moving the machine (§8.1).
func TestBrowserRegistrationPageRefusesSecondDeviceInNetwork(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		source control.BrowserMoveSource
		move   bool
	}{
		{name: "new Device"},
		{name: "own Device elsewhere", move: true, source: control.BrowserMoveSource{
			Kind:     "own",
			DeviceID: "01890f00-0000-7000-8000-00000000d001", Hostname: "laptop",
			NetworkID: siblingTestNetwork, NetworkName: "Home",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSiblingPageFixture(t, test.source)
			landing := serveBrowserRegistrationPage(fixture.page, fixture.path, fixture.cookie)
			fixture.fake.devices = []control.BrowserSiblingDevice{fixture.sibling(control.SiblingActive)}
			form := url.Values{
				"csrf": {pageProof(landing.Body.String())}, "workspace": {fixture.space},
				"network": {fixture.network},
			}
			if test.move {
				form.Set("move", test.source.DeviceID)
			}
			response := fixture.post(form)
			body := response.Body.String()
			if response.Code != http.StatusConflict || fixture.fake.calls != 0 || fixture.fake.moveCalls != 0 ||
				!strings.Contains(body, `id="registration-conflict"`) ||
				!strings.Contains(body, `name="join" value="`+siblingTestDevice+`"`) ||
				strings.Contains(body, "move--missing") {
				t.Fatalf("approval = (%d, approve=%d, move=%d, %q)", response.Code, fixture.fake.calls,
					fixture.fake.moveCalls, body)
			}
		})
	}
}
