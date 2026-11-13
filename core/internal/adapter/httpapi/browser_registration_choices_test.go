package httpapi

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

// manyWorkspacesFake is a person in several Workspaces; Networks come in
// pages of pageSize after a cursor, as Core reads them.
type manyWorkspacesFake struct {
	want       accountsession.Digest
	landing    enrollment.BrowserIntentLanding
	workspaces []enrollment.BrowserEnrollmentWorkspaceChoice
	networks   map[workspace.ID][]enrollment.BrowserEnrollmentNetworkChoice
	pageSize   int
	reads      []string
}

func (fake *manyWorkspacesFake) ReadWorkspaces(_ context.Context, digest accountsession.Digest, _ string,
	_ workspace.ID, _ int,
) (control.BrowserWorkspaceChoicePage, bool, error) {
	if digest != fake.want {
		return control.BrowserWorkspaceChoicePage{}, false, nil
	}
	return control.BrowserWorkspaceChoicePage{
		Landing: fake.landing,
		Choices: enrollment.BrowserEnrollmentWorkspaceChoices{Workspaces: fake.workspaces},
	}, true, nil
}

func (fake *manyWorkspacesFake) ReadNetworks(_ context.Context, digest accountsession.Digest, _ string,
	selected workspace.ID, after network.ID, limit int,
) (control.BrowserChoicePage, bool, error) {
	if digest != fake.want || limit != browserRegistrationPageLimit {
		return control.BrowserChoicePage{}, false, control.ErrInvalidBrowserChoice
	}
	fake.reads = append(fake.reads, selected.String()+"/"+after.String())
	all := fake.networks[selected]
	start := 0
	for index, choice := range all {
		if choice.NetworkID == after {
			start = index + 1
		}
	}
	end := min(start+fake.pageSize, len(all))
	return control.BrowserChoicePage{Landing: fake.landing, Choices: enrollment.BrowserEnrollmentChoices{
		WorkspaceID: selected, Networks: all[start:end],
	}, HasMore: end < len(all)}, true, nil
}

func mustWorkspace(t *testing.T, id string) workspace.ID {
	t.Helper()
	parsed, err := workspace.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func mustNetwork(t *testing.T, id string) network.ID {
	t.Helper()
	parsed, err := network.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func manyWorkspacesPage(t *testing.T) (*BrowserRegistrationPage, *manyWorkspacesFake, string) {
	t.Helper()
	base, reader, session := browserRegistrationPageFixture(t)
	home := mustWorkspace(t, "01890f00-0000-7000-8000-000000000a01")
	work := mustWorkspace(t, "01890f00-0000-7000-8000-000000000a02")
	fake := &manyWorkspacesFake{
		want: reader.want, landing: reader.page.Landing, pageSize: 2,
		workspaces: []enrollment.BrowserEnrollmentWorkspaceChoice{
			{WorkspaceID: home, DisplayName: "Home"}, {WorkspaceID: work, DisplayName: "Work"},
		},
		networks: map[workspace.ID][]enrollment.BrowserEnrollmentNetworkChoice{
			home: {
				{NetworkID: mustNetwork(t, "01890f00-0000-7000-8000-000000000b01"), DisplayName: "Lab"},
				{NetworkID: mustNetwork(t, "01890f00-0000-7000-8000-000000000b02"), DisplayName: "Office"},
				{NetworkID: mustNetwork(t, "01890f00-0000-7000-8000-000000000b03"), DisplayName: "Studio"},
			},
			work: {{NetworkID: mustNetwork(t, "01890f00-0000-7000-8000-000000000b04"), DisplayName: "Prod"}},
		},
	}
	page, err := NewBrowserRegistrationPage(BrowserRegistrationPageOptions{
		Origin: "https://console.example.test", SessionKeys: base.keys,
		Choices: fake, Timeout: 5 * time.Second, Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return page, fake, session.Encoded()
}

func TestBrowserRegistrationSelectionIsOnlyThePagesOwn(t *testing.T) {
	t.Parallel()
	const ws = "01890f00-0000-7000-8000-000000000a01"
	const net = "01890f00-0000-7000-8000-000000000b01"
	for query, admitted := range map[string]bool{
		"":                                        true,
		"workspace=" + ws:                         true,
		"workspace=" + ws + "&after=" + net:       true,
		"after=" + net + "&workspace=" + ws:       false,
		"workspace=" + strings.ToUpper(ws):        false,
		"workspace=" + ws + "&after=" + net + "&": false,
		"workspace=" + ws + "&x=1":                false,
		"workspace=" + ws + "&workspace=" + ws:    false,
		"workspace=" + url.QueryEscape(ws+" "):    false,
		"workspace=not-an-id":                     false,
		"network=" + net:                          false,
	} {
		if _, ok := parseBrowserRegistrationSelection(query); ok != admitted {
			t.Errorf("%q admitted = %t", query, ok)
		}
	}
}

// One Workspace's Networks at a time: the one asked for, else the first;
// every Workspace is a choice in the select.
func TestBrowserRegistrationPageShowsOneWorkspace(t *testing.T) {
	t.Parallel()
	page, fake, cookie := manyWorkspacesPage(t)
	path := browserRegistrationPagePrefix + browserPageTestToken
	first := serveBrowserRegistrationPage(page, path, cookie)
	body := first.Body.String()
	if first.Code != http.StatusOK || !strings.Contains(body, `<select id="workspace-select" name="workspace">`) ||
		!strings.Contains(body, `value="01890f00-0000-7000-8000-000000000a01" selected>Home</option>`) ||
		!strings.Contains(body, ">Work</option>") || !strings.Contains(body, "Lab") ||
		strings.Contains(body, "Prod") || len(fake.reads) != 1 {
		t.Fatalf("first landing = (%d, reads %v, %q)", first.Code, fake.reads, body)
	}
	work := serveBrowserRegistrationPage(page, path+"?workspace=01890f00-0000-7000-8000-000000000a02", cookie)
	if body := work.Body.String(); work.Code != http.StatusOK || !strings.Contains(body, "Prod") ||
		strings.Contains(body, "Lab") || !strings.Contains(body, `value="01890f00-0000-7000-8000-000000000a02" selected>`) {
		t.Fatalf("Work = (%d, %q)", work.Code, body)
	}
	// A Workspace the person may not join in shows nothing of it.
	other := serveBrowserRegistrationPage(page, path+"?workspace=01890f00-0000-7000-8000-000000000a09", cookie)
	if body := other.Body.String(); other.Code != http.StatusOK || !strings.Contains(body, "Lab") {
		t.Fatalf("unknown Workspace = (%d, %q)", other.Code, body)
	}
}

// Networks come a page at a time, with links to the next page and back.
func TestBrowserRegistrationPagePagesNetworks(t *testing.T) {
	t.Parallel()
	page, _, cookie := manyWorkspacesPage(t)
	path := browserRegistrationPagePrefix + browserPageTestToken
	first := serveBrowserRegistrationPage(page, path, cookie).Body.String()
	next := path + "?workspace=01890f00-0000-7000-8000-000000000a01&after=01890f00-0000-7000-8000-000000000b02"
	if !strings.Contains(first, `href="`+html.EscapeString(next)+`">Next Networks</a>`) ||
		strings.Contains(first, "Studio") || strings.Contains(first, "First Networks") {
		t.Fatalf("first page = %q", first)
	}
	second := serveBrowserRegistrationPage(page, next, cookie)
	body := second.Body.String()
	if second.Code != http.StatusOK || !strings.Contains(body, "Studio") || strings.Contains(body, "Lab") ||
		!strings.Contains(body, "First Networks") || strings.Contains(body, "Next Networks") {
		t.Fatalf("second page = (%d, %q)", second.Code, body)
	}
}

// Any other query, and a query on a POST, is no page at all.
func TestBrowserRegistrationPageRefusesOtherQueries(t *testing.T) {
	t.Parallel()
	page, _, cookie := manyWorkspacesPage(t)
	path := browserRegistrationPagePrefix + browserPageTestToken
	for _, query := range []string{"x=1", "workspace=bad", "after=01890f00-0000-7000-8000-000000000b01"} {
		if response := serveBrowserRegistrationPage(page, path+"?"+query, cookie); response.Code != http.StatusNotFound {
			t.Errorf("?%s = %d", query, response.Code)
		}
	}
	fixture := newSiblingPageFixture(t, control.BrowserMoveSource{})
	response := httptest.NewRecorder()
	fixture.page.ServeHTTP(response, browserRegistrationPostRequest(
		fixture.path+"?workspace=01890f00-0000-7000-8000-000000000a01", fixture.cookie, url.Values{}))
	if response.Code != http.StatusNotFound {
		t.Fatalf("POST with a query = %d", response.Code)
	}
}

// Beyond three, the person's Devices on this machine fold under Show more.
func TestBrowserRegistrationPageFoldsManySiblings(t *testing.T) {
	t.Parallel()
	fixture := newSiblingPageFixture(t, control.BrowserMoveSource{})
	for index := range 5 {
		device := fixture.sibling(control.SiblingActive)
		device.DeviceID = "01890f00-0000-7000-8000-00000000d1" + string(rune('0'+index)) + "0"
		device.NetworkID = "01890f00-0000-7000-8000-00000000e1" + string(rune('0'+index)) + "0"
		fixture.fake.devices = append(fixture.fake.devices, device)
	}
	body := serveBrowserRegistrationPage(fixture.page, fixture.path, fixture.cookie).Body.String()
	if !strings.Contains(body, "<summary>Show 2 more</summary>") ||
		strings.Count(body, `class="sibling__form"`) != 5 {
		t.Fatalf("landing = %q", body)
	}
}

// Without a query the page opens on the Workspace this computer is in, and
// its Network is listed (first) even when it is not on the first page; a
// Workspace the person is not in, with a cursor, is the default and its
// cursor is ignored.
func TestBrowserRegistrationPageKeepsTheComputersOwnNetwork(t *testing.T) {
	t.Parallel()
	page, fake, _ := manyWorkspacesPage(t)
	page.approval = &browserPageSiblingFake{browserPageMoverFake: browserPageMoverFake{source: control.BrowserMoveSource{
		Kind: "resume", Hostname: "laptop", WorkspaceID: "01890f00-0000-7000-8000-000000000a01",
		NetworkID: "01890f00-0000-7000-8000-000000000b03", NetworkName: "Studio",
	}}}
	path := browserRegistrationPagePrefix + browserPageTestToken
	read := func(selection browserRegistrationSelection) browserRegistrationChoiceView {
		t.Helper()
		_, view, found, err := page.readPage(t.Context(), fake.want, browserPageTestToken, selection)
		if err != nil || !found {
			t.Fatalf("readPage = %v/%v", found, err)
		}
		return view
	}
	home := read(browserRegistrationSelection{})
	if home.Workspace.Name != "Home" || len(home.Networks) != 3 || home.Networks[0].Name != "Studio" ||
		home.MoveWorkspace != "" || home.MoveElsewhere != "" {
		t.Fatalf("own Workspace = %+v", home)
	}
	// Inside this page's range but not listed: the person may not join it
	// any more, so it is not offered (re-check R1).
	page.approval = &browserPageSiblingFake{browserPageMoverFake: browserPageMoverFake{source: control.BrowserMoveSource{
		Kind: "resume", Hostname: "laptop", WorkspaceID: "01890f00-0000-7000-8000-000000000a01",
		NetworkID: "01890f00-0000-7000-8000-000000000b00", NetworkName: "Gone",
	}}}
	gone := read(browserRegistrationSelection{})
	for _, choice := range gone.Networks {
		if choice.Name == "Gone" {
			t.Fatalf("a Network inside this page's range was pinned: %+v", gone.Networks)
		}
	}
	page.approval = &browserPageSiblingFake{browserPageMoverFake: browserPageMoverFake{source: control.BrowserMoveSource{
		Kind: "resume", Hostname: "laptop", WorkspaceID: "01890f00-0000-7000-8000-000000000a01",
		NetworkID: "01890f00-0000-7000-8000-000000000b03", NetworkName: "Studio",
	}}}
	work := read(browserRegistrationSelection{workspace: mustWorkspace(t, "01890f00-0000-7000-8000-000000000a02")})
	if work.Workspace.Name != "Work" || work.MoveWorkspace != "Home" ||
		work.MoveElsewhere != path+"?workspace=01890f00-0000-7000-8000-000000000a01" {
		t.Fatalf("another Workspace = %+v", work)
	}
	fake.reads = nil
	read(browserRegistrationSelection{
		workspace: mustWorkspace(t, "01890f00-0000-7000-8000-000000000a09"),
		after:     mustNetwork(t, "01890f00-0000-7000-8000-000000000b02"),
	})
	if len(fake.reads) != 1 || !strings.HasPrefix(fake.reads[0], "01890f00-0000-7000-8000-000000000a01/") ||
		strings.HasSuffix(fake.reads[0], "b02") {
		t.Fatalf("a foreign Workspace's cursor was used: %v", fake.reads)
	}
}

// Without the script, the approval form posts exactly what the server
// takes: its proof, the Workspace shown and the Network chosen.
func TestBrowserRegistrationPageFormPostsWithoutScript(t *testing.T) {
	t.Parallel()
	fixture := newSiblingPageFixture(t, control.BrowserMoveSource{})
	body := serveBrowserRegistrationPage(fixture.page, fixture.path, fixture.cookie).Body.String()
	if !strings.Contains(body, `<input type="hidden" name="workspace" value="`+fixture.space+`">`) {
		t.Fatalf("form = %q", body)
	}
	approved := fixture.post(url.Values{
		"csrf": {pageProof(body)}, "workspace": {fixture.space},
		"network": {fixture.network},
	})
	if approved.Code != http.StatusOK || fixture.fake.calls != 1 {
		t.Fatalf("plain form post = (%d, approvals %d)", approved.Code, fixture.fake.calls)
	}
}

func FuzzBrowserRegistrationSelection(f *testing.F) {
	for _, seed := range []string{
		"", "workspace=01890f00-0000-7000-8000-000000000a01",
		"workspace=01890f00-0000-7000-8000-000000000a01&after=01890f00-0000-7000-8000-000000000b01", "x=1&&",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		selection, ok := parseBrowserRegistrationSelection(raw)
		if ok && selection.query() != raw {
			t.Fatalf("admitted %q, written %q", raw, selection.query())
		}
	})
}
