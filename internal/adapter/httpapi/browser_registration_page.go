package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	browserRegistrationPagePrefix = "/register/v1/"
	browserRegistrationStylesPath = "/register/v1/styles.css"
	browserRegistrationScriptPath = "/register/v1/client.js"
	browserRegistrationPageLimit  = 100
	browserRegistrationBodyLimit  = 64 << 10
	browserRegistrationPostLimit  = 2048
)

// ErrInvalidBrowserRegistrationPage reports invalid page composition or bounds.
var ErrInvalidBrowserRegistrationPage = errors.New("http api: invalid browser registration page")

// BrowserRegistrationChoices reads an SSO-bound, read-only enrollment view.
type BrowserRegistrationChoices interface {
	ReadWorkspaces(context.Context, accountsession.Digest, string, workspace.ID, int) (
		control.BrowserWorkspaceChoicePage, bool, error)
	ReadNetworks(context.Context, accountsession.Digest, string, workspace.ID, network.ID, int) (
		control.BrowserChoicePage, bool, error)
}

// BrowserRegistrationApprover rechecks the exact Session, intent, and Network
// authority in its committing transaction. A false result reveals no cause.
type BrowserRegistrationApprover interface {
	ApproveInWorkspace(context.Context, accountsession.Digest, string, workspace.ID, network.ID) (bool, error)
}

// BrowserRegistrationPageOptions binds the page to one origin and SSO authority.
type BrowserRegistrationPageOptions struct {
	Origin      string
	SessionKeys *accountsession.Keyring
	Choices     BrowserRegistrationChoices
	Management  *BrowserManagement
	Approval    BrowserRegistrationApprover
	Timeout     time.Duration
	Concurrency int
}

// BrowserRegistrationPage owns the SSO-bound landing and optional approval
// form. Read-only composition never renders a form or accepts a POST.
type BrowserRegistrationPage struct {
	host         string
	keys         *accountsession.Keyring
	choices      BrowserRegistrationChoices
	management   *BrowserManagement
	approval     BrowserRegistrationApprover
	timeout      time.Duration
	slots        chan struct{}
	loginPage    *template.Template
	choicesPage  *template.Template
	approvedPage *template.Template
}

// NewBrowserRegistrationPage validates the origin, authority, and request bounds.
func NewBrowserRegistrationPage(options BrowserRegistrationPageOptions) (*BrowserRegistrationPage, error) {
	origin, err := url.Parse(options.Origin)
	if err != nil || origin == nil || origin.Scheme != "https" || origin.Host == "" ||
		origin.User != nil || origin.Opaque != "" || origin.Path != "" ||
		origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || origin.RawFragment != "" ||
		"https://"+origin.Host != options.Origin || !canonicalBrowserManagementHost(origin) ||
		!options.SessionKeys.IsValid() || nilContinuationDependency(options.Choices) ||
		options.Timeout <= 0 || options.Timeout > 30*time.Second ||
		options.Concurrency < 1 || options.Concurrency > 128 ||
		((options.Management == nil) != nilContinuationDependency(options.Approval)) {
		return nil, ErrInvalidBrowserRegistrationPage
	}
	if options.Management != nil && (!validBrowserManagementOwner(options.Management) ||
		options.Management.host != origin.Host || options.Management.entropy == nil) {
		return nil, ErrInvalidBrowserRegistrationPage
	}
	loginPage, err := template.New("registration-login").Parse(browserRegistrationLoginHTML)
	if err != nil {
		return nil, ErrInvalidBrowserRegistrationPage
	}
	choicesPage, err := template.New("registration-choices").Parse(browserRegistrationChoicesHTML)
	if err != nil {
		return nil, ErrInvalidBrowserRegistrationPage
	}
	approvedPage, err := template.New("registration-approved").Parse(browserRegistrationApprovedHTML)
	if err != nil {
		return nil, ErrInvalidBrowserRegistrationPage
	}
	return &BrowserRegistrationPage{
		host: origin.Host, keys: options.SessionKeys, choices: options.Choices,
		management: options.Management, approval: options.Approval,
		timeout: options.Timeout, slots: make(chan struct{}, options.Concurrency),
		loginPage: loginPage, choicesPage: choicesPage, approvedPage: approvedPage,
	}, nil
}

func (page *BrowserRegistrationPage) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setLoginSecurityHeaders(response.Header())
	if page == nil || page.keys == nil || page.choices == nil || page.slots == nil ||
		request == nil || !page.validRequest(request) {
		http.Error(response, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if request.URL.Path == browserRegistrationStylesPath {
		response.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(response, browserRegistrationCSS+browserRegistrationWorkspaceCSS)
		return
	}
	if request.URL.Path == browserRegistrationScriptPath {
		response.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(response, browserRegistrationScript)
		return
	}
	encodedToken, _ := strings.CutPrefix(request.URL.Path, browserRegistrationPagePrefix)
	select {
	case page.slots <- struct{}{}:
		defer func() { <-page.slots }()
	default:
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), page.timeout)
	defer cancel()
	if request.Method == http.MethodPost {
		page.approve(ctx, response, request, encodedToken)
		return
	}
	if len(request.Header.Values("Cookie")) == 0 {
		page.render(response, page.loginPage, struct{ Path string }{Path: request.URL.Path})
		return
	}
	token, err := readBrowserSessionCookie(request.Header)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	digests, err := page.keys.Digests(token)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	for _, digest := range digests {
		landing, view, found, err := page.readChoices(ctx, digest, encodedToken, request)
		if err != nil {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if found {
			if landing.State == "approved" {
				page.render(response, page.approvedPage, nil)
				return
			}
			view.Hostname = landing.Hostname
			view.Path = request.URL.Path
			if page.approval != nil && len(view.Networks) > 0 {
				session, err := page.management.management.sessions.Authenticate(ctx, token)
				if err != nil || !page.management.activeSession(token, session, page.management.clock.Now()) {
					http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
					return
				}
				var nonce [32]byte
				if _, err := io.ReadFull(page.management.entropy, nonce[:]); err != nil {
					http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
					return
				}
				proof, err := page.management.sealProof(token, session, page.management.clock.Now(), nonce)
				if err != nil {
					http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
					return
				}
				view.CSRF = proof.encoded
				view.Action = request.URL.Path
			}
			page.render(response, page.choicesPage, view)
			return
		}
	}
	http.Error(response, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

type browserRegistrationNetworkView struct {
	ID   string
	Name string
}

type browserRegistrationWorkspaceView struct {
	Name string
	Path string
}

type browserRegistrationChoiceView struct {
	Hostname      string
	Path          string
	Workspaces    []browserRegistrationWorkspaceView
	WorkspaceID   string
	WorkspaceName string
	Next          string
	Networks      []browserRegistrationNetworkView
	CSRF          string
	Action        string
}

func (page *BrowserRegistrationPage) readChoices(ctx context.Context, digest accountsession.Digest,
	encodedToken string, request *http.Request,
) (enrollment.BrowserIntentLanding, browserRegistrationChoiceView, bool, error) {
	selected, workspaceAfter, networkAfter, err := browserRegistrationSelection(request.URL.RawQuery)
	if err != nil {
		return enrollment.BrowserIntentLanding{}, browserRegistrationChoiceView{}, false, err
	}
	if !selected.IsValid() {
		choicePage, found, err := page.choices.ReadWorkspaces(ctx, digest, encodedToken,
			workspaceAfter, browserRegistrationPageLimit)
		view := browserRegistrationChoiceView{}
		for _, choice := range choicePage.Choices.Workspaces {
			view.Workspaces = append(view.Workspaces, browserRegistrationWorkspaceView{
				Name: choice.DisplayName,
				Path: request.URL.Path + "?" + url.Values{"workspace": {choice.WorkspaceID.String()}}.Encode(),
			})
		}
		if choicePage.HasMore && len(choicePage.Choices.Workspaces) > 0 {
			last := choicePage.Choices.Workspaces[len(choicePage.Choices.Workspaces)-1]
			view.Next = request.URL.Path + "?" + url.Values{"after": {last.WorkspaceID.String()}}.Encode()
		}
		return choicePage.Landing, view, found, err
	}
	choicePage, found, err := page.choices.ReadNetworks(ctx, digest, encodedToken,
		selected, networkAfter, browserRegistrationPageLimit)
	view := browserRegistrationChoiceView{
		WorkspaceID: selected.String(), WorkspaceName: choicePage.Choices.WorkspaceDisplayName,
		Networks: browserRegistrationNetworks(choicePage),
	}
	if choicePage.HasMore && len(choicePage.Choices.Networks) > 0 {
		last := choicePage.Choices.Networks[len(choicePage.Choices.Networks)-1]
		view.Next = request.URL.Path + "?" + url.Values{
			"workspace": {selected.String()}, "after": {last.NetworkID.String()},
		}.Encode()
	}
	return choicePage.Landing, view, found, err
}

func browserRegistrationSelection(rawQuery string) (workspace.ID, workspace.ID, network.ID, error) {
	selected, workspaceAfter, networkAfter := workspace.ID{}, workspace.ID{}, network.ID{}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(rawQuery) > 128 || values.Encode() != rawQuery || len(values) > 2 {
		return selected, workspaceAfter, networkAfter, ErrInvalidBrowserRegistrationPage
	}
	for name, entries := range values {
		if (name != "workspace" && name != "after") || len(entries) != 1 || entries[0] == "" {
			return selected, workspaceAfter, networkAfter, ErrInvalidBrowserRegistrationPage
		}
	}
	if value := values.Get("workspace"); value != "" {
		selected, err = workspace.ParseID(value)
		if err != nil || selected.String() != value {
			return selected, workspaceAfter, networkAfter, ErrInvalidBrowserRegistrationPage
		}
	}
	if value := values.Get("after"); value != "" {
		if selected.IsValid() {
			networkAfter, err = network.ParseID(value)
			if err != nil || networkAfter.String() != value {
				return selected, workspaceAfter, networkAfter, ErrInvalidBrowserRegistrationPage
			}
		} else {
			workspaceAfter, err = workspace.ParseID(value)
			if err != nil || workspaceAfter.String() != value {
				return selected, workspaceAfter, networkAfter, ErrInvalidBrowserRegistrationPage
			}
		}
	}
	return selected, workspaceAfter, networkAfter, nil
}

func browserRegistrationNetworks(page control.BrowserChoicePage) []browserRegistrationNetworkView {
	names := make([]browserRegistrationNetworkView, 0, len(page.Choices.Networks))
	for _, choice := range page.Choices.Networks {
		names = append(names, browserRegistrationNetworkView{
			ID: choice.NetworkID.String(), Name: choice.DisplayName,
		})
	}
	return names
}

func (page *BrowserRegistrationPage) approve(
	ctx context.Context, response http.ResponseWriter, request *http.Request, encodedToken string,
) {
	if page.approval == nil || page.management == nil ||
		singleHeader(request.Header, "Origin") != page.management.origin ||
		singleHeader(request.Header, "Content-Type") != "application/x-www-form-urlencoded" ||
		request.Body == nil || request.ContentLength > browserRegistrationPostLimit {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, browserRegistrationPostLimit+1))
	if err != nil || len(body) > browserRegistrationPostLimit {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form) != 3 || len(form["csrf"]) != 1 ||
		len(form["workspace"]) != 1 || len(form["network"]) != 1 {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	workspaceID, err := workspace.ParseID(form.Get("workspace"))
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	networkID, err := network.ParseID(form.Get("network"))
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	token, err := readBrowserSessionCookie(request.Header)
	if err != nil || token.DeploymentID() != page.management.deploymentID {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if _, err := page.management.readProof(token, form.Get("csrf"), page.management.clock.Now()); err != nil {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	session, err := page.management.management.sessions.Authenticate(ctx, token)
	if err != nil || !page.management.activeSession(token, session, page.management.clock.Now()) {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	digests, err := page.keys.Digests(token)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	for _, digest := range digests {
		approved, err := page.approval.ApproveInWorkspace(ctx, digest, encodedToken, workspaceID, networkID)
		if err != nil {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if approved {
			page.render(response, page.approvedPage, nil)
			return
		}
	}
	http.Error(response, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func (page *BrowserRegistrationPage) render(
	response http.ResponseWriter, view *template.Template, data any,
) {
	var body bytes.Buffer
	if err := view.Execute(&body, data); err != nil || body.Len() > browserRegistrationBodyLimit {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	formAction := "'none'"
	scriptPolicy := ""
	if page.approval != nil {
		formAction = "'self'"
		scriptPolicy = "; script-src 'self'; connect-src 'self'"
	}
	response.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action "+formAction+scriptPolicy)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body.Bytes())
}

func (page *BrowserRegistrationPage) validRequest(request *http.Request) bool {
	if (request.Method != http.MethodGet && (request.Method != http.MethodPost || page.approval == nil)) ||
		request.URL == nil || request.TLS == nil ||
		!request.TLS.HandshakeComplete || request.TLS.Version < tls.VersionTLS12 ||
		request.Host != page.host || !boundedLoginHeaders(request.Header) ||
		request.URL.Scheme != "" || request.URL.Host != "" || request.URL.User != nil ||
		request.URL.Opaque != "" || request.URL.RawPath != "" ||
		request.URL.ForceQuery ||
		request.URL.Fragment != "" || request.URL.RawFragment != "" ||
		request.RequestURI != request.URL.RequestURI() ||
		len(request.URL.Path) > 256 {
		return false
	}
	if request.URL.Path == browserRegistrationStylesPath || request.URL.Path == browserRegistrationScriptPath {
		return request.Method == http.MethodGet && request.URL.RawQuery == ""
	}
	if request.Method == http.MethodPost && request.URL.RawQuery != "" {
		return false
	}
	if _, _, _, err := browserRegistrationSelection(request.URL.RawQuery); err != nil {
		return false
	}
	encodedToken, ok := strings.CutPrefix(request.URL.Path, browserRegistrationPagePrefix)
	if !ok || strings.Contains(encodedToken, "/") {
		return false
	}
	_, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken)
	return err == nil
}

const browserRegistrationLoginHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>Sign in to connect device | MeshTransit</title><link rel="stylesheet" href="/register/v1/styles.css"></head>
<body><main><p class="eyebrow">MeshTransit · Device connection</p><h1>Sign in to continue</h1><p>Open Mesh Console to sign in. Return to this tab and reload after sign-in.</p><p><a class="action" href="/console" target="_blank" rel="noopener noreferrer">Open Mesh Console</a></p><p><a href="{{.Path}}">Reload this request</a></p></main></body></html>`

const browserRegistrationChoicesHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>Choose {{if .WorkspaceID}}Network{{else}}Workspace{{end}} | MeshTransit</title><link rel="stylesheet" href="/register/v1/styles.css"></head>
<body><main><p class="eyebrow">MeshTransit · Device connection</p>
<p class="steps">{{if .WorkspaceID}}Step 2 of 2 · Network{{else}}Step 1 of 2 · Workspace{{end}}</p>
<h1>Choose a {{if .WorkspaceID}}Network{{else}}Workspace{{end}}</h1><p>Device: <strong>{{.Hostname}}</strong></p>
{{if .WorkspaceID}}<p>Workspace: <strong>{{.WorkspaceName}}</strong> · <a href="{{.Path}}">Change Workspace</a></p>
{{if .Networks}}<p>Networks you can join in this Workspace:</p>
{{if .CSRF}}<form id="registration-form" method="post" action="{{.Action}}" aria-busy="false">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="workspace" value="{{.WorkspaceID}}">
<fieldset><legend>Select one Network</legend>{{range .Networks}}<label class="choice"><input type="radio" name="network" value="{{.ID}}" required><span>{{.Name}}</span></label>{{end}}</fieldset>
<button id="registration-confirm" type="submit">Connect device</button><p id="registration-status" role="status" aria-live="polite"></p></form><script src="/register/v1/client.js" defer></script>
{{else}}<ul>{{range .Networks}}<li>{{.Name}}</li>{{end}}</ul>{{end}}
{{else}}<p>No Network is currently available to connect this device in this Workspace.</p>{{end}}
{{else}}<p>Select a Workspace you belong to, including one shared with you.</p>
{{if .Workspaces}}<ul>{{range .Workspaces}}<li class="workspace"><a class="choice" href="{{.Path}}">{{.Name}}<span aria-hidden="true">›</span></a></li>{{end}}</ul>
{{else}}<p>No Workspace is currently available with this sign-in.</p>{{end}}{{end}}
{{if .Next}}<p><a href="{{.Next}}">More {{if .WorkspaceID}}Networks{{else}}Workspaces{{end}}</a></p>{{end}}
</main></body></html>`

//go:embed browser_registration_page.js
var browserRegistrationScript string

const browserRegistrationApprovedHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>Device approved | MeshTransit</title><link rel="stylesheet" href="/register/v1/styles.css"></head>
<body><main><p class="eyebrow">MeshTransit · Device connection</p><h1>Device approved</h1><p>Return to Mesh Client. It will finish connecting to the selected Network.</p></main></body></html>`

const browserRegistrationCSS = `:root{color-scheme:light;--ink:#17212f;--muted:#425166;--paper:#fff;--line:#cbd5e1;--focus:#1d4ed8}*{box-sizing:border-box}body{margin:0;padding:2rem 1rem;background:var(--paper);color:var(--ink);font:1rem/1.55 system-ui,sans-serif}main{max-width:36rem;margin:7vh auto}.eyebrow{font-size:.875rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}h1{font-size:clamp(1.75rem,5vw,2.25rem);line-height:1.2}p{max-width:62ch}ul{list-style:none;padding:0;margin:1.5rem 0}li,.choice{border:1px solid var(--line);border-radius:.75rem;padding:1rem 1.25rem;margin:.75rem 0;font-weight:600}.choice{display:flex;gap:.75rem;align-items:center;cursor:pointer}.choice input{width:1.25rem;height:1.25rem}fieldset{border:0;padding:0;margin:0}legend{font-weight:700}button{min-height:44px;border:0;border-radius:.5rem;padding:.65rem 1rem;background:var(--ink);color:var(--paper);font:inherit;font-weight:700;cursor:pointer}a{color:#1742a0}a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid var(--focus);outline-offset:4px}.action{display:inline-block;min-height:44px;padding:.65rem 1rem;border-radius:.5rem;background:var(--ink);color:var(--paper);font-weight:700;text-decoration:none}`

var _ http.Handler = (*BrowserRegistrationPage)(nil)

const browserRegistrationWorkspaceCSS = `.steps{color:var(--muted);font-size:.875rem}.workspace{border:0;padding:0;font-weight:inherit}.workspace .choice{color:var(--ink);text-decoration:none;justify-content:space-between;min-height:44px}.workspace .choice:hover{border-color:var(--focus)}`
