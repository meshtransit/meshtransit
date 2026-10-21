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

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	browserRegistrationPagePrefix = "/register/v1/"
	browserRegistrationStylesPath = "/register/v1/styles.css"
	browserRegistrationScriptPath = "/register/v1/client.js"
	browserRegistrationPageLimit  = 100
	// browserRegistrationWorkspaceLimit bounds the Network reads one landing
	// makes; a person rarely belongs to more Workspaces than this.
	browserRegistrationWorkspaceLimit = 20
	browserRegistrationBodyLimit      = 64 << 10
	browserRegistrationPostLimit      = 2048
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
		_, _ = io.WriteString(response, browserRegistrationCSS)
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
		page.render(response, page.loginPage, struct {
			Path      string
			AutoStart bool
		}{Path: request.URL.Path, AutoStart: page.approval != nil})
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
		landing, view, found, err := page.readChoices(ctx, digest, encodedToken)
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
			// The browser may hold another person's or another account's
			// session; the page always offers signing in with another one.
			view.SwitchAccount = page.approval != nil
			if page.approval != nil && view.NetworkCount > 0 {
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
	ID           string
	Name         string
	Initial      string
	Networks     []browserRegistrationNetworkView
	MoreNetworks bool
}

type browserRegistrationChoiceView struct {
	Hostname       string
	Path           string
	Workspaces     []browserRegistrationWorkspaceView
	NetworkCount   int
	MoreWorkspaces bool
	CSRF           string
	Action         string
	SwitchAccount  bool
}

// readChoices lists every Workspace the Session may enroll into together with
// its joinable Networks, so one landing offers both choices at once.
func (page *BrowserRegistrationPage) readChoices(ctx context.Context, digest accountsession.Digest,
	encodedToken string,
) (enrollment.BrowserIntentLanding, browserRegistrationChoiceView, bool, error) {
	workspaces, found, err := page.choices.ReadWorkspaces(ctx, digest, encodedToken,
		workspace.ID{}, browserRegistrationPageLimit)
	if err != nil || !found {
		return enrollment.BrowserIntentLanding{}, browserRegistrationChoiceView{}, false, err
	}
	view := browserRegistrationChoiceView{MoreWorkspaces: workspaces.HasMore}
	for index, choice := range workspaces.Choices.Workspaces {
		if index == browserRegistrationWorkspaceLimit {
			view.MoreWorkspaces = true
			break
		}
		networks, found, err := page.choices.ReadNetworks(ctx, digest, encodedToken,
			choice.WorkspaceID, network.ID{}, browserRegistrationPageLimit)
		if err != nil {
			return enrollment.BrowserIntentLanding{}, browserRegistrationChoiceView{}, false, err
		}
		group := browserRegistrationWorkspaceView{
			ID: choice.WorkspaceID.String(), Name: choice.DisplayName, Initial: workspaceInitial(choice.DisplayName),
		}
		if found {
			group.Networks = browserRegistrationNetworks(networks)
			group.MoreNetworks = networks.HasMore
		}
		view.NetworkCount += len(group.Networks)
		view.Workspaces = append(view.Workspaces, group)
	}
	return workspaces.Landing, view, true, nil
}

func workspaceInitial(name string) string {
	for _, character := range strings.TrimSpace(name) {
		return strings.ToUpper(string(character))
	}
	return "W"
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
	if request.URL.RawQuery != "" {
		return false
	}
	encodedToken, ok := strings.CutPrefix(request.URL.Path, browserRegistrationPagePrefix)
	if !ok || strings.Contains(encodedToken, "/") {
		return false
	}
	_, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken)
	return err == nil
}

const browserRegistrationHead = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer">`

const browserRegistrationBrand = `<header class="brand"><span class="brand__mark" aria-hidden="true">›</span><span>MeshTransit</span></header>`

const browserRegistrationLoginHTML = browserRegistrationHead + `<title>Sign in to connect device | MeshTransit</title><link rel="stylesheet" href="/register/v1/styles.css"></head>
<body><main>` + browserRegistrationBrand + `<section class="card"><p class="eyebrow">Connect a device</p><h1>Sign in to continue</h1>
{{if .AutoStart}}<p id="registration-signin" data-path="{{.Path}}" role="status" aria-live="polite">Taking you to sign-in…</p>
<p class="muted">If nothing happens, <a href="/">sign in to Mesh Console</a>, then reopen the link from Mesh Client.</p><script src="/register/v1/client.js" defer></script>
{{else}}<p class="muted">Sign in to Mesh Console in this browser, then reload this page.</p><p><a class="button" href="/">Sign in to Mesh Console</a></p><p><a href="{{.Path}}">Reload this request</a></p>{{end}}
</section></main></body></html>`

const browserRegistrationChoicesHTML = browserRegistrationHead + `<title>Connect device | MeshTransit</title><link rel="stylesheet" href="/register/v1/styles.css"></head>
<body><main>` + browserRegistrationBrand + `<section class="card"><p class="eyebrow">Connect a device</p><h1>Choose where to connect</h1>
<p class="device"><span class="device__label">Device</span><strong>{{.Hostname}}</strong></p>
{{if .Workspaces}}{{if .CSRF}}<form id="registration-form" method="post" action="{{.Action}}" aria-busy="false">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{range .Workspaces}}<fieldset class="workspace"><legend><span class="avatar" aria-hidden="true">{{.Initial}}</span><span>{{.Name}}</span></legend>
{{if .Networks}}{{$workspace := .ID}}{{range .Networks}}<label class="choice"><input type="radio" name="network" value="{{.ID}}" data-workspace="{{$workspace}}" required><span class="choice__dot" aria-hidden="true"></span><span>{{.Name}}</span></label>{{end}}
{{if .MoreNetworks}}<p class="muted">More Networks exist; manage them in Mesh Console.</p>{{end}}{{else}}<p class="muted empty">No Network you can join in this Workspace.</p>{{end}}</fieldset>{{end}}
<button id="registration-confirm" class="button" type="submit">Connect device</button><p id="registration-status" role="status" aria-live="polite"></p></form>
{{else}}{{range .Workspaces}}<section class="workspace"><h2><span class="avatar" aria-hidden="true">{{.Initial}}</span><span>{{.Name}}</span></h2>
{{if .Networks}}<ul>{{range .Networks}}<li class="choice">{{.Name}}</li>{{end}}</ul>{{else}}<p class="muted empty">No Network you can join in this Workspace.</p>{{end}}</section>{{end}}{{end}}
{{if .MoreWorkspaces}}<p class="muted">Only your first Workspaces are shown.</p>{{end}}
{{else}}<p class="muted">No Workspace is available with this sign-in. Ask an owner to invite you, or sign in with another account.</p>{{end}}
{{if .SwitchAccount}}<p class="switch muted">Not the right account? <button id="registration-switch" class="link" type="button">Use another account</button></p><p id="registration-switch-status" class="muted" role="status" aria-live="polite"></p><script src="/register/v1/client.js" defer></script>{{end}}
</section></main></body></html>`

//go:embed browser_registration_page.js
var browserRegistrationScript string

const browserRegistrationApprovedHTML = browserRegistrationHead + `<title>Device approved | MeshTransit</title><link rel="stylesheet" href="/register/v1/styles.css"></head>
<body><main>` + browserRegistrationBrand + `<section class="card"><span class="done" aria-hidden="true">✓</span><p class="eyebrow">Connect a device</p><h1>Device approved</h1><p class="muted">Return to Mesh Client. It will finish connecting to the selected Network.</p></section></main></body></html>`

// The tokens mirror Mesh Console's dark theme so the hand-off feels like one product.
const browserRegistrationCSS = `:root{color-scheme:dark;--bg:#09090b;--surface:#141417;--raised:#1c1c21;--line:#27272a;--ink:#f4f4f5;--muted:#a1a1aa;--accent:#e5484d;--accent-ink:#fff;--focus:#f87171}` +
	`*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:2rem 1rem;background:radial-gradient(60rem 30rem at 50% -10%,rgba(229,72,77,.12),transparent),var(--bg);color:var(--ink);font:1rem/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}` +
	`main{max-width:32rem;margin:6vh auto}.brand{display:flex;align-items:center;gap:.6rem;margin-bottom:1.25rem;font-weight:700;font-size:1.05rem}.brand__mark{display:grid;place-items:center;width:1.9rem;height:1.9rem;border-radius:.55rem;background:rgba(229,72,77,.15);border:1px solid rgba(229,72,77,.35);color:var(--accent);font-weight:800}` +
	`.card{padding:1.75rem;border:1px solid var(--line);border-radius:1rem;background:var(--surface)}.eyebrow{margin:0 0 .35rem;color:var(--accent);font-size:.75rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase}h1{margin:0 0 1rem;font-size:1.5rem;line-height:1.25}p{margin:.5rem 0}.muted{color:var(--muted);font-size:.925rem}` +
	`.device{display:flex;flex-wrap:wrap;gap:.5rem;align-items:baseline;padding:.75rem 1rem;border-radius:.65rem;background:var(--raised);margin:0 0 1.25rem}.device__label{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.08em}` +
	`.workspace{border:0;padding:0;margin:0 0 1.25rem}.workspace legend,.workspace h2{display:flex;align-items:center;gap:.6rem;margin:0 0 .6rem;padding:0;font-size:.95rem;font-weight:700}.avatar{display:grid;place-items:center;width:1.6rem;height:1.6rem;border-radius:.45rem;background:var(--accent);color:var(--accent-ink);font-size:.8rem;font-weight:800}` +
	`ul{list-style:none;padding:0;margin:0}.choice{display:flex;align-items:center;gap:.75rem;min-height:48px;padding:.7rem 1rem;margin:.45rem 0;border:1px solid var(--line);border-radius:.7rem;background:var(--raised);font-weight:600;cursor:pointer;transition:border-color .15s,background .15s}` +
	`.choice:hover{border-color:#3f3f46}.choice input{position:absolute;opacity:0;width:1px;height:1px}.choice__dot{flex:none;width:1.1rem;height:1.1rem;border:2px solid #52525b;border-radius:50%}.choice:has(input:checked){border-color:var(--accent);background:rgba(229,72,77,.08)}.choice:has(input:checked) .choice__dot{border-color:var(--accent);box-shadow:inset 0 0 0 3px var(--raised);background:var(--accent)}.choice:has(input:focus-visible){outline:3px solid var(--focus);outline-offset:2px}` +
	`.empty{padding:.25rem 0 0 2.2rem}.button{display:inline-flex;align-items:center;justify-content:center;width:100%;min-height:46px;margin-top:.5rem;border:0;border-radius:.6rem;padding:.7rem 1rem;background:var(--accent);color:var(--accent-ink);font:inherit;font-weight:700;text-decoration:none;cursor:pointer}.button:disabled{opacity:.6;cursor:default}` +
	`a{color:#fca5a5}a:focus-visible,.button:focus-visible{outline:3px solid var(--focus);outline-offset:3px}#registration-status{min-height:1.5rem;color:var(--muted)}.switch{margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line)}.link{border:0;padding:0;background:none;color:#fca5a5;font:inherit;font-weight:600;text-decoration:underline;cursor:pointer}.link:disabled{opacity:.6;cursor:default}.link:focus-visible{outline:3px solid var(--focus);outline-offset:3px}.done{display:grid;place-items:center;width:2.5rem;height:2.5rem;margin-bottom:1rem;border-radius:50%;background:rgba(48,164,108,.15);color:#4cc38a;font-weight:800}`

var _ http.Handler = (*BrowserRegistrationPage)(nil)
