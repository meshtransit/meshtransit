package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
)

// loginFailureStyle is the only inline content of the refusal page; the CSP
// admits it by hash and runs no script.
const loginFailureStyle = `:root{color-scheme:dark}*{box-sizing:border-box}` +
	`body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1rem;` +
	`background:radial-gradient(60rem 30rem at 50% -10%,rgba(227,27,35,.14),transparent),#0b0d10;color:#fffdfc;` +
	`font:1rem/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}` +
	`main{width:100%;max-width:26rem;padding:2rem 1.75rem;border:1px solid #343941;border-radius:1rem;` +
	`background:#15181e;text-align:center}` +
	`h1{margin:0 0 .5rem;font-size:1.25rem;line-height:1.3}p{margin:0;color:#a9afb8}` +
	`a{display:inline-block;margin-top:1.25rem;padding:.625rem 1.125rem;border-radius:.5rem;background:#e31b23;` +
	`color:#fff;font-weight:600;text-decoration:none}a:focus-visible{outline:3px solid #ff6b70;outline-offset:3px}`

var (
	loginFailureTemplate = template.Must(template.New("login-failure").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}} | MeshTransit</title>
<style>` + loginFailureStyle + `</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<a href="/">Back to sign in</a>
</main>
</body>
</html>
`))
	loginFailureStyleHash = func() string {
		digest := sha256.Sum256([]byte(loginFailureStyle))
		return "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	}()
)

type loginFailureCopy struct {
	Status  int
	Title   string
	Message string
}

// loginFailureFor maps a closed handler error to plain words; it never echoes
// the request or the error text.
func loginFailureFor(err error) loginFailureCopy {
	switch {
	case errors.Is(err, ErrInvalidBrowserLogin), errors.Is(err, ErrInvalidLoginLanding):
		return loginFailureCopy{Status: http.StatusBadRequest, Title: "This sign-in link has expired",
			Message: "Sign-in links work once and only for a few minutes. Start again from the sign-in page."}
	case errors.Is(err, ErrBrowserCaptureLimited):
		return loginFailureCopy{Status: http.StatusTooManyRequests, Title: "Too many sign-in attempts",
			Message: "Wait a minute, then start sign-in again."}
	case errors.Is(err, ErrBrowserCaptureSaturated), errors.Is(err, ErrLoginLandingSaturated):
		return loginFailureCopy{Status: http.StatusServiceUnavailable, Title: "Sign-in is busy",
			Message: "Many people are signing in right now. Try again in a moment."}
	default:
		return loginFailureCopy{Status: http.StatusServiceUnavailable, Title: "Sign-in is temporarily unavailable",
			Message: "Try again in a moment. If it keeps happening, contact your administrator."}
	}
}

// loginNavigationWriter records whether a handler released anything. Unwrap
// keeps http.ResponseController deadlines reaching the owned transport.
type loginNavigationWriter struct {
	http.ResponseWriter
	wrote bool
}

func (writer *loginNavigationWriter) WriteHeader(status int) {
	writer.wrote = true
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *loginNavigationWriter) Write(body []byte) (int, error) {
	writer.wrote = true
	return writer.ResponseWriter.Write(body)
}

func (writer *loginNavigationWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

// serveLoginNavigation runs a browser navigation handler (the provider
// callback or the continuation landing). When it fails before releasing
// anything, the person gets a static page instead of a dropped connection;
// every staged header, including cookies, is discarded first, so nothing the
// handler prepared is delivered. Output already released still returns the
// error, and the caller aborts the transport as before.
func serveLoginNavigation(response http.ResponseWriter, request *http.Request,
	serve func(http.ResponseWriter, *http.Request) error) (refused bool, err error) {
	tracked := &loginNavigationWriter{ResponseWriter: response}
	err = serve(tracked, request)
	if err == nil || tracked.wrote {
		return false, err
	}
	page := loginFailureFor(err)
	var body bytes.Buffer
	if renderErr := loginFailureTemplate.Execute(&body, page); renderErr != nil {
		return false, errors.Join(err, renderErr)
	}
	header := response.Header()
	clear(header)
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src "+loginFailureStyleHash+
		"; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Strict-Transport-Security", "max-age=31536000")
	response.WriteHeader(page.Status)
	if request.Method == http.MethodHead {
		return true, nil
	}
	if written, writeErr := response.Write(body.Bytes()); writeErr != nil || written != body.Len() {
		return true, errors.Join(ErrLoginDispatchUnavailable, writeErr)
	}
	return true, nil
}
