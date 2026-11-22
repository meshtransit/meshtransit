//go:build dexbroker

package dexbroker

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// An upstream provider returns the browser to the broker's callback with
// the broker's state. When that sign-in expired or was already used, Dex
// answers 400 with "Requested resource does not exist", a page that tells
// the person nothing (TD-API-12). The broker replaces that page, only there,
// with one that sends them back to start again.

var expiredSignInPage = template.Must(template.New("expired").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in expired</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;color:#1d2125}
a{color:#0b6e4f}</style></head>
<body><h1>This sign-in has expired</h1>
<p>It took too long or was already used. Nothing was signed in.</p>
<p><a href="{{.}}">Start again</a></p></body></html>
`))

// expiredSignInWriter swaps Dex's 400 callback page for the expired page.
type expiredSignInWriter struct {
	http.ResponseWriter
	returnURL string
	replaced  bool
	wrote     bool
}

func (writer *expiredSignInWriter) WriteHeader(status int) {
	if writer.wrote {
		return
	}
	writer.wrote = true
	// Dex writes its error page without a Content-Type (net/http sniffs it
	// at the first Write); anything typed other than HTML is left alone.
	contentType := writer.Header().Get("Content-Type")
	if status != http.StatusBadRequest || contentType != "" && !strings.HasPrefix(contentType, "text/html") {
		writer.ResponseWriter.WriteHeader(status)
		return
	}
	writer.replaced = true
	header := writer.Header()
	header.Del("Content-Length")
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	writer.ResponseWriter.WriteHeader(status)
	_ = expiredSignInPage.Execute(writer.ResponseWriter, writer.returnURL)
}

func (writer *expiredSignInWriter) Write(contents []byte) (int, error) {
	if !writer.wrote {
		writer.WriteHeader(http.StatusOK)
	}
	if writer.replaced {
		return len(contents), nil
	}
	return writer.ResponseWriter.Write(contents)
}

// returnURLOf is the origin of the first client's redirect URI: where a
// person starts signing in again.
func returnURLOf(configuration componentConfiguration) string {
	for _, client := range configuration.clients {
		parsed, err := url.Parse(client.redirectURI)
		if err == nil && parsed.Scheme == "https" && parsed.Host != "" {
			return parsed.Scheme + "://" + parsed.Host + "/"
		}
	}
	return ""
}
