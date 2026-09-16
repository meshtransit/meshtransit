package httpapi

import (
	"net/http"
	"strings"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

const maximumBrowserManagementResponseBytes = 32768

// This finite private candidate has no underlying transport and cannot release
// status/body while authority processing is still in progress.
type browserManagementResponse struct {
	header               http.Header
	status, statusWrites int
	body                 []byte
	err                  error
}

func (response *browserManagementResponse) Header() http.Header { return response.header }
func (response *browserManagementResponse) WriteHeader(status int) {
	response.statusWrites++
	if response.statusWrites != 1 || status < 200 || status > 599 {
		response.err = ErrBrowserManagementUnavailable
		return
	}
	response.status = status
}
func (response *browserManagementResponse) Write(body []byte) (int, error) {
	invalidStatus := response.err != nil || response.statusWrites != 1
	if invalidStatus || len(body) > maximumBrowserManagementResponseBytes-len(response.body) {
		response.err = ErrBrowserManagementUnavailable
		return 0, response.err
	}
	response.body = append(response.body, body...)
	return len(body), nil
}

func pristineBrowserManagementResponse(header http.Header) bool {
	if !pristineLandingResponse(header) {
		return false
	}
	for name := range header {
		if strings.HasPrefix(name, "Access-Control-") {
			return false
		}
	}
	return true
}

func readBrowserSessionCookie(headers http.Header) (accountsession.Token, error) {
	fields := headers.Values("Cookie")
	if len(fields) == 0 || len(fields) > 8 {
		return accountsession.Token{}, ErrInvalidBrowserManagement
	}
	var used, pairs, matches int
	var value string
	for _, field := range fields {
		if len(field) == 0 || len(field) > 8192-used {
			return accountsession.Token{}, ErrInvalidBrowserManagement
		}
		used += len(field)
		for _, character := range field {
			if character > 0x7e || character < 0x20 && character != '\t' {
				return accountsession.Token{}, ErrInvalidBrowserManagement
			}
		}
		for pair := range strings.SplitSeq(field, ";") {
			pairs++
			if pairs > 64 {
				return accountsession.Token{}, ErrInvalidBrowserManagement
			}
			name, candidate, hasValue := strings.Cut(strings.Trim(pair, " \t"), "=")
			if !hasValue || name == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, "%\"\\, \t") {
				return accountsession.Token{}, ErrInvalidBrowserManagement
			}
			if strings.EqualFold(name, AccountSessionCookieName) {
				matches++
				if name != AccountSessionCookieName || matches != 1 {
					return accountsession.Token{}, ErrInvalidBrowserManagement
				}
				value = candidate
			}
		}
	}
	if matches != 1 || value == "" {
		return accountsession.Token{}, ErrInvalidBrowserManagement
	}
	token, err := accountsession.ParseToken(value)
	if err != nil {
		return accountsession.Token{}, ErrInvalidBrowserManagement
	}
	return token, nil
}
