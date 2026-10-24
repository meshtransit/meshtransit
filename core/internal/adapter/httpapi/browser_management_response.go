package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
)

// The largest catalog page is 100 bounded approval projections. At the maximum
// 128 concurrent private requests this caps buffered response ownership at 32 MiB.
const maximumBrowserManagementResponseBytes = 256 << 10

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

func expiredAccountSessionCookie() (*http.Cookie, error) {
	cookie := &http.Cookie{
		Name: AccountSessionCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
	}
	if err := cookie.Valid(); err != nil || len(cookie.String()) >= 4096 {
		return nil, ErrInvalidBrowserManagement
	}
	return cookie, nil
}

func validBrowserLogoutResponse(header http.Header) bool {
	if header == nil || len(header.Values("Set-Cookie")) != 1 {
		return false
	}
	cookie, err := expiredAccountSessionCookie()
	if err != nil || header.Values("Set-Cookie")[0] != cookie.String() {
		return false
	}
	withoutCookie := header.Clone()
	withoutCookie.Del("Set-Cookie")
	return pristineBrowserManagementResponse(withoutCookie)
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

// answerRefusedBrowserManagement answers a request browser management refused
// before admission (ErrBrowserManagementRefused) with a plain 400 naming no
// reason, so a client sees a malformed request instead of a dropped
// connection. It writes nothing and reports false unless the response is
// still pristine; the caller then aborts as for any other failure.
func answerRefusedBrowserManagement(response http.ResponseWriter) (string, bool) {
	if response == nil || response.Header() == nil || len(response.Header()) != 0 {
		return "", false
	}
	correlationID, err := publicid.New()
	if err != nil {
		return "", false
	}
	apiError := invalidManagementRequest()
	body, err := json.Marshal(managementErrorResponse{Error: managementErrorBody{
		Code: apiError.Code, Message: apiError.Message, CorrelationID: correlationID.String(),
	}})
	if err != nil {
		return "", false
	}
	body = append(body, '\n')
	header := response.Header()
	setManagementSecurityHeaders(header, correlationID)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", strconv.Itoa(len(body)))
	// The request body was never read; the connection is not reused for it.
	header.Set("Connection", "close")
	response.WriteHeader(http.StatusBadRequest)
	written, err := response.Write(body)
	return correlationID.String(), err == nil && written == len(body)
}
