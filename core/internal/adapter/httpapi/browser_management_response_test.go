package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestBrowserSessionCookieIsBoundedAndUnambiguous(t *testing.T) {
	t.Parallel()
	valid := AccountSessionCookieName + "=" + managementTokenFixture
	for _, invalid := range []string{
		"", "other=x", valid + "; " + valid,
		strings.ToLower(AccountSessionCookieName) + "=" + managementTokenFixture,
		AccountSessionCookieName + " =" + managementTokenFixture,
		AccountSessionCookieName + "=\"" + managementTokenFixture + "\"",
		AccountSessionCookieName + "= " + managementTokenFixture, "%5f_Host-mt_session=" + managementTokenFixture,
		valid + "\r\n", valid + "; bad", valid + strings.Repeat("; a=x", 64), valid + "; a=" + strings.Repeat("x", 8192)} {
		_, cookieErr := readBrowserSessionCookie(http.Header{"Cookie": {invalid}})
		if !errors.Is(cookieErr, ErrInvalidBrowserManagement) {
			t.Fatal("ambiguous cookie accepted", cookieErr)
		}
	}
	for _, fields := range [][]string{{valid, valid}, {valid, "a=x", "b=x", "c=x", "d=x", "e=x", "f=x", "g=x", "h=x"}} {
		if _, err := readBrowserSessionCookie(http.Header{"Cookie": fields}); err == nil {
			t.Fatal("duplicate/oversize cookie fields accepted")
		}
	}
	token, err := readBrowserSessionCookie(http.Header{"Cookie": {"other=x; " + valid}})
	if err != nil || token.Encoded() != managementTokenFixture {
		t.Fatal("exact bounded Session cookie rejected", err)
	}
}

func TestBrowserManagementResponseNeverReleasesPartialCandidate(t *testing.T) {
	t.Parallel()
	response := &browserManagementResponse{header: make(http.Header)}
	if _, err := response.Write([]byte("x")); err == nil {
		t.Fatal("body accepted before sole final status")
	}
	response = &browserManagementResponse{header: make(http.Header)}
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(make([]byte, maximumBrowserManagementResponseBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := response.Write([]byte("x")); err == nil || len(response.body) != maximumBrowserManagementResponseBytes {
		t.Fatal("candidate exceeded resident bound")
	}
	response.WriteHeader(http.StatusOK)
	if response.err == nil {
		t.Fatal("duplicate status accepted")
	}
}

func FuzzBrowserSessionCookie(f *testing.F) {
	f.Add(AccountSessionCookieName + "=" + managementTokenFixture)
	f.Add("")
	f.Add("other=x")
	f.Fuzz(func(t *testing.T, value string) {
		token, err := readBrowserSessionCookie(http.Header{"Cookie": {value}})
		invalidShape := !token.IsValid() || len(value) > 8192
		if err == nil && (invalidShape || !strings.Contains(value, AccountSessionCookieName+"="+token.Encoded())) {
			t.Fatal("unverified/unbounded cookie accepted")
		}
	})
}

func TestAnswerRefusedBrowserManagementOnlyWhenPristine(t *testing.T) {
	t.Parallel()
	staged := httptest.NewRecorder()
	staged.Header().Set("X-Staged", "1")
	if _, answered := answerRefusedBrowserManagement(staged); answered || staged.Body.Len() != 0 ||
		len(staged.Header()) != 1 {
		t.Fatal("refusal answered over a staged response")
	}
	pristine := httptest.NewRecorder()
	logged, answered := answerRefusedBrowserManagement(pristine)
	if !answered {
		t.Fatal("pristine refusal not answered")
	}
	correlation := pristine.Header().Get("X-Correlation-ID")
	if logged != correlation || pristine.Code != http.StatusBadRequest || correlation == "" ||
		pristine.Header().Get("Connection") != "close" || pristine.Header().Get("Cache-Control") != "no-store" ||
		pristine.Header().Get("Content-Length") != strconv.Itoa(pristine.Body.Len()) ||
		pristine.Body.String() != `{"error":{"code":"invalid_request","message":"the request is invalid",`+
			`"correlation_id":"`+correlation+`","retryable":false}}`+"\n" {
		t.Fatal("refusal answer changed", pristine.Code, pristine.Header(), pristine.Body.String())
	}
}
