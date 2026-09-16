package oidc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestLoginCallbackCookieBoundsAndExactScope(t *testing.T) {
	t.Parallel()
	value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 100))
	for _, test := range []struct {
		name     string
		field    string
		accepted bool
	}{
		{name: "canonical", field: LoginCallbackCookieName + "=" + value, accepted: true},
		{name: "missing", field: "other=value"},
		{name: "duplicate", field: LoginCallbackCookieName + "=" + value + "; " + LoginCallbackCookieName + "=" + value},
		{name: "quoted", field: LoginCallbackCookieName + "=\"" + value + "\""},
		{name: "padded", field: LoginCallbackCookieName + "=" + value + "="},
		{name: "newline", field: LoginCallbackCookieName + "=" + value + "\n"},
		{name: "value limit", field: LoginCallbackCookieName + "=" + strings.Repeat("A", 3801)},
		{name: "pair limit", field: LoginCallbackCookieName + "=" + value + strings.Repeat("; a=b", 64)},
		{name: "header limit", field: LoginCallbackCookieName + "=" + value + "; a=" + strings.Repeat("b", 8192)},
	} {
		t.Run(test.name, func(t *testing.T) {
			headers := http.Header{"Cookie": []string{test.field}}
			got, err := ReadLoginCallbackCookie(headers)
			if test.accepted {
				if err != nil || got != value {
					t.Fatal("canonical capture cookie changed", err)
				}
				return
			}
			if !errors.Is(err, ErrLoginCallbackCookie) || got != "" {
				t.Fatal("unsafe cookie retained")
			}
		})
	}
	cookie := ExpiredLoginCallbackCookie()
	if cookie.Name != LoginCallbackCookieName || cookie.Path != "/" || cookie.Domain != "" ||
		!cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != -1 {
		t.Fatal("capture clear widened cookie scope")
	}
}

func FuzzLoginCallbackCookie(f *testing.F) {
	f.Add(LoginCallbackCookieName + "=AAAA")
	f.Add(LoginCallbackCookieName + "=\"quoted\"")
	f.Add("a=b")
	f.Fuzz(func(t *testing.T, field string) {
		got, err := ReadLoginCallbackCookie(http.Header{"Cookie": []string{field}})
		if err != nil && got != "" {
			t.Fatal("failed parser retained input")
		}
		if err == nil {
			decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(got)
			if decodeErr != nil || len(got) > 3800 || base64.RawURLEncoding.EncodeToString(decoded) != got {
				t.Fatal("cookie parser violated canonical bounds")
			}
		}
	})
}
