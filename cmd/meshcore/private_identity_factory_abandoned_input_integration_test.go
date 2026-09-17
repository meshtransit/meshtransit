//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodePrivateFactoryAbandonedInput(t *testing.T) {
	t.Parallel()
	input := privateFactoryAbandonedInput{
		ProviderOrigin: "https://127.0.0.1:12345",
		Cookies:        []string{"synthetic-cookie=private"}, CSRF: "synthetic-proof",
	}
	valid, err := json.Marshal(input)
	if err != nil {
		t.Fatal("encode private syntax fixture")
	}
	for _, test := range []struct {
		name    string
		data    string
		isValid bool
	}{
		{name: "valid canonical input", data: string(valid), isValid: true},
		{name: "empty", data: ""},
		{name: "oversized", data: strings.Repeat("x", privateFactoryAbandonedInputLimit+1)},
		{name: "trailing value", data: string(valid) + "{}"},
		{name: "unknown field", data: strings.Replace(string(valid), "}", `,"unknown":true}`, 1)},
		{name: "duplicate field", data: strings.Replace(string(valid), "}", `,"csrf":"replacement"}`, 1)},
		{name: "noncanonical whitespace", data: " " + string(valid)},
		{name: "remote origin", data: strings.Replace(string(valid), "127.0.0.1", "example.test", 1)},
		{name: "plain http", data: strings.Replace(string(valid), "https:", "http:", 1)},
		{name: "invalid port", data: strings.Replace(string(valid), "12345", "0", 1)},
		{name: "origin path", data: strings.Replace(string(valid), "12345", "12345/realm", 1)},
		{name: "origin query", data: strings.Replace(string(valid), "12345", "12345?secret=private", 1)},
		{name: "origin user info", data: strings.Replace(string(valid), "127.0.0.1", "private@127.0.0.1", 1)},
		{name: "missing proof", data: strings.Replace(string(valid), "synthetic-proof", "", 1)},
		{name: "missing cookies", data: strings.Replace(string(valid), `["synthetic-cookie=private"]`, "[]", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, decodeErr := decodePrivateFactoryAbandonedInput(strings.NewReader(test.data))
			if test.isValid {
				if decodeErr != nil || got.ProviderOrigin != input.ProviderOrigin ||
					got.CSRF != input.CSRF || len(got.Cookies) != 1 || got.Cookies[0] != input.Cookies[0] {
					t.Fatal("canonical private fixture input did not round-trip")
				}
				return
			}
			if decodeErr == nil || decodeErr.Error() != "invalid private fixture input" ||
				got.ProviderOrigin != "" || got.CSRF != "" || got.Cookies != nil {
				t.Fatal("invalid private fixture syntax released input or reflected diagnostics")
			}
		})
	}
}

func FuzzDecodePrivateFactoryAbandonedInput(f *testing.F) {
	f.Add([]byte(`{"provider_origin":"https://127.0.0.1:12345","cookies":["fixture=value"],"csrf":"proof"}`))
	f.Add([]byte(`{"csrf":"a","csrf":"b"}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		input, err := decodePrivateFactoryAbandonedInput(bytes.NewReader(data))
		if err != nil {
			if err.Error() != "invalid private fixture input" || input.ProviderOrigin != "" ||
				input.CSRF != "" || input.Cookies != nil {
				t.Fatal("invalid syntax disclosed partial private input")
			}
			return
		}
		canonical, marshalErr := json.Marshal(input)
		if marshalErr != nil || len(data) > privateFactoryAbandonedInputLimit || !bytes.Equal(data, canonical) {
			t.Fatal("accepted private input was not bounded and canonical")
		}
	})
}
