package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/shared/flowlog"
)

func decodePushRequest(t *testing.T, body string) storageCredentialRequest {
	t.Helper()
	var request storageCredentialRequest
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return request
}

// A push credential's body: the secret and destination come together, the
// URL is canonicalised, the region comes from the ARN, a Datadog key is
// lower-cased.
func TestStorageCredentialRequestPush(t *testing.T) {
	t.Parallel()
	kinesis := decodePushRequest(t, `{"name":"Stream","provider":"kinesis","network_ids":[],
"secret":{"kind":"aws_keys","id":"AKIAIOSFODNN7EXAMPLE","key":"x"},
"destination":{"stream_arn":"arn:aws:kinesis:eu-west-1:123456789012:stream/flow-logs"}}`)
	put, ok := kinesis.put(true)
	if !ok || put.PushSecret == nil || put.Destination.Region != "eu-west-1" || put.Check() != nil {
		t.Fatalf("kinesis: %+v %t", put, ok)
	}
	datadog := decodePushRequest(t, `{"name":"DD","provider":"datadog","network_ids":[],
"secret":{"kind":"datadog_key","key":"`+strings.Repeat("AB", 16)+`"},"destination":{"site":"datadoghq.eu"}}`)
	put, ok = datadog.put(true)
	if !ok || put.PushSecret.Key != strings.Repeat("ab", 16) || put.Check() != nil {
		t.Fatalf("datadog: %+v %t", put, ok)
	}
	elastic := decodePushRequest(t, `{"name":"ES","provider":"elasticsearch","network_ids":[],
"secret":{"kind":"basic","id":"writer","key":"p"},"destination":{"url":"HTTPS://ES.example.com/","flavor":"opensearch"}}`)
	put, ok = elastic.put(true)
	if !ok || put.Destination.URL != "https://es.example.com:443" || put.Check() != nil {
		t.Fatalf("elasticsearch: %+v %t", put, ok)
	}
	for name, body := range map[string]string{ //nolint:gosec // test bodies, no real secret
		"a secret without destination": `{"name":"x","provider":"datadog","network_ids":[],
"secret":{"kind":"datadog_key","key":"` + strings.Repeat("ab", 16) + `"}}`,
		"a destination without secret": `{"name":"x","provider":"datadog","network_ids":[],"destination":{"site":"datadoghq.eu"}}`,
		"an S3 key and a secret": `{"name":"x","provider":"datadog","network_ids":[],"access_key_id":"a","secret_access_key":"b",
"secret":{"kind":"datadog_key","key":"` + strings.Repeat("ab", 16) + `"},"destination":{"site":"datadoghq.eu"}}`,
		"an unknown kind": `{"name":"x","provider":"datadog","network_ids":[],"secret":{"kind":"token","key":"k"},
"destination":{"site":"datadoghq.eu"}}`,
		"a bad URL": `{"name":"x","provider":"elasticsearch","network_ids":[],"secret":{"kind":"basic","id":"a","key":"b"},
"destination":{"url":"http://es.example.com","flavor":"elasticsearch"}}`,
		"a bad ARN": `{"name":"x","provider":"kinesis","network_ids":[],"secret":{"kind":"aws_keys","id":"AKIAIOSFODNN7EXAMPLE","key":"x"},
"destination":{"stream_arn":"arn:aws:kinesis:eu-west-1:1:stream/x"}}`,
	} {
		if _, ok := decodePushRequest(t, body).put(true); ok {
			t.Errorf("%s accepted", name)
		}
	}
	var unknown storageCredentialRequest
	decoder := json.NewDecoder(strings.NewReader(`{"destination":{"region":"eu-west-1"}}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&unknown) == nil {
		t.Fatal("a region given for a destination")
	}
}

// The response shows a push destination without its CA, and settings
// round-trip the push fields; an empty one is refused, no tags are none.
func TestConnectionLogPushBodies(t *testing.T) {
	t.Parallel()
	body := newStorageCredentialBody(connectionlog.Credential{
		Provider: flowlog.ProviderElasticsearch,
		Destination: connectionlog.Destination{URL: "https://es.example.com:443", Flavor: flowlog.FlavorElasticsearch,
			CAPEM: []byte("secret-ish"), CASHA256: strings.Repeat("a", 64)},
	})
	encoded, err := json.Marshal(body)
	if err != nil || strings.Contains(string(encoded), "ca_pem") || strings.Contains(string(encoded), "secret-ish") ||
		!strings.Contains(string(encoded), `"ca_sha256"`) {
		t.Fatalf("credential body: %s %v", encoded, err)
	}
	empty, tags := "", []string{}
	enabled, bucket, region, prefix, forwarded, window := true, "", "", "", false, 60
	request := connectionLogSettingsRequest{
		Enabled: &enabled, Bucket: &bucket, Region: &region, Prefix: &prefix, Forwarded: &forwarded,
		WindowSeconds: &window, Tags: tags,
	}
	settings, ok := request.settings()
	if !ok || settings.Tags != nil {
		t.Fatalf("no tags: %+v %t", settings, ok)
	}
	request.Target = &empty
	if _, ok := request.settings(); ok {
		t.Fatal("an empty target accepted")
	}
}
