package legacyts2021

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeFullMapRequest(t *testing.T) {
	t.Parallel()

	request, err := DecodeFullMapRequest(strings.NewReader(mapRequestBody))
	if err != nil {
		t.Fatalf("DecodeFullMapRequest() error = %v", err)
	}
	if !request.IsValid() || request.CapabilityVersion() != 142 ||
		request.NodeKey() != mapSnapshotFixture(t).NodeKey() {
		t.Fatalf("DecodeFullMapRequest() = %+v, want validated request", request)
	}
}

func TestDecodeMapRequestPreservesStreamingMode(t *testing.T) {
	t.Parallel()

	body := strings.Replace(mapRequestBody, `"Stream":false`, `"Stream":true`, 1)
	request, streaming, err := DecodeMapRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeMapRequest() error = %v", err)
	}
	if !request.IsValid() || !streaming {
		t.Fatalf("DecodeMapRequest() = (%+v, %t), want valid streaming request", request, streaming)
	}
}

func TestDecodeFullMapRequestRejectsUnsupportedOrAmbiguousInput(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		body string
	}{
		{name: "empty", body: ""},
		{name: "wrong capability", body: strings.Replace(mapRequestBody, `"Version":142`, `"Version":141`, 1)},
		{name: "unsupported compression", body: strings.Replace(mapRequestBody, `"Compress":"zstd"`, `"Compress":"gzip"`, 1)},
		{name: "streaming", body: strings.Replace(mapRequestBody, `"Stream":false`, `"Stream":true`, 1)},
		{name: "omit peers", body: strings.Replace(mapRequestBody, `"OmitPeers":false`, `"OmitPeers":true`, 1)},
		{name: "session handle", body: strings.Replace(mapRequestBody, `"Stream":false`, `"Stream":false,"MapSessionHandle":"opaque"`, 1)},
		{name: "unknown field", body: strings.Replace(mapRequestBody, `"Version":142`, `"Unknown":true,"Version":142`, 1)},
		{name: "duplicate field", body: strings.Replace(mapRequestBody, `"Version":142`, `"Version":142,"version":142`, 1)},
		{name: "trailing document", body: mapRequestBody + `{}`},
		{name: "oversized", body: `{"padding":"` + strings.Repeat("x", maxMapRequestBytes) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeFullMapRequest(strings.NewReader(test.body)); !errors.Is(err, ErrInvalidMapRequest) {
				t.Fatalf("DecodeFullMapRequest() error = %v, want ErrInvalidMapRequest", err)
			}
		})
	}
}
