package cloudaddr

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

// metadataEcho answers every metadata request with the same body and the
// headers each platform's client checks.
type metadataEcho []byte

func (body metadataEcho) RoundTrip(*http.Request) (*http.Response, error) {
	header := http.Header{}
	header.Set("Metadata-Flavor", "Google")
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK, Header: header,
		Body: io.NopCloser(bytes.NewReader(body)),
	}, nil
}

// FuzzPublicAddresses feeds every platform arbitrary metadata answers: only
// distinct public addresses come out, at most maxAddresses of them.
func FuzzPublicAddresses(f *testing.F) {
	f.Add([]byte("203.0.113.7"))
	f.Add([]byte(`{"network":{"interface":[{"ipv4":{"ipAddress":[{"publicIpAddress":"203.0.113.7"}]}}]}}`))
	f.Add([]byte(`[{"accessConfigs":[{"externalIp":"203.0.113.7"}],"ipv6AccessConfigs":[{"externalIpv6":"2001:db8::7"}]}]`))
	f.Add([]byte("2001:db8::1\n10.0.0.1\n203.0.113.7\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		client := newClient("http://metadata.test", &http.Client{Transport: metadataEcho(body)})
		for _, platform := range []Platform{PlatformAWS, PlatformGCP, PlatformAzure, PlatformDigitalOcean} {
			addresses, err := client.PublicAddresses(context.Background(), platform)
			if err != nil {
				continue
			}
			if len(addresses) > maxAddresses {
				t.Fatalf("%s: %d addresses", platform, len(addresses))
			}
			for i, address := range addresses {
				if !address.IsGlobalUnicast() || address.IsPrivate() || sharedAddressSpace.Contains(address) {
					t.Fatalf("%s: non-public address %s", platform, address)
				}
				for _, earlier := range addresses[:i] {
					if earlier == address {
						t.Fatalf("%s: duplicate address %s", platform, address)
					}
				}
			}
		}
	})
}
