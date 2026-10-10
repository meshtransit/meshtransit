package cloudaddr

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func dmi(fields map[string]string) func(string) string {
	return func(name string) string { return fields[name] }
}

func TestDetectPlatform(t *testing.T) {
	t.Parallel()
	for want, fields := range map[Platform]map[string]string{
		PlatformAWS:          {"sys_vendor": "Amazon EC2\n", "product_name": "t4g.small"},
		PlatformGCP:          {"sys_vendor": "Google", "product_name": "Google Compute Engine"},
		PlatformAzure:        {"sys_vendor": "Microsoft Corporation", "product_name": "Virtual Machine", "chassis_asset_tag": azureAssetTag},
		PlatformDigitalOcean: {"sys_vendor": "DigitalOcean", "product_name": "Droplet"},
		PlatformNone:         {"sys_vendor": "Microsoft Corporation", "product_name": "Virtual Machine"}, // Hyper-V, not Azure
	} {
		if got := DetectPlatform(dmi(fields)); got != want {
			t.Errorf("%v: got %q, want %q", fields, got, want)
		}
	}
	if got := DetectPlatform(dmi(map[string]string{"bios_version": "4.11.amazon"})); got != PlatformAWS {
		t.Errorf("xen-based EC2: %q", got)
	}
	if got := DetectPlatform(dmi(nil)); got != PlatformNone {
		t.Errorf("bare metal: %q", got)
	}
}

// metadataServer plays a provider's metadata service.
type metadataServer struct {
	t        *testing.T
	mu       sync.Mutex
	requests []string
	handler  func(w http.ResponseWriter, r *http.Request)
}

func (m *metadataServer) start() (*httptest.Server, *Client) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.requests = append(m.requests, r.Method+" "+r.URL.RequestURI())
		m.mu.Unlock()
		m.handler(w, r)
	}))
	client := NewClient()
	client.base = server.URL

	return server, client
}

func TestAWSUsesIMDSv2(t *testing.T) {
	t.Parallel()
	m := &metadataServer{t: t}
	m.handler = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, "session-token")
		case r.Header.Get("X-aws-ec2-metadata-token") != "session-token":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/latest/meta-data/public-ipv4":
			_, _ = io.WriteString(w, "18.142.253.199")
		case r.URL.Path == "/latest/meta-data/ipv6":
			_, _ = io.WriteString(w, "2406:da18:abcd::10\nfd00::1")
		default:
			http.NotFound(w, r)
		}
	}
	server, client := m.start()
	defer server.Close()
	addresses, err := client.PublicAddresses(context.Background(), PlatformAWS)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("18.142.253.199"), netip.MustParseAddr("2406:da18:abcd::10")}
	if !slices.Equal(addresses, want) {
		t.Fatalf("addresses %v", addresses)
	}

	// An instance without a public address answers 404: no addresses, no error.
	m.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			_, _ = io.WriteString(w, "session-token")
			return
		}
		http.NotFound(w, r)
	}
	if addresses, err := client.PublicAddresses(context.Background(), PlatformAWS); err != nil || len(addresses) != 0 {
		t.Fatalf("private instance: %v %v", addresses, err)
	}
}

func TestGCPAzureAndDigitalOcean(t *testing.T) {
	t.Parallel()
	m := &metadataServer{t: t}
	m.handler = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/computeMetadata/"):
			if r.Header.Get("Metadata-Flavor") != "Google" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Metadata-Flavor", "Google")
			_, _ = io.WriteString(w, `[{"accessConfigs":[{"externalIp":"34.87.1.2"}],"ipv6AccessConfigs":[{"externalIpv6":"2600:1900:4000::1"}]},
				{"accessConfigs":[{"externalIp":""}]}]`)
		case strings.HasPrefix(r.URL.Path, "/metadata/instance/"):
			if r.Header.Get("Metadata") != "true" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.0.4","publicIpAddress":"20.1.2.3"}]},
				"ipv6":{"ipAddress":[{"privateIpAddress":"2603:1030::5"}]}}]}`)
		case r.URL.Path == "/metadata/v1/interfaces/public/0/ipv4/address":
			_, _ = io.WriteString(w, "167.99.68.41")
		default:
			http.NotFound(w, r)
		}
	}
	server, client := m.start()
	defer server.Close()
	for platform, want := range map[Platform][]string{
		PlatformGCP:          {"34.87.1.2", "2600:1900:4000::1"},
		PlatformAzure:        {"20.1.2.3", "2603:1030::5"},
		PlatformDigitalOcean: {"167.99.68.41"},
	} {
		addresses, err := client.PublicAddresses(context.Background(), platform)
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		var got []string
		for _, addr := range addresses {
			got = append(got, addr.String())
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v", platform, got)
		}
	}
}

func TestMetadataResponsesAreChecked(t *testing.T) {
	t.Parallel()
	m := &metadataServer{t: t}
	m.handler = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/computeMetadata/"):
			_, _ = io.WriteString(w, `[]`) // no Metadata-Flavor: not the GCP service
		case r.URL.Path == "/metadata/v1/interfaces/public/0/ipv4/address":
			http.Redirect(w, r, "http://192.0.2.9/", http.StatusFound)
		default:
			_, _ = io.WriteString(w, strings.Repeat("x", maxResponseSize+1))
		}
	}
	server, client := m.start()
	defer server.Close()
	for _, platform := range []Platform{PlatformGCP, PlatformDigitalOcean, PlatformAzure} {
		if _, err := client.PublicAddresses(context.Background(), platform); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: %v", platform, err)
		}
	}
	if _, err := client.PublicAddresses(context.Background(), PlatformNone); !errors.Is(err, ErrNoPlatform) {
		t.Errorf("no platform: %v", err)
	}
}

func TestPublicOnly(t *testing.T) {
	t.Parallel()
	got := publicOnly([]string{
		"18.142.253.199", "10.0.0.4", "100.64.1.1", "169.254.169.254", "127.0.0.1", "fe80::1",
		"fd00::1", "::ffff:18.142.253.199", "not-an-ip", "", "2406:da18::1",
	})
	want := []netip.Addr{netip.MustParseAddr("18.142.253.199"), netip.MustParseAddr("2406:da18::1")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestWatcher(t *testing.T) {
	t.Parallel()
	var (
		mu      sync.Mutex
		address = "18.142.253.199"
		fail    = true
	)
	m := &metadataServer{t: t}
	m.handler = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/metadata/v1/interfaces/public/0/ipv4/address" {
			_, _ = io.WriteString(w, address)
			return
		}
		http.NotFound(w, r)
	}
	server, client := m.start()
	defer server.Close()
	watcher := NewWatcher(WatcherOptions{ReadDMI: dmi(map[string]string{"sys_vendor": "DigitalOcean"}), Client: client})
	watcher.schedule = watchSchedule{refresh: time.Hour, minInterval: 10 * time.Millisecond, retry: 10 * time.Millisecond, maxRetry: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	waitFor := func(what string, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !condition() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s: %+v", what, watcher.Status())
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	waitFor("failed", func() bool { return watcher.Status().State == StateFailed })
	mu.Lock()
	fail = false
	mu.Unlock()
	waitFor("ready after retry", func() bool { return watcher.Status().State == StateReady })
	if got := watcher.Addresses(); len(got) != 1 || got[0].String() != "18.142.253.199" {
		t.Fatalf("addresses %v", got)
	}
	<-watcher.Changes()

	mu.Lock()
	address = "167.99.68.41"
	mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	watcher.NetworkChanged()
	waitFor("the new address after a network change", func() bool {
		got := watcher.Addresses()
		return len(got) == 1 && got[0].String() == "167.99.68.41"
	})

	none := NewWatcher(WatcherOptions{ReadDMI: dmi(nil)})
	if none.Status().State != StateNone || none.Platform() != PlatformNone {
		t.Fatalf("bare metal watcher %+v", none.Status())
	}
}
