package portmap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var upnpTestGateway = Gateway{Addr: netip.MustParseAddr("127.0.0.1"), Local: netip.MustParseAddr("192.168.1.10")}

// igd is a UPnP Internet gateway device for tests.
type igd struct {
	t           *testing.T
	serviceType string
	description string // overrides the generated description when set
	conflicts   int    // AddPortMapping answers 718 this many times
	permanent   bool   // only permanent leases (725 for any other)
	reserved    uint16 // AddAnyPortMapping's port
	noAddAny    bool   // a v2 service without AddAnyPortMapping
	// foreign holds entries already on the gateway: external port →
	// "description|client:port".
	foreign map[string]string

	mu       sync.Mutex
	mappings map[string]string // external port → internal client:port
	leases   []string
	actions  []string
}

func (g *igd) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/rootDesc.xml", func(w http.ResponseWriter, _ *http.Request) {
		if g.description != "" {
			_, _ = io.WriteString(w, g.description)
			return
		}
		_, _ = fmt.Fprintf(w, `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
 <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
 <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3f</controlURL></service></serviceList>
 <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
  <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
   <serviceList><service><serviceType>%s</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList>
  </device></deviceList></device></deviceList>
</device></root>`, g.serviceType)
	})
	mux.HandleFunc("/ctl/IPConn", g.soap)

	return httptest.NewServer(mux)
}

func (g *igd) fault(w http.ResponseWriter, code int) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>test</errorDescription></UPnPError>
</detail></s:Fault></s:Body></s:Envelope>`, code)
}

func (g *igd) reply(w http.ResponseWriter, action string, fields ...string) {
	var body strings.Builder
	for i := 0; i+1 < len(fields); i += 2 {
		body.WriteString("<" + fields[i] + ">" + fields[i+1] + "</" + fields[i] + ">")
	}
	//nolint:gosec // G705: a test gateway echoing fixed test values.
	_, _ = fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>`+
		`<u:%sResponse xmlns:u="%s">%s</u:%sResponse></s:Body></s:Envelope>`, action, g.serviceType, body.String(), action)
}

func (g *igd) soap(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("SOAPAction")
	prefix := `"` + g.serviceType + "#"
	if !strings.HasPrefix(header, prefix) {
		g.t.Errorf("SOAPAction %q", header)
	}
	action := strings.TrimSuffix(strings.TrimPrefix(header, prefix), `"`)
	body, _ := io.ReadAll(r.Body)
	fields, err := soapLeaves(body)
	if err != nil {
		g.t.Errorf("request body: %v", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.actions = append(g.actions, action)
	if g.mappings == nil {
		g.mappings = map[string]string{}
	}
	switch action {
	case "GetExternalIPAddress":
		g.reply(w, action, "NewExternalIPAddress", testExternal.String())
	case "AddPortMapping", "AddAnyPortMapping":
		if fields["NewProtocol"] != "UDP" || fields["NewInternalClient"] != upnpTestGateway.Local.String() ||
			fields["NewPortMappingDescription"] != upnpDescription {
			g.t.Errorf("mapping request %v", fields)
		}
		if g.permanent && fields["NewLeaseDuration"] != "0" {
			g.fault(w, upnpErrorPermanentLeasesOK)
			return
		}
		g.leases = append(g.leases, fields["NewLeaseDuration"])
		port := fields["NewExternalPort"]
		if action == "AddAnyPortMapping" && g.noAddAny {
			g.fault(w, upnpErrorInvalidAction)
			return
		}
		if action == "AddAnyPortMapping" {
			port = strconv.Itoa(int(g.reserved))
		} else if g.conflicts > 0 {
			g.conflicts--
			g.fault(w, upnpErrorConflict)
			return
		}
		g.mappings[port] = fields["NewInternalClient"] + ":" + fields["NewInternalPort"]
		if action == "AddAnyPortMapping" {
			g.reply(w, action, "NewReservedPort", port)
		} else {
			g.reply(w, action)
		}
	case "GetSpecificPortMappingEntry":
		target, ok := g.mappings[fields["NewExternalPort"]]
		if !ok {
			g.fault(w, upnpErrorNoSuchEntry)
			return
		}
		client, port, _ := strings.Cut(target, ":")
		g.reply(w, action, "NewInternalPort", port, "NewInternalClient", client, "NewEnabled", "1")
	case "GetGenericPortMappingEntry":
		index, _ := strconv.Atoi(fields["NewPortMappingIndex"])
		ports := make([]string, 0, len(g.mappings)+len(g.foreign))
		for port := range g.mappings {
			ports = append(ports, port)
		}
		for port := range g.foreign {
			ports = append(ports, port)
		}
		slices.Sort(ports)
		if index >= len(ports) {
			g.fault(w, 713)
			return
		}
		port := ports[index]
		description, target := upnpDescription, g.mappings[port]
		if entry, ok := g.foreign[port]; ok {
			description, target, _ = strings.Cut(entry, "|")
		}
		client, internal, _ := strings.Cut(target, ":")
		g.reply(w, action, "NewRemoteHost", "", "NewExternalPort", port, "NewProtocol", "UDP",
			"NewInternalPort", internal, "NewInternalClient", client, "NewPortMappingDescription", description)
	case "DeletePortMapping":
		delete(g.mappings, fields["NewExternalPort"])
		delete(g.foreign, fields["NewExternalPort"])
		g.reply(w, action)
	default:
		g.fault(w, 401)
	}
}

// ssdpResponder answers M-SEARCH like the gateway at 127.0.0.1.
func ssdpResponder(location string, from netip.Addr) *fakeNet {
	return &fakeNet{handler: func(request []byte, to netip.AddrPort) []datagram {
		if !strings.HasPrefix(string(request), "M-SEARCH * HTTP/1.1") || to.Port() != ssdpPort {
			return nil
		}
		reply := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
			"LOCATION: " + location + "\r\n\r\n"
		return []datagram{{payload: []byte(reply), from: netip.AddrPortFrom(from, ssdpPort)}}
	}}
}

func newUPnPTestClient(network *fakeNet) upnpClient {
	return upnpClient{listen: network.listen, http: newUPnPHTTPClient(), clock: time.Now}
}

func TestUPnPMapsChecksAndRemovesV1(t *testing.T) {
	t.Parallel()
	device := &igd{t: t, serviceType: upnpWANIPv1, conflicts: 1}
	server := device.server()
	defer server.Close()
	c := newUPnPTestClient(ssdpResponder(server.URL+"/rootDesc.xml", upnpTestGateway.Addr))

	mapping, err := c.mapPort(context.Background(), upnpTestGateway, 41641, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.Protocol != ProtocolUPnP || mapping.External.Addr() != testExternal ||
		mapping.External.Port() == 41641 || mapping.Lifetime != DefaultLifetime {
		t.Fatalf("mapping %+v (the conflict should move the external port)", mapping)
	}
	if mapping.control.serviceType != upnpWANIPv1 || !strings.HasSuffix(mapping.control.url, "/ctl/IPConn") {
		t.Fatalf("control %+v", mapping.control)
	}
	if held, err := c.check(context.Background(), mapping); err != nil || !held {
		t.Fatalf("check: %v %v", held, err)
	}
	// A renewal reuses the control URL and the external port: no new search.
	renewed, err := c.mapPort(context.Background(), upnpTestGateway, 41641, &mapping)
	if err != nil || renewed.External != mapping.External {
		t.Fatalf("renewal %+v %v", renewed, err)
	}
	if err := c.unmap(context.Background(), mapping); err != nil {
		t.Fatal(err)
	}
	if held, err := c.check(context.Background(), mapping); err != nil || held {
		t.Fatalf("check after removal: %v %v", held, err)
	}
}

func TestUPnPV2AndPermanentLeases(t *testing.T) {
	t.Parallel()
	device := &igd{t: t, serviceType: upnpWANIPv2, reserved: 43210, permanent: true}
	server := device.server()
	defer server.Close()
	c := newUPnPTestClient(ssdpResponder(server.URL+"/rootDesc.xml", upnpTestGateway.Addr))
	mapping, err := c.mapPort(context.Background(), upnpTestGateway, 41641, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.External.Port() != 43210 || mapping.Lifetime != 0 {
		t.Fatalf("mapping %+v", mapping)
	}
	if len(device.leases) != 1 || device.leases[0] != "0" {
		t.Fatalf("leases %v", device.leases)
	}
}

func TestUPnPStaysOnTheGateway(t *testing.T) {
	t.Parallel()
	device := &igd{t: t, serviceType: upnpWANIPv1}
	server := device.server()
	defer server.Close()
	port := strings.TrimPrefix(server.URL, "http://127.0.0.1")

	for name, test := range map[string]struct {
		location    string
		from        netip.Addr
		description string
		want        error
	}{
		"location elsewhere":  {location: "http://127.0.0.2" + port + "/rootDesc.xml", want: ErrInvalidResponse},
		"location by name":    {location: "http://localhost" + port + "/rootDesc.xml", want: ErrInvalidResponse},
		"https location":      {location: "https://127.0.0.1" + port + "/rootDesc.xml", want: ErrInvalidResponse},
		"credentials":         {location: "http://user:pw@127.0.0.1" + port + "/rootDesc.xml", want: ErrInvalidResponse},
		"reply from stranger": {from: netip.MustParseAddr("192.168.1.66"), want: ErrUnsupported},
		"control elsewhere": {
			description: `<root><device><serviceList><service><serviceType>` + upnpWANIPv1 +
				`</serviceType><controlURL>http://192.0.2.9/ctl</controlURL></service></serviceList></device></root>`,
			want: ErrInvalidResponse,
		},
		"no wan service": {description: `<root><device><serviceList></serviceList></device></root>`, want: ErrUnsupported},
	} {
		location := test.location
		if location == "" {
			location = server.URL + "/rootDesc.xml"
		}
		from := test.from
		if !from.IsValid() {
			from = upnpTestGateway.Addr
		}
		device.description = test.description
		c := newUPnPTestClient(ssdpResponder(location, from))
		if _, err := c.discover(context.Background(), upnpTestGateway); !errors.Is(err, test.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUPnPRefusesRedirectsAndLargeBodies(t *testing.T) {
	t.Parallel()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = io.WriteString(w, strings.Repeat("x", upnpMaxDescription+1))
			return
		}
		http.Redirect(w, r, "http://192.0.2.9/rootDesc.xml", http.StatusFound)
	}))
	defer redirect.Close()
	c := newUPnPTestClient(&fakeNet{})
	if _, err := c.get(context.Background(), redirect.URL+"/rootDesc.xml"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("redirect: %v", err)
	}
	if _, err := c.get(context.Background(), redirect.URL+"/big"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("large body: %v", err)
	}
}

func FuzzParseUPnP(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:5000/rootDesc.xml\r\n\r\n"))
	f.Add([]byte(`<root><device><serviceList><service><serviceType>` + upnpWANIPv1 +
		`</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></root>`))
	location, _ := url.Parse("http://127.0.0.1:5000/rootDesc.xml")
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseSSDPLocation(b)
		if control, err := parseUPnPDescription(b, location, upnpTestGateway); err == nil {
			parsed, parseErr := url.Parse(control.url)
			if parseErr != nil || parsed.Hostname() != "127.0.0.1" || parsed.Scheme != "http" {
				t.Fatalf("control URL %q left the gateway", control.url)
			}
		}
		if fields, err := soapLeaves(b); err == nil {
			_ = xml.EscapeText(io.Discard, []byte(fields["errorCode"]))
		}
	})
}

func TestUPnPV2WithoutAddAnyFallsBackToAddPortMapping(t *testing.T) {
	t.Parallel()
	device := &igd{t: t, serviceType: upnpWANIPv2, noAddAny: true}
	server := device.server()
	defer server.Close()
	c := newUPnPTestClient(ssdpResponder(server.URL+"/rootDesc.xml", upnpTestGateway.Addr))
	mapping, err := c.mapPort(context.Background(), upnpTestGateway, 41641, nil)
	if err != nil || mapping.External.Port() != 41641 {
		t.Fatalf("mapping %+v %v", mapping, err)
	}
}

func TestUPnPRemovesStaleEntriesAndMovedPorts(t *testing.T) {
	t.Parallel()
	local := upnpTestGateway.Local.String()
	device := &igd{t: t, serviceType: upnpWANIPv1, foreign: map[string]string{
		"40000": upnpDescription + "|" + local + ":41641", // left by an earlier meshd
		"40001": "Game console|192.168.1.20:3074",         // another device's
		"40002": "Another app|" + local + ":5000",         // another app on this host
	}}
	server := device.server()
	defer server.Close()
	c := newUPnPTestClient(ssdpResponder(server.URL+"/rootDesc.xml", upnpTestGateway.Addr))
	mapping, err := c.mapPort(context.Background(), upnpTestGateway, 41641, nil)
	if err != nil {
		t.Fatal(err)
	}
	device.mu.Lock()
	_, stale := device.foreign["40000"]
	kept := len(device.foreign)
	device.mu.Unlock()
	if stale || kept != 2 {
		t.Fatalf("foreign entries after mapping: %v", device.foreign)
	}

	// A renewal that lands on another external port removes the old entry.
	device.mu.Lock()
	device.conflicts = 1
	device.mu.Unlock()
	renewed, err := c.mapPort(context.Background(), upnpTestGateway, 41641, &mapping)
	if err != nil || renewed.External.Port() == mapping.External.Port() {
		t.Fatalf("renewal %+v %v", renewed, err)
	}
	device.mu.Lock()
	_, old := device.mappings[strconv.Itoa(int(mapping.External.Port()))]
	device.mu.Unlock()
	if old {
		t.Fatal("the entry for the old external port is still on the gateway")
	}
}

func TestUPnPFindsTheServiceAgainAfterAGatewayRestart(t *testing.T) {
	t.Parallel()
	device := &igd{t: t, serviceType: upnpWANIPv1}
	server := device.server()
	defer server.Close()
	c := newUPnPTestClient(ssdpResponder(server.URL+"/rootDesc.xml", upnpTestGateway.Addr))
	mapping, err := c.mapPort(context.Background(), upnpTestGateway, 41641, nil)
	if err != nil {
		t.Fatal(err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // the old control port no longer answers
	mapping.control.url = gone.URL + "/ctl/IPConn"
	renewed, err := c.mapPort(context.Background(), upnpTestGateway, 41641, &mapping)
	if err != nil || !strings.HasPrefix(renewed.control.url, server.URL) {
		t.Fatalf("renewal %+v %v", renewed, err)
	}
}
