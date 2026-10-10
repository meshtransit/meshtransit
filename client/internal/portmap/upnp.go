package portmap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UPnP IGD service types, most capable first.
//
//nolint:gosec // G101: UPnP service type URNs, not credentials.
const (
	upnpWANIPv2  = "urn:schemas-upnp-org:service:WANIPConnection:2"
	upnpWANIPv1  = "urn:schemas-upnp-org:service:WANIPConnection:1"
	upnpWANPPPv1 = "urn:schemas-upnp-org:service:WANPPPConnection:1"
)

var upnpServiceTypes = []string{upnpWANIPv2, upnpWANIPv1, upnpWANPPPv1}

// UPnP error codes used by the client (UPnP IGD WANIPConnection v2 §2.5).
const (
	upnpErrorInvalidAction     = 401
	upnpErrorNotImplemented    = 602
	upnpErrorNoSuchEntry       = 714
	upnpErrorConflict          = 718
	upnpErrorPermanentLeasesOK = 725
)

// upnpMaxListed bounds the gateway's mapping table walked when cleaning up.
const upnpMaxListed = 64

// Limits on what the gateway may send.
const (
	ssdpPort            = 1900
	ssdpWait            = 1500 * time.Millisecond
	ssdpMaxDatagram     = 2048
	upnpMaxDescription  = 256 << 10
	upnpMaxSOAPResponse = 64 << 10
	upnpRequestTimeout  = 3 * time.Second
	upnpDescription     = "MeshTransit"
	upnpConflictRetries = 3
)

var ssdpGroup = netip.AddrPortFrom(netip.AddrFrom4([4]byte{239, 255, 255, 250}), ssdpPort)

// upnpControl is a WAN connection service's SOAP endpoint.
type upnpControl struct {
	url         string
	serviceType string
}

func (c upnpControl) valid() bool { return c.url != "" && c.serviceType != "" }

// upnpError is a SOAP fault carrying a UPnP error code.
type upnpError struct {
	code        int
	description string
}

func (e *upnpError) Error() string {
	return fmt.Sprintf("portmap: upnp error %d %s", e.code, e.description)
}

func upnpErrorCode(err error) int {
	var fault *upnpError
	if errors.As(err, &fault) {
		return fault.code
	}

	return 0
}

// upnpClient implements UPnP IGD port mapping.
type upnpClient struct {
	listen ListenFunc
	http   *http.Client
	clock  func() time.Time
}

func (upnpClient) protocol() Protocol { return ProtocolUPnP }

// newUPnPHTTPClient returns an HTTP client for talking to the gateway: no
// proxy (the gateway is on the local link), no redirects, no cookies.
func newUPnPHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DisableKeepAlives:      true,
			ResponseHeaderTimeout:  upnpRequestTimeout,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ssdpSearch is an M-SEARCH for Internet gateway devices.
func ssdpSearch(target string) []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: " + target + "\r\n\r\n")
}

// parseSSDPLocation returns the LOCATION of an SSDP search response.
func parseSSDPLocation(b []byte) (string, bool) {
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		return "", false
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", false
	}
	location := response.Header.Get("Location")

	return location, location != ""
}

// gatewayURL parses raw relative to base and requires plain HTTP to the
// gateway's own address: no names, no credentials, no other hosts.
func gatewayURL(base *url.URL, raw string, gw Gateway) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: upnp url", ErrInvalidResponse)
	}
	if base != nil {
		parsed = base.ResolveReference(parsed)
	}
	if parsed.Scheme != "http" || parsed.User != nil {
		return nil, fmt.Errorf("%w: upnp url is not plain http", ErrInvalidResponse)
	}
	host, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || host.Unmap() != gw.Addr {
		return nil, fmt.Errorf("%w: upnp url points away from the gateway", ErrInvalidResponse)
	}

	return parsed, nil
}

// discover finds the gateway's WAN connection service.
func (c upnpClient) discover(ctx context.Context, gw Gateway) (upnpControl, error) {
	location, err := c.search(ctx, gw)
	if err != nil {
		return upnpControl{}, err
	}
	description, err := gatewayURL(nil, location, gw)
	if err != nil {
		return upnpControl{}, err
	}
	body, err := c.get(ctx, description.String())
	if err != nil {
		return upnpControl{}, err
	}

	return parseUPnPDescription(body, description, gw)
}

func (c upnpClient) search(ctx context.Context, gw Gateway) (string, error) {
	conn, err := c.listen(ctx, gw.Local)
	if err != nil {
		return "", fmt.Errorf("portmap: opening socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	defer context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })()
	gatewaySSDP := netip.AddrPortFrom(gw.Addr, ssdpPort)
	for _, target := range []string{
		"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	} {
		request := ssdpSearch(target)
		// Multicast as SSDP specifies, and unicast to the gateway, which most
		// gateways also answer when multicast leaves on another interface.
		for _, destination := range []netip.AddrPort{ssdpGroup, gatewaySSDP} {
			if _, err := conn.WriteToUDPAddrPort(request, destination); err != nil && destination == gatewaySSDP {
				return "", fmt.Errorf("portmap: sending ssdp search: %w", err)
			}
		}
	}
	deadline := time.Now().Add(ssdpWait)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return "", fmt.Errorf("portmap: setting deadline: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	buffer := make([]byte, ssdpMaxDatagram)
	for {
		n, source, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}

			return "", ErrUnsupported
		}
		if source.Addr().Unmap() != gw.Addr {
			continue
		}
		if location, ok := parseSSDPLocation(buffer[:n]); ok {
			return location, nil
		}
	}
}

func (c upnpClient) get(ctx context.Context, target string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, upnpRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("portmap: upnp request: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("portmap: fetching upnp description: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: upnp description status %d", ErrInvalidResponse, response.StatusCode)
	}

	return readLimited(response.Body, upnpMaxDescription)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("portmap: reading upnp response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: upnp response too large", ErrInvalidResponse)
	}

	return body, nil
}

type upnpDevice struct {
	Services []struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []upnpDevice `xml:"deviceList>device"`
}

// upnpMaxDepth bounds device nesting in a description.
const upnpMaxDepth = 8

// parseUPnPDescription finds the most capable WAN connection service in a
// device description and resolves its control URL.
func parseUPnPDescription(body []byte, location *url.URL, gw Gateway) (upnpControl, error) {
	var root struct {
		URLBase string     `xml:"URLBase"`
		Device  upnpDevice `xml:"device"`
	}
	if err := xml.Unmarshal(body, &root); err != nil {
		return upnpControl{}, fmt.Errorf("%w: upnp description", ErrInvalidResponse)
	}
	base := location
	if root.URLBase != "" {
		parsed, err := gatewayURL(nil, root.URLBase, gw)
		if err != nil {
			return upnpControl{}, err
		}
		base = parsed
	}
	found := map[string]string{}
	var walk func(device upnpDevice, depth int)
	walk = func(device upnpDevice, depth int) {
		if depth > upnpMaxDepth {
			return
		}
		for _, service := range device.Services {
			serviceType := strings.TrimSpace(service.ServiceType)
			if _, seen := found[serviceType]; !seen && service.ControlURL != "" {
				found[serviceType] = service.ControlURL
			}
		}
		for _, child := range device.Devices {
			walk(child, depth+1)
		}
	}
	walk(root.Device, 0)
	for _, serviceType := range upnpServiceTypes {
		raw, ok := found[serviceType]
		if !ok {
			continue
		}
		control, err := gatewayURL(base, raw, gw)
		if err != nil {
			return upnpControl{}, err
		}

		return upnpControl{url: control.String(), serviceType: serviceType}, nil
	}

	return upnpControl{}, ErrUnsupported
}

// soapArgument is one named argument of a SOAP action, in order.
type soapArgument struct{ name, value string }

// soapCall invokes action on control and returns the response's leaf
// elements by local name.
func (c upnpClient) soapCall(
	ctx context.Context,
	control upnpControl,
	action string,
	arguments ...soapArgument,
) (map[string]string, error) {
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	body.WriteString(`<u:` + action + ` xmlns:u="` + control.serviceType + `">`)
	for _, argument := range arguments {
		body.WriteString("<" + argument.name + ">")
		if err := xml.EscapeText(&body, []byte(argument.value)); err != nil {
			return nil, fmt.Errorf("portmap: encoding soap: %w", err)
		}
		body.WriteString("</" + argument.name + ">")
	}
	body.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)

	ctx, cancel := context.WithTimeout(ctx, upnpRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, control.url, &body)
	if err != nil {
		return nil, fmt.Errorf("portmap: soap request: %w", err)
	}
	request.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	request.Header.Set("SOAPAction", `"`+control.serviceType+"#"+action+`"`)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("portmap: soap %s: %w", action, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := readLimited(response.Body, upnpMaxSOAPResponse)
	if err != nil {
		return nil, err
	}
	fields, err := soapLeaves(payload)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		if code, convErr := strconv.Atoi(fields["errorCode"]); convErr == nil {
			return nil, &upnpError{code: code, description: fields["errorDescription"]}
		}

		return nil, fmt.Errorf("%w: soap %s status %d", ErrInvalidResponse, action, response.StatusCode)
	}

	return fields, nil
}

// soapLeaves collects the text of leaf elements by local name. Later
// duplicates are ignored.
func soapLeaves(payload []byte) (map[string]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	fields := map[string]string{}
	var (
		name  string
		text  strings.Builder
		depth int
	)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return fields, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: soap response", ErrInvalidResponse)
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			if depth > 32 {
				return nil, fmt.Errorf("%w: soap response nesting", ErrInvalidResponse)
			}
			name = element.Name.Local
			text.Reset()
		case xml.CharData:
			if name != "" && text.Len() < 1024 {
				text.Write(element)
			}
		case xml.EndElement:
			depth--
			if name == element.Name.Local {
				if _, seen := fields[name]; !seen {
					fields[name] = strings.TrimSpace(text.String())
				}
			}
			name = ""
		}
	}
}

func (c upnpClient) externalAddress(ctx context.Context, control upnpControl) (netip.Addr, error) {
	fields, err := c.soapCall(ctx, control, "GetExternalIPAddress")
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(fields["NewExternalIPAddress"])
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("%w: upnp external address", ErrInvalidResponse)
	}

	return addr, nil
}

func randomPort() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])

	return 1024 + binary.BigEndian.Uint16(b[:])%(65535-1024)
}

// add requests external → internal, preferring the given external port, and
// returns the external port and lease granted.
func (c upnpClient) add(
	ctx context.Context,
	control upnpControl,
	gw Gateway,
	internal, external uint16,
) (uint16, time.Duration, error) {
	lease := DefaultLifetime
	arguments := func(port uint16, lease time.Duration) []soapArgument {
		return []soapArgument{
			{"NewRemoteHost", ""},
			{"NewExternalPort", strconv.Itoa(int(port))},
			{"NewProtocol", "UDP"},
			{"NewInternalPort", strconv.Itoa(int(internal))},
			{"NewInternalClient", gw.Local.String()},
			{"NewEnabled", "1"},
			{"NewPortMappingDescription", upnpDescription},
			{"NewLeaseDuration", strconv.Itoa(int(lease / time.Second))},
		}
	}
	if control.serviceType == upnpWANIPv2 {
		for {
			fields, err := c.soapCall(ctx, control, "AddAnyPortMapping", arguments(external, lease)...)
			if upnpErrorCode(err) == upnpErrorPermanentLeasesOK && lease != 0 {
				lease = 0

				continue
			}
			if code := upnpErrorCode(err); code == upnpErrorInvalidAction || code == upnpErrorNotImplemented {
				break // AddPortMapping is part of v2 too
			}
			if err != nil {
				return 0, 0, err
			}
			port, convErr := strconv.ParseUint(fields["NewReservedPort"], 10, 16)
			if convErr != nil || port == 0 {
				return 0, 0, fmt.Errorf("%w: upnp reserved port", ErrInvalidResponse)
			}

			return uint16(port), lease, nil
		}
	}
	port := external
	lease = DefaultLifetime
	for attempt := 0; ; attempt++ {
		_, err := c.soapCall(ctx, control, "AddPortMapping", arguments(port, lease)...)
		switch {
		case err == nil:
			return port, lease, nil
		case upnpErrorCode(err) == upnpErrorPermanentLeasesOK && lease != 0:
			lease = 0
		case upnpErrorCode(err) == upnpErrorConflict && attempt < upnpConflictRetries:
			port = randomPort()
		default:
			return 0, 0, err
		}
	}
}

func (c upnpClient) mapPort(ctx context.Context, gw Gateway, internal uint16, previous *Mapping) (Mapping, error) {
	control := upnpControl{}
	external := internal
	if previous != nil && previous.Protocol == ProtocolUPnP && previous.Gateway == gw && previous.Internal == internal {
		control = previous.control
		external = previous.External.Port()
	}
	fresh := !control.valid()
	if fresh {
		discovered, err := c.discover(ctx, gw)
		if err != nil {
			return Mapping{}, err
		}
		control = discovered
	}
	address, port, lease, err := c.request(ctx, control, gw, internal, external)
	if err != nil && !fresh && upnpErrorCode(err) == 0 {
		// The cached control URL stopped answering, as after a gateway
		// restart on another port: find the service again, once.
		discovered, discoverErr := c.discover(ctx, gw)
		if discoverErr != nil {
			return Mapping{}, discoverErr
		}
		control, fresh = discovered, true
		address, port, lease, err = c.request(ctx, control, gw, internal, external)
	}
	if err != nil {
		if upnpErrorCode(err) != 0 {
			return Mapping{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}

		return Mapping{}, err
	}
	if previous != nil && previous.Protocol == ProtocolUPnP && previous.External.Port() != port {
		// The renewal moved the external port: remove the old entry.
		_ = c.unmap(ctx, *previous)
	}
	if fresh {
		c.removeStale(ctx, control, gw, port)
	}

	return Mapping{
		Protocol: ProtocolUPnP,
		Gateway:  gw,
		Internal: internal,
		External: netip.AddrPortFrom(address, port),
		Lifetime: lease,
		Obtained: c.clock(),
		control:  control,
	}, nil
}

// request reads the external address and adds the mapping.
func (c upnpClient) request(
	ctx context.Context,
	control upnpControl,
	gw Gateway,
	internal, external uint16,
) (netip.Addr, uint16, time.Duration, error) {
	address, err := c.externalAddress(ctx, control)
	if err != nil {
		return netip.Addr{}, 0, 0, err
	}
	port, lease, err := c.add(ctx, control, gw, internal, external)

	return address, port, lease, err
}

// removeStale deletes UDP entries an earlier meshd left for this host, such
// as a permanent lease after a crash: same description, same internal client,
// another external port than keep. It reads at most upnpMaxListed entries
// and is best effort.
func (c upnpClient) removeStale(ctx context.Context, control upnpControl, gw Gateway, keep uint16) {
	var stale []string
	for index := 0; index < upnpMaxListed; index++ {
		fields, err := c.soapCall(ctx, control, "GetGenericPortMappingEntry",
			soapArgument{"NewPortMappingIndex", strconv.Itoa(index)})
		if err != nil {
			break // 713 ends the table; anything else ends the walk too
		}
		if fields["NewProtocol"] == "UDP" && fields["NewPortMappingDescription"] == upnpDescription &&
			fields["NewInternalClient"] == gw.Local.String() &&
			fields["NewExternalPort"] != strconv.Itoa(int(keep)) && fields["NewRemoteHost"] == "" {
			stale = append(stale, fields["NewExternalPort"])
		}
	}
	for _, port := range stale {
		_, _ = c.soapCall(ctx, control, "DeletePortMapping",
			soapArgument{"NewRemoteHost", ""},
			soapArgument{"NewExternalPort", port},
			soapArgument{"NewProtocol", "UDP"},
		)
	}
}

func (c upnpClient) unmap(ctx context.Context, m Mapping) error {
	_, err := c.soapCall(ctx, m.control, "DeletePortMapping",
		soapArgument{"NewRemoteHost", ""},
		soapArgument{"NewExternalPort", strconv.Itoa(int(m.External.Port()))},
		soapArgument{"NewProtocol", "UDP"},
	)

	return err
}

func (c upnpClient) check(ctx context.Context, m Mapping) (bool, error) {
	fields, err := c.soapCall(ctx, m.control, "GetSpecificPortMappingEntry",
		soapArgument{"NewRemoteHost", ""},
		soapArgument{"NewExternalPort", strconv.Itoa(int(m.External.Port()))},
		soapArgument{"NewProtocol", "UDP"},
	)
	if upnpErrorCode(err) == upnpErrorNoSuchEntry {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	client, parseErr := netip.ParseAddr(fields["NewInternalClient"])

	return parseErr == nil && client == m.Gateway.Local &&
		fields["NewInternalPort"] == strconv.Itoa(int(m.Internal)), nil
}
