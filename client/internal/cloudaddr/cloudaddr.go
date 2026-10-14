// Package cloudaddr finds the public addresses a cloud provider assigns to
// this instance, from the provider's instance metadata service.
//
// On AWS, GCP and Azure a public IPv4 address is a 1:1 NAT in front of the
// instance's private address: the operating system never sees it, and STUN
// finds it only when outbound UDP works. The metadata service knows it
// directly, so meshd can offer publicIP:port as a static candidate.
//
// The metadata service is contacted only on a platform recognised from the
// machine's DMI data, never otherwise.
package cloudaddr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"meshtransit.net/client/internal/underlay"
)

// Platform is a cloud provider recognised from DMI data.
type Platform string

// Recognised platforms.
const (
	PlatformNone         Platform = ""
	PlatformAWS          Platform = "aws"
	PlatformGCP          Platform = "gcp"
	PlatformAzure        Platform = "azure"
	PlatformDigitalOcean Platform = "digitalocean"
)

// Errors.
var (
	// ErrNoPlatform means the machine is not on a recognised cloud.
	ErrNoPlatform = errors.New("cloudaddr: not a recognised cloud instance")
	// ErrInvalidResponse means the metadata service answered unexpectedly.
	ErrInvalidResponse = errors.New("cloudaddr: invalid metadata response")
)

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// azureAssetTag is the chassis asset tag Azure sets on every VM.
const azureAssetTag = "7783-7084-3265-9085-8269-3286-77"

// dmiDirectory holds the SMBIOS fields Linux exposes.
const dmiDirectory = "/sys/class/dmi/id"

// DetectPlatform recognises the cloud provider from DMI fields read by read
// (a field name such as "sys_vendor"; missing fields read as empty).
func DetectPlatform(read func(field string) string) Platform {
	field := func(name string) string { return strings.TrimSpace(read(name)) }
	vendor, product := field("sys_vendor"), field("product_name")
	switch {
	case vendor == "Amazon EC2" || strings.HasPrefix(field("bios_vendor"), "Amazon EC2") ||
		strings.Contains(strings.ToLower(field("bios_version")), "amazon"):
		return PlatformAWS
	case vendor == "Google" && product == "Google Compute Engine":
		return PlatformGCP
	case vendor == "Microsoft Corporation" && field("chassis_asset_tag") == azureAssetTag:
		return PlatformAzure
	case vendor == "DigitalOcean":
		return PlatformDigitalOcean
	default:
		return PlatformNone
	}
}

// ReadDMI reads one DMI field on Linux; elsewhere every field is empty.
func ReadDMI(field string) string {
	content, err := os.ReadFile(filepath.Join(dmiDirectory, filepath.Base(field)))
	if err != nil || len(content) > 256 {
		return ""
	}

	return string(content)
}

// Limits on the metadata service.
const (
	metadataBase    = "http://169.254.169.254"
	requestTimeout  = 2 * time.Second
	maxResponseSize = 64 << 10
	maxAddresses    = 8
	awsTokenTTL     = "60"
)

// Client reads public addresses from a metadata service.
type Client struct {
	base string
	http *http.Client
}

// NewClient returns a client for the link-local metadata service: no proxy,
// no redirects, no keep-alive.
func NewClient() *Client {
	return newClient(metadataBase, &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            underlay.Dialer(0).DialContext,
			DisableKeepAlives:      true,
			ResponseHeaderTimeout:  requestTimeout,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})
}

func newClient(base string, httpClient *http.Client) *Client {
	return &Client{base: base, http: httpClient}
}

// PublicAddresses returns the instance's public addresses on platform. An
// instance without a public address returns an empty list and no error.
func (c *Client) PublicAddresses(ctx context.Context, platform Platform) ([]netip.Addr, error) {
	var (
		raw []string
		err error
	)
	switch platform {
	case PlatformAWS:
		raw, err = c.aws(ctx)
	case PlatformGCP:
		raw, err = c.gcp(ctx)
	case PlatformAzure:
		raw, err = c.azure(ctx)
	case PlatformDigitalOcean:
		raw, err = c.digitalOcean(ctx)
	default:
		return nil, ErrNoPlatform
	}
	if err != nil {
		return nil, err
	}

	return publicOnly(raw), nil
}

// publicOnly keeps distinct global unicast addresses that are not private,
// shared or link-local, at most maxAddresses.
func publicOnly(raw []string) []netip.Addr {
	var out []netip.Addr
	for _, value := range raw {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.Zone() != "" || sharedAddressSpace.Contains(addr) {
			continue
		}
		duplicate := false
		for _, seen := range out {
			duplicate = duplicate || seen == addr
		}
		if !duplicate && len(out) < maxAddresses {
			out = append(out, addr)
		}
	}

	return out
}

// get performs one request and returns the body. A 404 is an absent value,
// returned as nil without error.
func (c *Client) get(
	ctx context.Context,
	method, path string,
	header map[string]string,
	wantHeader [2]string,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return nil, fmt.Errorf("cloudaddr: request: %w", err)
	}
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("cloudaddr: metadata request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrInvalidResponse, response.StatusCode)
	}
	if wantHeader[0] != "" && response.Header.Get(wantHeader[0]) != wantHeader[1] {
		return nil, fmt.Errorf("%w: missing %s", ErrInvalidResponse, wantHeader[0])
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("cloudaddr: reading metadata: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("%w: response too large", ErrInvalidResponse)
	}

	return body, nil
}

// aws uses IMDSv2: a session token first, then the public IPv4 address and
// the IPv6 addresses of the primary interface.
func (c *Client) aws(ctx context.Context) ([]string, error) {
	token, err := c.get(ctx, http.MethodPut, "/latest/api/token",
		map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": awsTokenTTL}, [2]string{})
	if err != nil {
		return nil, err
	}
	if len(token) == 0 || len(token) > 1024 {
		return nil, fmt.Errorf("%w: imds token", ErrInvalidResponse)
	}
	header := map[string]string{"X-aws-ec2-metadata-token": strings.TrimSpace(string(token))}
	var out []string
	for _, path := range []string{"/latest/meta-data/public-ipv4", "/latest/meta-data/ipv6"} {
		body, err := c.get(ctx, http.MethodGet, path, header, [2]string{})
		if err != nil {
			return nil, err
		}
		out = append(out, strings.Fields(string(body))...)
	}

	return out, nil
}

// gcp reads every interface's external IPv4 and IPv6 addresses.
func (c *Client) gcp(ctx context.Context) ([]string, error) {
	body, err := c.get(ctx, http.MethodGet, "/computeMetadata/v1/instance/network-interfaces/?recursive=true",
		map[string]string{"Metadata-Flavor": "Google"}, [2]string{"Metadata-Flavor", "Google"})
	if err != nil || body == nil {
		return nil, err
	}
	var interfaces []struct {
		AccessConfigs []struct {
			ExternalIP string `json:"externalIp"`
		} `json:"accessConfigs"`
		IPv6AccessConfigs []struct {
			ExternalIPv6 string `json:"externalIpv6"`
		} `json:"ipv6AccessConfigs"`
	}
	if err := json.Unmarshal(body, &interfaces); err != nil {
		return nil, fmt.Errorf("%w: gcp interfaces", ErrInvalidResponse)
	}
	var out []string
	for _, nic := range interfaces {
		for _, config := range nic.AccessConfigs {
			out = append(out, config.ExternalIP)
		}
		for _, config := range nic.IPv6AccessConfigs {
			out = append(out, config.ExternalIPv6)
		}
	}

	return out, nil
}

// azure reads the public IPv4 addresses of every interface (present for
// instance-level public IPs) and the interfaces' IPv6 addresses.
func (c *Client) azure(ctx context.Context) ([]string, error) {
	body, err := c.get(ctx, http.MethodGet, "/metadata/instance/network?api-version=2021-02-01",
		map[string]string{"Metadata": "true"}, [2]string{})
	if err != nil || body == nil {
		return nil, err
	}
	var network struct {
		Interface []struct {
			IPv4 struct {
				IPAddress []struct {
					PublicIPAddress string `json:"publicIpAddress"`
				} `json:"ipAddress"`
			} `json:"ipv4"`
			IPv6 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress"`
				} `json:"ipAddress"`
			} `json:"ipv6"`
		} `json:"interface"`
	}
	if err := json.Unmarshal(body, &network); err != nil {
		return nil, fmt.Errorf("%w: azure network", ErrInvalidResponse)
	}
	var out []string
	for _, nic := range network.Interface {
		for _, address := range nic.IPv4.IPAddress {
			out = append(out, address.PublicIPAddress)
		}
		for _, address := range nic.IPv6.IPAddress {
			out = append(out, address.PrivateIPAddress) // global IPv6 addresses are not translated
		}
	}

	return out, nil
}

// digitalOcean reads the public interface's IPv4 and IPv6 addresses.
func (c *Client) digitalOcean(ctx context.Context) ([]string, error) {
	var out []string
	for _, path := range []string{
		"/metadata/v1/interfaces/public/0/ipv4/address",
		"/metadata/v1/interfaces/public/0/ipv6/address",
	} {
		body, err := c.get(ctx, http.MethodGet, path, nil, [2]string{})
		if err != nil {
			return nil, err
		}
		out = append(out, strings.Fields(string(body))...)
	}

	return out, nil
}
