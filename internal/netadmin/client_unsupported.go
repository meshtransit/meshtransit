//go:build !linux

package netadmin

import (
	"context"
	"time"
)

// Client is unavailable outside Linux and exists to preserve portable builds.
type Client struct{}

// NewClient reports that the privileged helper is Linux-only.
func NewClient(_ string, _ time.Duration) (*Client, error) {
	return nil, ErrUnsupported
}

// OpenTUN reports that the privileged helper is Linux-only.
func (c *Client) OpenTUN(_ context.Context, _ TUNConfig) (TUN, error) {
	return TUN{}, ErrUnsupported
}

// OpenDNS reports that the privileged DNS link is Linux-only.
func (c *Client) OpenDNS(_ context.Context) (DNSLink, error) {
	return DNSLink{}, ErrUnsupported
}

// ConfigureDNS reports that systemd-resolved integration is Linux-only.
func (c *Client) ConfigureDNS(_ context.Context, _ DNSConfig) error {
	return ErrUnsupported
}

// ResetDNS reports that systemd-resolved integration is Linux-only.
func (c *Client) ResetDNS(_ context.Context) error {
	return ErrUnsupported
}
