package netwatch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	routeSocketBufferSize = 64 * 1024
	maxRouteDrainMessages = 64
	// rtfIfscope marks a route bound to one interface (RTF_IFSCOPE in
	// <net/route.h>); macOS keeps one such default route per interface.
	rtfIfscope = 0x1000000
)

// routeSocketSource wakes on any routing socket message: address, link and
// route changes. Reading it needs no privileges.
type routeSocketSource struct {
	fileDescriptor int
	pollDescriptor int32
	buffer         []byte
}

func newNativeSource(_ time.Duration) (changeSource, error) {
	fileDescriptor, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("opening routing socket: %w", err)
	}
	unix.CloseOnExec(fileDescriptor)
	if fileDescriptor > math.MaxInt32 {
		_ = unix.Close(fileDescriptor)
		return nil, errors.New("netwatch: file descriptor is outside int32")
	}
	return &routeSocketSource{
		fileDescriptor: fileDescriptor,
		pollDescriptor: int32(fileDescriptor), //nolint:gosec // checked above
		buffer:         make([]byte, routeSocketBufferSize),
	}, nil
}

func (s *routeSocketSource) Wait(ctx context.Context) error {
	if s == nil || s.fileDescriptor < 0 {
		return errors.New("netwatch: routing socket source is closed")
	}
	pollDescriptors := []unix.PollFd{{Fd: s.pollDescriptor, Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := unix.Poll(pollDescriptors, 1000)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("polling routing socket: %w", err)
		}
		revents := pollDescriptors[0].Revents
		if revents&unix.POLLIN != 0 {
			return s.drain()
		}
		if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("netwatch: routing socket stopped")
		}
	}
}

func (s *routeSocketSource) drain() error {
	for range maxRouteDrainMessages {
		_, _, err := unix.Recvfrom(s.fileDescriptor, s.buffer, unix.MSG_DONTWAIT)
		switch {
		case err == nil:
			continue
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.ENOBUFS):
			return nil
		default:
			return fmt.Errorf("reading routing socket: %w", err)
		}
	}
	return nil
}

func (s *routeSocketSource) Close() error {
	if s == nil || s.fileDescriptor < 0 {
		return nil
	}
	fileDescriptor := s.fileDescriptor
	s.fileDescriptor = -1
	if err := unix.Close(fileDescriptor); err != nil {
		return fmt.Errorf("closing routing socket: %w", err)
	}
	return nil
}

func defaultRouteTokens(excludedIndexes map[int]struct{}) ([]string, map[int]struct{}, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("reading routing table: %w", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing routing table: %w", err)
	}
	return defaultRouteTokensFrom(messages, excludedIndexes)
}

// defaultRouteTokensFrom keeps the unscoped default routes: the ones macOS
// actually uses, not the per-interface scoped copies.
func defaultRouteTokensFrom(
	messages []route.Message,
	excludedIndexes map[int]struct{},
) ([]string, map[int]struct{}, error) {
	tokens := make([]string, 0, 2)
	indexes := make(map[int]struct{}, 2)
	for _, message := range messages {
		routeMessage, ok := message.(*route.RouteMessage)
		if !ok || routeMessage.Flags&rtfIfscope != 0 || routeMessage.Flags&unix.RTF_UP == 0 {
			continue
		}
		family, isDefault := defaultDestination(routeMessage.Addrs)
		if !isDefault {
			continue
		}
		if _, excluded := excludedIndexes[routeMessage.Index]; excluded {
			continue
		}
		indexes[routeMessage.Index] = struct{}{}
		tokens = append(tokens, fmt.Sprintf(
			"default|family=%d|link=%d|gateway=%s",
			family,
			routeMessage.Index,
			gatewayText(routeMessage.Addrs),
		))
	}
	sort.Strings(tokens)
	return tokens, indexes, nil
}

func defaultDestination(addresses []route.Addr) (int, bool) {
	if len(addresses) <= unix.RTAX_DST {
		return 0, false
	}
	switch destination := addresses[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		return unix.AF_INET, destination.IP == [4]byte{} && hostMaskAbsentOrZero(addresses)
	case *route.Inet6Addr:
		return unix.AF_INET6, destination.IP == [16]byte{} && hostMaskAbsentOrZero(addresses)
	default:
		return 0, false
	}
}

func hostMaskAbsentOrZero(addresses []route.Addr) bool {
	if len(addresses) <= unix.RTAX_NETMASK || addresses[unix.RTAX_NETMASK] == nil {
		return true
	}
	switch mask := addresses[unix.RTAX_NETMASK].(type) {
	case *route.Inet4Addr:
		return mask.IP == [4]byte{}
	case *route.Inet6Addr:
		return mask.IP == [16]byte{}
	default:
		return false
	}
}

func gatewayText(addresses []route.Addr) string {
	if len(addresses) <= unix.RTAX_GATEWAY {
		return ""
	}
	switch gateway := addresses[unix.RTAX_GATEWAY].(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(gateway.IP).String()
	case *route.Inet6Addr:
		return netip.AddrFrom16(gateway.IP).String()
	case *route.LinkAddr:
		return fmt.Sprintf("link#%d", gateway.Index)
	default:
		return ""
	}
}
