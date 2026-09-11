//go:build linux

package netwatch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	netlinkReadBufferSize    = 64 * 1024
	maxNetlinkDrainDatagrams = 64
)

type netlinkSource struct {
	fileDescriptor int
	pollDescriptor int32
	buffer         []byte
}

func newNativeSource(_ time.Duration) (changeSource, error) {
	fileDescriptor, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return nil, fmt.Errorf("opening route netlink socket: %w", err)
	}
	pollDescriptor, err := checkedPollDescriptor(fileDescriptor)
	if err != nil {
		closeErr := unix.Close(fileDescriptor)

		return nil, errors.Join(err, closeErr)
	}
	groups := uint32(
		unix.RTMGRP_LINK |
			unix.RTMGRP_IPV4_IFADDR |
			unix.RTMGRP_IPV6_IFADDR |
			unix.RTMGRP_IPV4_ROUTE |
			unix.RTMGRP_IPV6_ROUTE,
	)
	if err := unix.Bind(fileDescriptor, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: groups,
	}); err != nil {
		closeErr := unix.Close(fileDescriptor)

		return nil, errors.Join(fmt.Errorf("binding route netlink socket: %w", err), closeErr)
	}
	if err := unix.SetsockoptInt(
		fileDescriptor,
		unix.SOL_SOCKET,
		unix.SO_RCVBUF,
		netlinkReadBufferSize,
	); err != nil {
		closeErr := unix.Close(fileDescriptor)

		return nil, errors.Join(fmt.Errorf("sizing route netlink socket: %w", err), closeErr)
	}

	return &netlinkSource{
		fileDescriptor: fileDescriptor,
		pollDescriptor: pollDescriptor,
		buffer:         make([]byte, netlinkReadBufferSize),
	}, nil
}

func (s *netlinkSource) Wait(ctx context.Context) error {
	if s == nil || s.fileDescriptor < 0 {
		return errors.New("netwatch: netlink source is closed")
	}
	pollDescriptors := []unix.PollFd{{
		Fd:     s.pollDescriptor,
		Events: unix.POLLIN,
	}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := unix.Poll(pollDescriptors, 1000)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("polling route netlink socket: %w", err)
		}
		revents := pollDescriptors[0].Revents
		if revents&unix.POLLIN != 0 {
			return s.drain()
		}
		if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("netwatch: route netlink socket stopped")
		}
	}
}

func checkedPollDescriptor(fileDescriptor int) (int32, error) {
	if fileDescriptor < 0 || int64(fileDescriptor) > math.MaxInt32 {
		return 0, errors.New("netwatch: file descriptor is outside int32")
	}

	return int32(fileDescriptor), nil
}

func (s *netlinkSource) drain() error {
	for range maxNetlinkDrainDatagrams {
		_, _, err := unix.Recvfrom(s.fileDescriptor, s.buffer, unix.MSG_DONTWAIT)
		switch {
		case err == nil:
			continue
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.ENOBUFS):
			return nil
		default:
			return fmt.Errorf("reading route netlink socket: %w", err)
		}
	}

	return nil
}

func (s *netlinkSource) Close() error {
	if s == nil || s.fileDescriptor < 0 {
		return nil
	}
	fileDescriptor := s.fileDescriptor
	s.fileDescriptor = -1
	if err := unix.Close(fileDescriptor); err != nil {
		return fmt.Errorf("closing route netlink socket: %w", err)
	}

	return nil
}

func defaultRouteTokens(excludedIndexes map[int]struct{}) ([]string, map[int]struct{}, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, err
	}
	tokens := make([]string, 0, 2)
	indexes := make(map[int]struct{}, 2)
	for _, route := range routes {
		if !isDefaultRoute(route) {
			continue
		}
		if _, excluded := excludedIndexes[route.LinkIndex]; excluded {
			continue
		}
		indexes[route.LinkIndex] = struct{}{}
		tokens = append(tokens, fmt.Sprintf(
			"default|family=%d|link=%d|gateway=%s|priority=%d|table=%d",
			route.Family,
			route.LinkIndex,
			route.Gw.String(),
			route.Priority,
			route.Table,
		))
	}
	sort.Strings(tokens)

	return tokens, indexes, nil
}

func isDefaultRoute(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	ones, _ := route.Dst.Mask.Size()

	return ones == 0
}
