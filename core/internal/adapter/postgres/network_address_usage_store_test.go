package postgres

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network/addressusage"
)

func TestDecodeNetworkAddressUsage(t *testing.T) {
	t.Parallel()
	state, err := decodeNetworkAddressUsage([]byte(`{"prefixes":[
{"family":4,"prefix":"100.80.0.0/16","capacity":65534,"in_use":12,"held_by_expired":1,
 "held_after_revocation":2,"next_release":"2026-10-15T08:30:00.123456+00:00"},
{"family":6,"prefix":"fd07:d4de:9d87::/64","capacity":null,"in_use":12,"held_by_expired":0,
 "held_after_revocation":0,"next_release":null}]}`))
	if err != nil || len(state.Ranges) != 2 {
		t.Fatalf("decode = %+v, %v", state, err)
	}
	ipv4 := state.Ranges[0]
	if ipv4.Capacity != 65534 || ipv4.InUse != 12 || ipv4.HeldByExpired != 1 || ipv4.HeldAfterRevocation != 2 ||
		!ipv4.NextRelease.Equal(time.Date(2026, 10, 15, 8, 30, 0, 123456000, time.UTC)) {
		t.Fatalf("IPv4 range = %+v", ipv4)
	}
	if state.Ranges[1].Capacity != 0 || !state.Ranges[1].NextRelease.IsZero() {
		t.Fatalf("IPv6 range = %+v", state.Ranges[1])
	}
	for name, encoded := range map[string]string{
		"empty":           ``,
		"no ranges":       `{"prefixes":[]}`,
		"unknown field":   `{"prefixes":[],"extra":1}`,
		"trailing value":  `{"prefixes":[{"family":6,"prefix":"fd07::/64","capacity":null,"in_use":0,"held_by_expired":0,"held_after_revocation":0,"next_release":null}]} {}`,
		"family mismatch": `{"prefixes":[{"family":6,"prefix":"100.80.0.0/16","capacity":65534,"in_use":0,"held_by_expired":0,"held_after_revocation":0,"next_release":null}]}`,
		"over capacity":   `{"prefixes":[{"family":4,"prefix":"100.80.0.0/28","capacity":14,"in_use":15,"held_by_expired":0,"held_after_revocation":0,"next_release":null}]}`,
	} {
		if _, err := decodeNetworkAddressUsage([]byte(encoded)); !errors.Is(err, addressusage.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
