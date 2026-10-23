package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/dnsdigest"
	"meshtransit.net/shared/policydigest"
)

var _ mapsession.DNSHealthRecorder = (*Client)(nil)

// maximumDNSHealthBytes bounds one stored resolver health set: 64 resolvers
// of an address, a port, a state and a time.
const maximumDNSHealthBytes = 8 << 10

// resolverStates names the stored states (mtcp-v1 §8.6).
var resolverStates = map[mapsession.ResolverState]string{
	mapsession.ResolverOK:       distribution.ResolverOK,
	mapsession.ResolverBroken:   distribution.ResolverBroken,
	mapsession.ResolverStopped:  distribution.ResolverStopped,
	mapsession.ResolverRefusing: distribution.ResolverRefusing,
	mapsession.ResolverIdle:     distribution.ResolverIdle,
}

// RecordDNSHealth stores how a node's resolver sees the zones' resolvers
// against its current delivery session. It reports false when the node key
// has no current session, or the session belongs to another machine.
func (client *Client) RecordDNSHealth(ctx context.Context, health mapsession.DNSHealth) (bool, error) {
	if ctx == nil || client == nil || client.recordDNSHealth == nil || client.loadSession == nil ||
		!health.NodeKey.IsValid() || health.MachineFingerprint == [32]byte{} || health.ReportedAt.IsZero() ||
		!mapsession.ValidResolverHealth(health.Resolvers) {
		return false, ErrInvalidOptions
	}
	encoded, err := encodeDNSHealth(health.Resolvers)
	if err != nil {
		return false, errors.Join(ErrInvalidOptions, err)
	}
	startedAt := time.Now()
	stored, err := client.recordDNSHealthForSession(ctx, health, encoded)
	client.metrics.observeCommand(redisCommandRecordDNSHealth, startedAt, err)
	if err != nil {
		return false, errors.Join(ErrRecordDelivery, err)
	}
	return stored, nil
}

func (client *Client) recordDNSHealthForSession(ctx context.Context, health mapsession.DNSHealth,
	encoded string,
) (bool, error) {
	fields, err := client.loadSession(ctx, sessionKeyForNodeKey(health.NodeKey))
	if err != nil {
		return false, err
	}
	nodeID, generation, machine, found, err := decodeSession(fields)
	if err != nil || !found || machine != hex.EncodeToString(health.MachineFingerprint[:]) {
		return false, err
	}
	result, err := client.recordDNSHealth(ctx, deliveryKeyForNode(nodeID), nodeID.String(), generation, encoded,
		health.ReportedAt.UnixMilli(), deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected dns health record result")
	}
	return result == 1, err
}

// encodeDNSHealth writes resolvers as [[address:port, state, last ok ms],
// ...], the time 0 when none.
func encodeDNSHealth(resolvers []mapsession.ResolverHealth) (string, error) {
	rows := make([][3]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		lastOK := int64(0)
		if !resolver.LastOK.IsZero() {
			lastOK = resolver.LastOK.UnixMilli()
		}
		rows = append(rows, [3]string{resolver.Resolver.String(), resolverStates[resolver.State],
			strconv.FormatInt(lastOK, 10)})
	}
	encoded, err := json.Marshal(rows)
	if err != nil || len(encoded) > maximumDNSHealthBytes {
		return "", errors.New("dns health does not fit")
	}
	return string(encoded), nil
}

// decodeDNSHealth reads what encodeDNSHealth wrote; empty is none.
func decodeDNSHealth(text string) ([]distribution.ResolverHealth, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > maximumDNSHealthBytes {
		return nil, errors.New("dns health is too large")
	}
	var rows [][3]string
	if err := json.Unmarshal([]byte(text), &rows); err != nil || len(rows) > mapsession.MaximumResolverHealth {
		return nil, errors.New("malformed dns health")
	}
	resolvers := make([]distribution.ResolverHealth, 0, len(rows))
	for _, row := range rows {
		resolver, err := netip.ParseAddrPort(row[0])
		lastOK, timeErr := strconv.ParseInt(row[2], 10, 64)
		health := distribution.ResolverHealth{Resolver: resolver, State: row[1]}
		if lastOK > 0 {
			health.LastOK = time.UnixMilli(lastOK).UTC()
		}
		if err != nil || timeErr != nil || lastOK < 0 || !health.IsValid() {
			return nil, errors.New("malformed dns health")
		}
		resolvers = append(resolvers, health)
	}
	return resolvers, nil
}

// decodeDNSSummary reads a DNS digest and route count that are both present
// or both empty.
func decodeDNSSummary(digestText, routesText string) (distribution.DNSSummary, error) {
	if digestText == "" && routesText == "" {
		return distribution.DNSSummary{}, nil
	}
	digest, err := policydigest.Parse(digestText)
	if err != nil {
		return distribution.DNSSummary{}, errors.New("malformed dns digest")
	}
	routes, err := strconv.Atoi(routesText)
	if err != nil || routes < 0 || routes > dnsdigest.MaximumRoutes {
		return distribution.DNSSummary{}, errors.New("malformed dns routes")
	}
	return distribution.DNSSummary{Digest: digest, Routes: routes}, nil
}
