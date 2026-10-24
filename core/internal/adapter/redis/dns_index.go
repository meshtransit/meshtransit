package redis

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// The DNS index counts a Network's Devices by zone and resolver (DNS design
// D1b §8, §9) without reading every delivery record. The scripts that write
// a Device's DNS evidence keep it up to date:
//
//   - dns-index:zone:<network>:<suffix>, a hash: the Devices that hold the
//     zone, field node ID, value when it was delivered.
//   - dns-index:apply:<network>, a hash: field node ID, value the DNS digest
//     sent, its routes, the digest applied, its routes, the reason it
//     applies none, when it was delivered and when it was last seen, joined
//     by '|'.
//   - dns-index:health:<network>:<address:port>:<state>, a sorted set: the
//     Devices whose last resolver health put that resolver in that state,
//     scored by when Core received it.
//
// Only Devices that report what they apply (dns.root1) are indexed. The keys
// are not in KEYS: Core runs on a single Redis node
// (docs/operations/deployment.md), and their names come from Core's own
// records, never the node's text.
const (
	dnsIndexPrefix = "meshtransit:v1:dns-index:"
	// dnsIndexTTL drops a Network's index when nobody in it reports any more.
	dnsIndexTTL = deliveryTTL
	// dnsHealthPruneAfter is how old a resolver state a write drops.
	dnsHealthPruneAfter = 24 * time.Hour
	// maximumDNSIndexEntries bounds the Devices one zone's count reads.
	maximumDNSIndexEntries = 100_000
	// dnsApplyBatch bounds one read of the application hash.
	dnsApplyBatch = 1_000
	// maximumDNSIndexPrune bounds the fields one count deletes.
	maximumDNSIndexPrune = 1_000
	// maximumResolverCounts bounds the resolvers one count reads.
	maximumResolverCounts = 64
)

var errDNSIndexTooLarge = errors.New("dns index is too large to count")

// ErrLoadDNSIndex classifies an unavailable or corrupt DNS index.
var ErrLoadDNSIndex = errors.New("redis: load dns index")

// dnsIndexLua holds the functions the delivery, touch, enforcement and
// health scripts call to keep the DNS index.
const dnsIndexLua = `
local function dns_apply(delivery, node, prefix, ttl)
    local f = redis.call('HMGET', delivery, 'dns_network', 'dns_digest', 'dns_routes', 'enforced_dns_digest',
        'enforced_dns_routes', 'dns_reason', 'delivered_at', 'seen_at')
    if not f[1] or f[1] == '' then
        return
    end
    local key = prefix .. 'apply:' .. f[1]
    if not f[2] or f[2] == '' then
        redis.call('HDEL', key, node)
        return
    end
    local parts = {}
    for index = 2, 8 do
        parts[#parts + 1] = f[index] or ''
    end
    redis.call('HSET', key, node, table.concat(parts, '|'))
    redis.call('PEXPIRE', key, ttl)
end
local function dns_zones(delivery, node, network, zones, at, prefix, ttl)
    local old = redis.call('HMGET', delivery, 'dns_network', 'dns_zones')
    local keep = {}
    if network ~= '' and zones ~= '' then
        local ok, decoded = pcall(cjson.decode, zones)
        if ok and type(decoded) == 'table' then
            for _, zone in ipairs(decoded) do
                keep[zone] = true
            end
        end
    end
    if old[1] and old[1] ~= '' then
        if old[2] and old[2] ~= '' then
            local ok, previous = pcall(cjson.decode, old[2])
            if ok and type(previous) == 'table' then
                for _, zone in ipairs(previous) do
                    if old[1] ~= network or not keep[zone] then
                        redis.call('HDEL', prefix .. 'zone:' .. old[1] .. ':' .. zone, node)
                    end
                end
            end
        end
        if old[1] ~= network then
            redis.call('HDEL', prefix .. 'apply:' .. old[1], node)
        end
    end
    for zone in pairs(keep) do
        local key = prefix .. 'zone:' .. network .. ':' .. zone
        redis.call('HSET', key, node, at)
        redis.call('PEXPIRE', key, ttl)
    end
    redis.call('HSET', delivery, 'dns_network', network, 'dns_zones', zones)
end
local dns_states = {'ok', 'broken', 'stopped', 'refusing', 'idle'}
local function dns_health(delivery, node, previous, current, at, prefix, ttl, prune_before)
    local network = redis.call('HGET', delivery, 'dns_network')
    if not network or network == '' then
        return
    end
    local base = prefix .. 'health:' .. network .. ':'
    local kept = {}
    local ok, rows = pcall(cjson.decode, current)
    if ok and type(rows) == 'table' then
        for _, row in ipairs(rows) do
            kept[row[1]] = true
            for _, state in ipairs(dns_states) do
                local key = base .. row[1] .. ':' .. state
                if state == row[2] then
                    redis.call('ZADD', key, at, node)
                    redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. prune_before)
                    redis.call('PEXPIRE', key, ttl)
                else
                    redis.call('ZREM', key, node)
                end
            end
        end
    end
    if previous and previous ~= '' then
        local before_ok, before = pcall(cjson.decode, previous)
        if before_ok and type(before) == 'table' then
            for _, row in ipairs(before) do
                if not kept[row[1]] then
                    for _, state in ipairs(dns_states) do
                        redis.call('ZREM', base .. row[1] .. ':' .. state, node)
                    end
                end
            end
        end
    end
end
`

// pruneDNSIndexScript drops Devices from a zone's hash (KEYS[1]) and the
// Network's application hash (KEYS[2]); ARGV holds pairs of node ID and the
// application entry a count read, empty for none. Nothing is dropped for a
// Device whose entry changed since.
var pruneDNSIndexScript = redisclient.NewScript(`
for index = 1, #ARGV, 2 do
    local current = redis.call('HGET', KEYS[2], ARGV[index])
    if (ARGV[index + 1] == '' and not current) or current == ARGV[index + 1] then
        redis.call('HDEL', KEYS[1], ARGV[index])
        if current then
            redis.call('HDEL', KEYS[2], ARGV[index])
        end
    end
end
return 1
`)

func dnsZoneKey(networkID network.ID, suffix string) string {
	return dnsIndexPrefix + "zone:" + networkID.String() + ":" + suffix
}

func dnsApplyKey(networkID network.ID) string { return dnsIndexPrefix + "apply:" + networkID.String() }

func dnsHealthKey(networkID network.ID, resolver netip.AddrPort, state string) string {
	return dnsIndexPrefix + "health:" + networkID.String() + ":" + resolver.String() + ":" + state
}

// LoadDNSZoneApplication counts the Devices of the Network that hold the
// zone of suffix by how the DNS they apply compares with what they were
// sent. Entries of Devices that left the index are deleted as it reads, a
// bounded number at a time. With receivers, a Device it would count offline
// counts only while the zone is still sent to it: a Device deleted, or no
// longer in the zone's Device Groups, stays in the index until it expires.
func (client *Client) LoadDNSZoneApplication(ctx context.Context, networkID network.ID, suffix string,
	now time.Time, receivers distribution.DNSZoneReceivers,
) (distribution.DNSZoneApplication, error) {
	if ctx == nil || client == nil || client.loadDNSZone == nil || client.loadDNSApply == nil ||
		!networkID.IsValid() || suffix == "" || now.IsZero() {
		return distribution.DNSZoneApplication{}, ErrInvalidOptions
	}
	startedAt := time.Now()
	counts, err := client.countDNSZone(ctx, networkID, suffix, now, receivers)
	client.metrics.observeCommand(redisCommandLoadDNSIndex, startedAt, err)
	if err != nil {
		return distribution.DNSZoneApplication{}, errors.Join(ErrLoadDNSIndex, err)
	}
	return counts, nil
}

func (client *Client) countDNSZone(ctx context.Context, networkID network.ID, suffix string,
	now time.Time, receivers distribution.DNSZoneReceivers,
) (distribution.DNSZoneApplication, error) {
	zoneKey, applyKey := dnsZoneKey(networkID, suffix), dnsApplyKey(networkID)
	var counts distribution.DNSZoneApplication
	var stale []dnsIndexEntry
	seen := make(map[string]struct{})
	// The zone's hash is read a page at a time, so its size never blocks
	// Redis nor the pruning of what left it; past maximumDNSIndexEntries
	// the count is refused, after pruning what it read.
	var cursor uint64
	for {
		nodes, next, err := client.scanDNSZone(ctx, zoneKey, cursor, dnsApplyBatch)
		if err != nil {
			return distribution.DNSZoneApplication{}, err
		}
		fresh := nodes[:0]
		for _, nodeID := range nodes {
			if _, duplicate := seen[nodeID]; !duplicate {
				seen[nodeID] = struct{}{}
				fresh = append(fresh, nodeID)
			}
		}
		if len(fresh) != 0 {
			values, err := client.loadDNSApply(ctx, applyKey, fresh)
			if err != nil || len(values) != len(fresh) {
				return distribution.DNSZoneApplication{}, errors.Join(errors.New("unexpected dns index read"), err)
			}
			var offline []offlineDNSEntry
			for index, value := range values {
				text, present := value.(string)
				application, valid := decodeDNSApplication(text)
				switch {
				case !present:
					// The Device left the Network's index: no longer in it.
					stale = append(stale, dnsIndexEntry{node: fresh[index]})
				case !valid:
					// Written by another version: leave it, uncounted.
				case now.Sub(application.SeenAt) > dnsIndexTTL:
					stale = append(stale, dnsIndexEntry{node: fresh[index], apply: text})
				case receivers != nil && application.IsOffline(now):
					id, err := node.ParseID(fresh[index])
					if err != nil {
						// Not a Device ID Core wrote: counted, as before receivers.
						counts.Count(application, now)
						continue
					}
					offline = append(offline, offlineDNSEntry{node: id, application: application})
				default:
					counts.Count(application, now)
				}
			}
			if !countReceivers(ctx, &counts, offline, receivers, now) {
				// A filter that failed once fails the rest of the count too.
				receivers = nil
			}
		}
		if next == 0 || len(seen) > maximumDNSIndexEntries {
			client.pruneDNSIndexEntries(ctx, zoneKey, applyKey, stale)
			if next != 0 {
				return distribution.DNSZoneApplication{}, errDNSIndexTooLarge
			}
			return counts, nil
		}
		cursor = next
	}
}

// offlineDNSEntry is a Device a count would call offline, until the zone's
// receivers say whether it still gets the zone.
type offlineDNSEntry struct {
	node        node.ID
	application distribution.DNSApplication
}

// countReceivers counts the offline entries of one page whose Devices the
// zone is still sent to, false once the receivers could not be read: every
// entry left then counts, as before them. Its entries stay in the index:
// the application entry serves every zone of the Device, and expires on
// its own.
func countReceivers(ctx context.Context, counts *distribution.DNSZoneApplication, entries []offlineDNSEntry,
	receivers distribution.DNSZoneReceivers, now time.Time,
) bool {
	for start := 0; start < len(entries); start += distribution.DNSZoneReceiversBatch {
		batch := entries[start:min(len(entries), start+distribution.DNSZoneReceiversBatch)]
		ids := make([]node.ID, len(batch))
		for index, entry := range batch {
			ids[index] = entry.node
		}
		kept, err := receivers(ctx, ids)
		if err != nil {
			for _, entry := range entries[start:] {
				counts.Count(entry.application, now)
			}
			return false
		}
		for _, entry := range batch {
			if _, receives := kept[entry.node]; receives {
				counts.Count(entry.application, now)
			}
		}
	}
	return true
}

// dnsIndexEntry is a Device to drop from a zone's hash: apply is the
// application entry read for it, empty when it had none.
type dnsIndexEntry struct {
	node, apply string
}

// pruneDNSIndexEntries drops up to maximumDNSIndexPrune Devices from the
// zone's hash, and their application entries, only where the application
// entry is still what the count read: a Device that came back since keeps
// both. A failure leaves them for the next count.
func (client *Client) pruneDNSIndexEntries(ctx context.Context, zoneKey, applyKey string, entries []dnsIndexEntry) {
	if len(entries) == 0 || client.pruneDNSIndex == nil {
		return
	}
	_ = client.pruneDNSIndex(ctx, zoneKey, applyKey, entries[:min(len(entries), maximumDNSIndexPrune)])
}

// scanDNSZone reads one page of a zone's hash: its node IDs and the cursor
// of the next page, 0 after the last.
func (client *Client) scanDNSZone(ctx context.Context, key string, cursor uint64, count int) (
	[]string, uint64, error,
) {
	if client.loadDNSZone == nil {
		return nil, 0, ErrInvalidOptions
	}
	return client.loadDNSZone(ctx, key, cursor, count)
}

// decodeDNSApplication reads one application entry; false when it is
// missing or malformed.
func decodeDNSApplication(text string) (distribution.DNSApplication, bool) {
	parts := strings.Split(text, "|")
	if len(parts) != 7 {
		return distribution.DNSApplication{}, false
	}
	sent, err := decodeDNSSummary(parts[0], parts[1])
	if err != nil || sent.IsZero() {
		return distribution.DNSApplication{}, false
	}
	enforced, err := decodeDNSSummary(parts[2], parts[3])
	if err != nil {
		return distribution.DNSApplication{}, false
	}
	deliveredAt, deliveredErr := strconv.ParseInt(parts[5], 10, 64)
	seenAt, seenErr := strconv.ParseInt(parts[6], 10, 64)
	if deliveredErr != nil || seenErr != nil || deliveredAt <= 0 || seenAt <= 0 {
		return distribution.DNSApplication{}, false
	}
	switch parts[4] {
	case "", distribution.DNSReasonUserOff, distribution.DNSReasonApplyFailed:
	default:
		return distribution.DNSApplication{}, false
	}
	return distribution.DNSApplication{
		Sent: sent, Enforced: enforced, Reason: parts[4],
		DeliveredAt: time.UnixMilli(deliveredAt).UTC(), SeenAt: time.UnixMilli(seenAt).UTC(),
	}, true
}

// CountResolverHealth counts, for each resolver, the Devices of the Network
// whose resolver reported it in each state within DNSHealthStale.
func (client *Client) CountResolverHealth(ctx context.Context, networkID network.ID, resolvers []netip.AddrPort,
	now time.Time,
) ([]distribution.ResolverHealthCount, error) {
	if ctx == nil || client == nil || client.countDNSHealth == nil || !networkID.IsValid() ||
		len(resolvers) > maximumResolverCounts || now.IsZero() {
		return nil, ErrInvalidOptions
	}
	if len(resolvers) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(resolvers)*len(distribution.ResolverStates))
	for _, resolver := range resolvers {
		if !resolver.IsValid() || resolver.Port() == 0 {
			return nil, ErrInvalidOptions
		}
		for _, state := range distribution.ResolverStates {
			keys = append(keys, dnsHealthKey(networkID, resolver, state))
		}
	}
	startedAt := time.Now()
	values, err := client.countDNSHealth(ctx, keys, now.Add(-distribution.DNSHealthStale).UnixMilli())
	if err == nil && len(values) != len(keys) {
		err = errors.New("unexpected dns health count")
	}
	client.metrics.observeCommand(redisCommandLoadDNSIndex, startedAt, err)
	if err != nil {
		return nil, errors.Join(ErrLoadDNSIndex, err)
	}
	counts := make([]distribution.ResolverHealthCount, len(resolvers))
	for index, resolver := range resolvers {
		row := values[index*len(distribution.ResolverStates):]
		counts[index] = distribution.ResolverHealthCount{
			Resolver: resolver, OK: int(row[0]), Broken: int(row[1]), Stopped: int(row[2]),
			Refusing: int(row[3]), Idle: int(row[4]),
		}
	}
	return counts, nil
}
