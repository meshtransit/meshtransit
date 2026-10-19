package redis

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/policydigest"
)

const (
	deliveryKeyPrefix = "meshtransit:v1:delivery:node:"
	// sessionKeyPrefix indexes the current delivery session by node key, so
	// an enforcement report reaching any replica finds its Device. It shares
	// the delivery namespace and so the existing Redis ACL key pattern.
	sessionKeyPrefix = deliveryKeyPrefix + "session:"
	// deliveryTTL keeps the last delivery of an offline Device long enough to
	// answer "what does it still run"; every record or touch renews it.
	deliveryTTL = 30 * 24 * time.Hour
	// maximumDeliveryLoad bounds one read to one distribution page.
	maximumDeliveryLoad = distribution.MaximumObservationBatch
	deliveryFieldCount  = 21
	presenceField       = deliveryFieldCount - 1
)

var (
	// ErrRecordDelivery classifies a failed or malformed delivery record.
	ErrRecordDelivery = errors.New("redis: record delivery")
	// ErrLoadDeliveries classifies unavailable or corrupt delivery records.
	ErrLoadDeliveries = errors.New("redis: load deliveries")

	// A record never moves a Device backwards: an older session generation, or
	// a lower Network revision in the same generation, is ignored. A new
	// generation clears the enforcement report of the previous session.
	// Fields are cleared by writing empty values, so the script needs no
	// command beyond HGET, HSET and PEXPIRE.
	recordDeliveryScript = redisclient.NewScript(`
local stored_generation = redis.call('HGET', KEYS[1], 'generation')
local requested_generation = tonumber(ARGV[1])
local requested_revision = tonumber(ARGV[2])
if requested_generation == nil or requested_revision == nil then
    return -1
end
local same_generation = false
if stored_generation ~= false then
    local generation = tonumber(stored_generation)
    if generation == nil then
        return -1
    end
    if requested_generation < generation then
        return 0
    end
    if requested_generation == generation then
        same_generation = true
        local revision = tonumber(redis.call('HGET', KEYS[1], 'network_revision'))
        if revision ~= nil and requested_revision < revision then
            return 0
        end
    end
end
redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'network_revision', ARGV[2],
    'policy_revision', ARGV[3], 'delivered_at', ARGV[4], 'seen_at', ARGV[4],
    'filter_digest', ARGV[6], 'filter_grants', ARGV[7], 'peer_limit', ARGV[10],
    'route_digest', ARGV[11], 'route_entries', ARGV[12])
if not same_generation then
    redis.call('HSET', KEYS[1], 'enforced_digest', '', 'enforced_grants', '',
        'applied_at', '', 'reported_at', '', 'paths', '', 'connectivity', '',
        'enforced_route_digest', '', 'enforced_route_entries', '', 'route_health', '', 'route_health_at', '')
end
redis.call('PEXPIRE', KEYS[1], ARGV[5])
redis.call('HSET', KEYS[2], 'node_id', ARGV[8], 'generation', ARGV[1], 'machine', ARGV[9])
redis.call('PEXPIRE', KEYS[2], ARGV[5])
return 1
`)
	// An enforcement report is stored only for the session generation that
	// currently owns the delivery record.
	recordEnforcementScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then
    return 0
end
redis.call('HSET', KEYS[1], 'enforced_digest', ARGV[2], 'enforced_grants', ARGV[3],
    'applied_at', ARGV[4], 'reported_at', ARGV[5],
    'enforced_route_digest', ARGV[7], 'enforced_route_entries', ARGV[8])
redis.call('PEXPIRE', KEYS[1], ARGV[6])
return 1
`)
	// A router's Site health is stored only for the session generation that
	// currently owns the delivery record. A report that newly holds a failed
	// Site (ARGV[5] = '1' and other than the stored one) wakes the Site
	// election worker on channel ARGV[6], in the same step. The wakeup is a
	// hint: where the ACL does not allow the channel, the report is stored
	// all the same and the worker finds the Site at its next pass.
	recordRouteHealthScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then
    return 0
end
local previous = redis.call('HGET', KEYS[1], 'route_health')
redis.call('HSET', KEYS[1], 'route_health', ARGV[2], 'route_health_at', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
if ARGV[5] == '1' and previous ~= ARGV[2] then
    redis.pcall('PUBLISH', ARGV[6], ARGV[7])
end
return 1
`)
	// A path report is stored only for the session generation that
	// currently owns the delivery record.
	recordPathsScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then
    return 0
end
redis.call('HSET', KEYS[1], 'paths', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
`)
	// A connectivity report is stored only for the session generation that
	// currently owns the delivery record.
	recordConnectivityScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then
    return 0
end
redis.call('HSET', KEYS[1], 'connectivity', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
`)
	// A touch only refreshes the record of the same session generation.
	touchDeliveryScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then
    return 0
end
redis.call('HSET', KEYS[1], 'seen_at', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
`)
	// KEYS alternate delivery and presence keys; each pair yields twenty
	// fields (empty when absent) and whether a presence lease exists.
	loadDeliveriesScript = redisclient.NewScript(`
local result = {}
for index = 1, #KEYS, 2 do
    local fields = redis.call('HMGET', KEYS[index], 'generation', 'network_revision',
        'policy_revision', 'delivered_at', 'seen_at', 'filter_digest', 'filter_grants',
        'enforced_digest', 'enforced_grants', 'applied_at', 'reported_at', 'paths', 'connectivity',
        'peer_limit', 'route_digest', 'route_entries', 'enforced_route_digest', 'enforced_route_entries',
        'route_health', 'route_health_at')
    for field = 1, 20 do
        result[#result + 1] = fields[field] or ''
    end
    result[#result + 1] = tostring(redis.call('EXISTS', KEYS[index + 1]))
end
return result
`)
)

// deliveryRecord is one delivery as the record script stores it; an absent
// filter digest is an empty string.
type deliveryRecord struct {
	nodeID          string
	machine         string
	generation      int64
	networkRevision int64
	policyRevision  int64
	deliveredAt     int64
	filterDigest    string
	filterGrants    string
	peerLimit       string // "sent:authorized", empty when the map was not limited
	// routeDigest and routeEntries describe a router's served routes;
	// empty for a session that does not route.
	routeDigest, routeEntries string
}

// enforcementRecord is one enforcement report as its script stores it.
type enforcementRecord struct {
	generation int64
	digest     string
	grants     int64
	appliedAt  int64
	reportedAt int64
	// routeDigest and routeEntries are empty without a route digest.
	routeDigest, routeEntries string
}

type recordDeliveryFunc func(ctx context.Context, deliveryKey, sessionKey string, record deliveryRecord,
	ttl time.Duration) (int64, error)

type recordEnforcementFunc func(context.Context, string, enforcementRecord, time.Duration) (int64, error)

// loadSessionFunc reads node_id, generation and machine of a session index.
type loadSessionFunc func(context.Context, string) ([]any, error)

type touchDeliveryFunc func(context.Context, string, int64, int64, time.Duration) (int64, error)

type loadDeliveriesFunc func(context.Context, []string) ([]any, error)

var (
	_ mapsession.DeliveryRecorder    = (*Client)(nil)
	_ mapsession.EnforcementRecorder = (*Client)(nil)
	_ distribution.ObservationLoader = (*Client)(nil)
)

// RecordDelivery stores the last frame a Device received. It never moves a
// Device to an older revision.
func (client *Client) RecordDelivery(ctx context.Context, delivery mapsession.Delivery) error {
	if ctx == nil || client == nil || client.recordDelivery == nil || !delivery.IsValid() {
		return ErrInvalidOptions
	}
	record := deliveryRecord{
		nodeID:          delivery.NodeID.String(),
		machine:         hex.EncodeToString(delivery.MachineFingerprint[:]),
		generation:      delivery.SessionGeneration,
		networkRevision: delivery.NetworkRevision,
		policyRevision:  delivery.PolicyRevision,
		deliveredAt:     delivery.DeliveredAt.UnixMilli(),
	}
	if delivery.Filter.IsValid() {
		record.filterDigest = delivery.Filter.Digest().String()
		record.filterGrants = strconv.Itoa(delivery.Filter.Grants())
	}
	if delivery.Routes.IsValid() {
		record.routeDigest = delivery.Routes.Digest().String()
		record.routeEntries = strconv.Itoa(delivery.Routes.Entries())
	}
	if delivery.PeersAuthorized > delivery.PeersSent && delivery.PeersSent > 0 {
		record.peerLimit = strconv.Itoa(delivery.PeersSent) + ":" + strconv.Itoa(delivery.PeersAuthorized)
	}
	startedAt := time.Now()
	result, err := client.recordDelivery(ctx, deliveryKeyForNode(delivery.NodeID),
		sessionKeyForNodeKey(delivery.NodeKey), record, deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected delivery record result")
	}
	client.metrics.observeCommand(redisCommandRecordDelivery, startedAt, err)
	if err != nil {
		return errors.Join(ErrRecordDelivery, err)
	}
	return nil
}

// RecordEnforcement stores what a node reports it enforces against its
// current delivery session. It reports false when the node key has no
// current session, or the session belongs to another machine.
func (client *Client) RecordEnforcement(ctx context.Context, enforcement mapsession.Enforcement) (bool, error) {
	if ctx == nil || client == nil || client.recordEnforcement == nil || client.loadSession == nil ||
		!enforcement.IsValid() {
		return false, ErrInvalidOptions
	}
	startedAt := time.Now()
	stored, err := client.recordEnforcementForSession(ctx, enforcement)
	client.metrics.observeCommand(redisCommandRecordEnforcement, startedAt, err)
	if err != nil {
		return false, errors.Join(ErrRecordDelivery, err)
	}
	return stored, nil
}

func (client *Client) recordEnforcementForSession(ctx context.Context,
	enforcement mapsession.Enforcement) (bool, error) {
	fields, err := client.loadSession(ctx, sessionKeyForNodeKey(enforcement.NodeKey))
	if err != nil {
		return false, err
	}
	nodeID, generation, machine, found, err := decodeSession(fields)
	if err != nil || !found {
		return false, err
	}
	if machine != hex.EncodeToString(enforcement.MachineFingerprint[:]) {
		return false, nil
	}
	record := enforcementRecord{
		generation: generation,
		digest:     enforcement.Filter.Digest().String(),
		grants:     int64(enforcement.Filter.Grants()),
		appliedAt:  enforcement.AppliedAt.UnixMilli(),
		reportedAt: enforcement.ReportedAt.UnixMilli(),
	}
	if enforcement.Routes.IsValid() {
		record.routeDigest = enforcement.Routes.Digest().String()
		record.routeEntries = strconv.Itoa(enforcement.Routes.Entries())
	}
	result, err := client.recordEnforcement(ctx, deliveryKeyForNode(nodeID), record, deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected enforcement record result")
	}
	return result == 1, err
}

func decodeSession(fields []any) (node.ID, int64, string, bool, error) {
	if len(fields) != 3 {
		return node.ID{}, 0, "", false, errors.New("unexpected session index length")
	}
	values := make([]string, 3)
	for index, field := range fields {
		if field == nil {
			return node.ID{}, 0, "", false, nil
		}
		value, ok := field.(string)
		if !ok {
			return node.ID{}, 0, "", false, errors.New("unexpected session index field type")
		}
		values[index] = value
	}
	nodeID, err := node.ParseID(values[0])
	if err != nil {
		return node.ID{}, 0, "", false, errors.New("malformed session index")
	}
	generation, err := strconv.ParseInt(values[1], 10, 64)
	if err != nil || generation < 1 || len(values[2]) != hex.EncodedLen(32) {
		return node.ID{}, 0, "", false, errors.New("malformed session index")
	}
	return nodeID, generation, values[2], true, nil
}

// TouchDelivery refreshes when a Device was last seen on its current session.
func (client *Client) TouchDelivery(ctx context.Context, nodeID node.ID, sessionGeneration int64,
	seenAt time.Time) error {
	if ctx == nil || client == nil || client.touchDelivery == nil || !nodeID.IsValid() ||
		sessionGeneration < 1 || seenAt.IsZero() {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.touchDelivery(ctx, deliveryKeyForNode(nodeID), sessionGeneration, seenAt.UnixMilli(),
		deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected delivery touch result")
	}
	client.metrics.observeCommand(redisCommandTouchDelivery, startedAt, err)
	if err != nil {
		return errors.Join(ErrRecordDelivery, err)
	}
	return nil
}

// LoadObservations returns one observation per Device, in order, together
// with whether a presence lease is live.
func (client *Client) LoadObservations(ctx context.Context, ids []node.ID) ([]distribution.Observation, error) {
	if ctx == nil || client == nil || client.loadDeliveries == nil || len(ids) == 0 ||
		len(ids) > maximumDeliveryLoad {
		return nil, ErrInvalidOptions
	}
	keys := make([]string, 0, len(ids)*2)
	for _, id := range ids {
		if !id.IsValid() {
			return nil, ErrInvalidOptions
		}
		keys = append(keys, deliveryKeyForNode(id), presenceKeyForNode(id))
	}
	startedAt := time.Now()
	raw, err := client.loadDeliveries(ctx, keys)
	if err == nil {
		var observations []distribution.Observation
		observations, err = decodeObservations(raw, len(ids))
		if err == nil {
			client.metrics.observeCommand(redisCommandLoadDeliveries, startedAt, nil)
			return observations, nil
		}
	}
	client.metrics.observeCommand(redisCommandLoadDeliveries, startedAt, err)
	return nil, errors.Join(ErrLoadDeliveries, err)
}

func decodeObservations(raw []any, count int) ([]distribution.Observation, error) {
	if len(raw) != count*deliveryFieldCount {
		return nil, errors.New("unexpected delivery load length")
	}
	observations := make([]distribution.Observation, count)
	for index := range observations {
		fields := make([]string, deliveryFieldCount)
		for field := range fields {
			value, ok := raw[index*deliveryFieldCount+field].(string)
			if !ok {
				return nil, errors.New("unexpected delivery field type")
			}
			fields[field] = value
		}
		observation, err := decodeObservation(fields)
		if err != nil {
			return nil, err
		}
		observations[index] = observation
	}
	return observations, nil
}

// decodeObservation reads, in order: generation, network_revision,
// policy_revision, delivered_at, seen_at, filter_digest, filter_grants,
// enforced_digest, enforced_grants, applied_at, reported_at, paths,
// connectivity, peer_limit, route_digest, route_entries,
// enforced_route_digest, enforced_route_entries, route_health,
// route_health_at, presence.
func decodeObservation(fields []string) (distribution.Observation, error) {
	online := fields[presenceField] == "1"
	if fields[presenceField] != "0" && fields[presenceField] != "1" {
		return distribution.Observation{}, errors.New("unexpected presence flag")
	}
	if fields[0] == "" {
		for _, field := range fields[1:presenceField] {
			if field != "" {
				return distribution.Observation{}, errors.New("partial delivery record")
			}
		}
		return distribution.Observation{Online: online}, nil
	}
	numbers := make([]int64, 5)
	for index, field := range fields[:5] {
		value, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			return distribution.Observation{}, errors.New("malformed delivery record")
		}
		numbers[index] = value
	}
	filter, err := decodeFilterSummary(fields[5], fields[6])
	if err != nil {
		return distribution.Observation{}, err
	}
	enforced, err := decodeFilterSummary(fields[7], fields[8])
	if err != nil {
		return distribution.Observation{}, err
	}
	appliedAt, err := decodeOptionalTime(fields[9])
	if err != nil {
		return distribution.Observation{}, err
	}
	reportedAt, err := decodeOptionalTime(fields[10])
	if err != nil {
		return distribution.Observation{}, err
	}
	paths, err := decodePaths(fields[11])
	if err != nil {
		return distribution.Observation{}, err
	}
	connectivity, err := decodeConnectivity(fields[12])
	if err != nil {
		return distribution.Observation{}, err
	}
	peerLimit, err := decodePeerLimit(fields[13])
	if err != nil {
		return distribution.Observation{}, err
	}
	routes, err := decodeRouteSummary(fields[14], fields[15])
	if err != nil {
		return distribution.Observation{}, err
	}
	enforcedRoutes, err := decodeRouteSummary(fields[16], fields[17])
	if err != nil {
		return distribution.Observation{}, err
	}
	routeHealth, err := decodeRouteHealth(fields[18])
	if err != nil {
		return distribution.Observation{}, err
	}
	routeHealthAt, err := decodeOptionalTime(fields[19])
	if err != nil {
		return distribution.Observation{}, err
	}
	observation := distribution.Observation{
		Known:             true,
		SessionGeneration: numbers[0],
		NetworkRevision:   numbers[1],
		PolicyRevision:    numbers[2],
		DeliveredAt:       time.UnixMilli(numbers[3]).UTC(),
		SeenAt:            time.UnixMilli(numbers[4]).UTC(),
		Online:            online,
		Filter:            filter,
		Enforced:          enforced,
		AppliedAt:         appliedAt,
		ReportedAt:        reportedAt,
		Paths:             paths,
		Connectivity:      connectivity,
		PeerLimit:         peerLimit,
		Routes:            routes,
		EnforcedRoutes:    enforcedRoutes,
		RouteHealth:       routeHealth,
		RouteHealthAt:     routeHealthAt,
	}
	if !observation.IsValid() {
		return distribution.Observation{}, errors.New("inconsistent delivery record")
	}
	return observation, nil
}

// decodeFilterSummary reads a digest and grant count that are both present or
// both empty; records written before R1-69 have neither.
func decodeFilterSummary(digestText, grantsText string) (distribution.FilterSummary, error) {
	if digestText == "" && grantsText == "" {
		return distribution.FilterSummary{}, nil
	}
	digest, err := policydigest.Parse(digestText)
	if err != nil {
		return distribution.FilterSummary{}, errors.New("malformed filter digest")
	}
	grants, err := strconv.Atoi(grantsText)
	if err != nil || grants < 0 || grants > policydigest.MaximumGrants {
		return distribution.FilterSummary{}, errors.New("malformed filter grants")
	}
	return distribution.FilterSummary{Digest: digest, Grants: grants}, nil
}

// decodePeerLimit reads "sent:authorized"; empty means not limited (and
// records written before the peer limit have no field).
func decodePeerLimit(text string) (distribution.PeerLimit, error) {
	if text == "" {
		return distribution.PeerLimit{}, nil
	}
	sentText, authorizedText, found := strings.Cut(text, ":")
	sent, sentErr := strconv.Atoi(sentText)
	authorized, authorizedErr := strconv.Atoi(authorizedText)
	limit := distribution.PeerLimit{Sent: sent, Authorized: authorized}
	if !found || sentErr != nil || authorizedErr != nil || !limit.IsValid() {
		return distribution.PeerLimit{}, errors.New("malformed peer limit")
	}
	return limit, nil
}

func decodeOptionalTime(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value <= 0 {
		return time.Time{}, errors.New("malformed enforcement time")
	}
	return time.UnixMilli(value).UTC(), nil
}

func deliveryKeyForNode(nodeID node.ID) string { return deliveryKeyPrefix + nodeID.String() }

func sessionKeyForNodeKey(nodeKey node.Key) string {
	fingerprint := nodeKey.Fingerprint()
	return sessionKeyPrefix + hex.EncodeToString(fingerprint[:])
}
