package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

const (
	// siteSelectionPrefix keys, per Site reference, which router each node
	// reported using for it: field node public ID, value router|via|ms.
	siteSelectionPrefix = "meshtransit:v1:site-selection:"
	// siteSelectionTTL drops the hash of a Site nobody reports on any more.
	siteSelectionTTL = 24 * time.Hour
	// maximumRouteSelectionBytes bounds one stored selection.
	maximumRouteSelectionBytes = 160 << 10
	// maximumSiteSelectionEntries bounds one Site's count: past it the
	// count is not read.
	maximumSiteSelectionEntries = 100_000
	// siteSelectionPruneAfter is how old an entry a Site's read deletes: a
	// node that left the Site, ended its session or was removed, so a Site's
	// hash holds the nodes that reported lately, not every node it ever had.
	siteSelectionPruneAfter = 10 * time.Minute
	// maximumSiteSelectionPrune bounds the fields one read deletes.
	maximumSiteSelectionPrune = 1_000
)

// recordRouteSelectionScript stores a node's Site routers for the session
// generation that owns the delivery record, sets them in each Site's hash
// and removes the node from the hashes of Sites it no longer reports. The
// Site keys are not in KEYS: Core runs on a single Redis node
// (docs/operations/deployment.md), and the references are those of the
// routes the session was sent (mapsession.SelectedOnly), never the node's
// own text.
var recordRouteSelectionScript = redisclient.NewScript(`
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then
    return 0
end
local previous = redis.call('HGET', KEYS[1], 'route_selection')
redis.call('HSET', KEYS[1], 'route_selection', ARGV[2], 'route_selection_at', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
local kept = {}
for _, row in ipairs(cjson.decode(ARGV[2])) do
    kept[row[1]] = true
    local key = ARGV[6] .. row[1]
    redis.call('HSET', key, ARGV[5], row[2] .. '|' .. row[3] .. '|' .. ARGV[3])
    redis.call('PEXPIRE', key, ARGV[7])
end
if previous and previous ~= '' then
    local ok, rows = pcall(cjson.decode, previous)
    if ok then
        for _, row in ipairs(rows) do
            if not kept[row[1]] then
                redis.call('HDEL', ARGV[6] .. row[1], ARGV[5])
            end
        end
    end
end
return 1
`)

var selectionVia = map[mapsession.RouteSelectionReason]string{
	mapsession.RouteSelectionPrimary:       distribution.ViaPrimary,
	mapsession.RouteSelectionLocalFailover: distribution.ViaLocalFailover,
	mapsession.RouteSelectionNone:          distribution.ViaNone,
}

// RecordRouteSelection stores a node's Site routers for its current
// session, and counts it in each Site's routers.
func (client *Client) RecordRouteSelection(ctx context.Context, selection mapsession.RouteSelection) (bool, error) {
	if ctx == nil || client == nil || client.recordRouteSelection == nil || client.loadSession == nil ||
		!selection.NodeKey.IsValid() || selection.MachineFingerprint == [32]byte{} || selection.ReportedAt.IsZero() ||
		!mapsession.ValidSiteSelection(selection.Sites) {
		return false, ErrInvalidOptions
	}
	rows := make([][3]string, 0, len(selection.Sites))
	for _, site := range selection.Sites {
		router := ""
		if site.Router != (node.ID{}) {
			router = site.Router.String()
		}
		rows = append(rows, [3]string{site.Ref, router, selectionVia[site.Reason]})
	}
	encoded, err := json.Marshal(rows)
	if err != nil || len(encoded) > maximumRouteSelectionBytes {
		return false, ErrInvalidOptions
	}
	startedAt := time.Now()
	stored, err := client.recordRouteSelectionForSession(ctx, selection, string(encoded))
	client.metrics.observeCommand(redisCommandRecordRouteSelection, startedAt, err)
	if err != nil {
		return false, errors.Join(ErrRecordDelivery, err)
	}
	return stored, nil
}

func (client *Client) recordRouteSelectionForSession(ctx context.Context, selection mapsession.RouteSelection,
	encoded string,
) (bool, error) {
	fields, err := client.loadSession(ctx, sessionKeyForNodeKey(selection.NodeKey))
	if err != nil {
		return false, err
	}
	nodeID, generation, machine, found, err := decodeSession(fields)
	if err != nil || !found || machine != hex.EncodeToString(selection.MachineFingerprint[:]) {
		return false, err
	}
	result, err := client.recordRouteSelection(ctx, deliveryKeyForNode(nodeID), generation, encoded,
		selection.ReportedAt.UnixMilli(), nodeID.String())
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected route selection record result")
	}
	return result == 1, err
}

// decodeRouteSelection reads [[ref, router, via], ...].
func decodeRouteSelection(text string) ([]distribution.SiteRouter, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > maximumRouteSelectionBytes {
		return nil, errors.New("route selection is too large")
	}
	var rows [][3]string
	if err := json.Unmarshal([]byte(text), &rows); err != nil || len(rows) > mapsession.MaximumRouteHealthSites {
		return nil, errors.New("malformed route selection")
	}
	sites := make([]distribution.SiteRouter, 0, len(rows))
	for _, row := range rows {
		sites = append(sites, distribution.SiteRouter{Ref: row[0], Router: row[1], Via: row[2]})
	}
	return sites, nil
}

// CountSiteRouters counts, per router (Device public ID), the nodes that
// reported using it for the Site within distribution.RouteSelectionStale of
// now, and how many of those chose it themselves (local failover).
func (client *Client) CountSiteRouters(ctx context.Context, siteRef string, now time.Time) (
	map[string]distribution.RouterUse, error,
) {
	if ctx == nil || client == nil || client.loadSiteSelection == nil || siteRef == "" {
		return nil, ErrInvalidOptions
	}
	key := siteSelectionPrefix + siteRef
	startedAt := time.Now()
	entries, err := client.loadSiteSelection(ctx, key, maximumSiteSelectionEntries)
	client.metrics.observeCommand(redisCommandLoadSiteSelection, startedAt, err)
	if err != nil {
		return nil, err
	}
	uses := map[string]distribution.RouterUse{}
	var expired []string
	for field, value := range entries {
		router, rest, cut := strings.Cut(value, "|")
		via, at, cutAt := strings.Cut(rest, "|")
		millis, parseErr := strconv.ParseInt(at, 10, 64)
		age := now.Sub(time.UnixMilli(millis))
		if !cut || !cutAt || parseErr != nil || age > siteSelectionPruneAfter {
			if len(expired) < maximumSiteSelectionPrune {
				expired = append(expired, field)
			}
			continue
		}
		if router == "" || via == distribution.ViaNone || age > distribution.RouteSelectionStale {
			continue
		}
		use := uses[router]
		use.Clients++
		if via == distribution.ViaLocalFailover {
			use.LocalFailover++
		}
		uses[router] = use
	}
	if len(expired) > 0 && client.pruneSiteSelection != nil {
		// Best effort: a failure leaves them for the next read.
		_ = client.pruneSiteSelection(ctx, key, expired)
	}
	return uses, nil
}
