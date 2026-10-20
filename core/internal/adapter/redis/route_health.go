package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/policydigest"
	"meshtransit.net/shared/routedigest"
)

var _ mapsession.RouteHealthRecorder = (*Client)(nil)

// maximumRouteHealthBytes bounds one stored health set: 1,024 Sites of a
// 64-byte reference and code.
const maximumRouteHealthBytes = 160 << 10

// routeHealthStates names the stored states.
var routeHealthStates = map[mapsession.RouteHealthState]string{
	mapsession.RouteHealthOK:       distribution.SiteHealthOK,
	mapsession.RouteHealthDegraded: distribution.SiteHealthDegraded,
	mapsession.RouteHealthFailed:   distribution.SiteHealthFailed,
}

// RecordRouteHealth stores a router's Site health against its current
// delivery session. It reports false when the node key has no current
// session, or the session belongs to another machine.
func (client *Client) RecordRouteHealth(ctx context.Context, health mapsession.RouteHealth) (bool, error) {
	if ctx == nil || client == nil || client.recordRouteHealth == nil || client.loadSession == nil ||
		!health.NodeKey.IsValid() || health.MachineFingerprint == [32]byte{} || health.ReportedAt.IsZero() ||
		!mapsession.ValidSiteHealth(health.Sites) || (health.Exit != nil && !mapsession.ValidExitHealth(*health.Exit)) {
		return false, ErrInvalidOptions
	}
	encoded, err := encodeRouteHealth(health.Sites)
	if err != nil {
		return false, errors.Join(ErrInvalidOptions, err)
	}
	exit, err := encodeExitHealth(health.Exit)
	if err != nil {
		return false, errors.Join(ErrInvalidOptions, err)
	}
	startedAt := time.Now()
	stored, err := client.recordRouteHealthForSession(ctx, health, encoded, exit)
	client.metrics.observeCommand(redisCommandRecordRouteHealth, startedAt, err)
	if err != nil {
		return false, errors.Join(ErrRecordDelivery, err)
	}
	return stored, nil
}

func (client *Client) recordRouteHealthForSession(ctx context.Context, health mapsession.RouteHealth,
	encoded, exit string,
) (bool, error) {
	fields, err := client.loadSession(ctx, sessionKeyForNodeKey(health.NodeKey))
	if err != nil {
		return false, err
	}
	nodeID, generation, machine, found, err := decodeSession(fields)
	if err != nil || !found || machine != hex.EncodeToString(health.MachineFingerprint[:]) {
		return false, err
	}
	failed := slices.ContainsFunc(health.Sites, func(site mapsession.SiteHealth) bool {
		return site.State == mapsession.RouteHealthFailed
	})
	result, err := client.recordRouteHealth(ctx, deliveryKeyForNode(nodeID), generation, encoded,
		health.ReportedAt.UnixMilli(), deliveryTTL, failed, exit)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected route health record result")
	}
	return result == 1, err
}

// encodeRouteHealth writes Sites as [[ref, state, code], ...].
func encodeRouteHealth(sites []mapsession.SiteHealth) (string, error) {
	rows := make([][3]string, 0, len(sites))
	for _, site := range sites {
		rows = append(rows, [3]string{site.Ref, routeHealthStates[site.State], site.Code})
	}
	encoded, err := json.Marshal(rows)
	if err != nil || len(encoded) > maximumRouteHealthBytes {
		return "", errors.New("route health does not fit")
	}
	return string(encoded), nil
}

// decodeRouteHealth reads what encodeRouteHealth wrote; empty is none.
func decodeRouteHealth(text string) ([]distribution.SiteHealth, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > maximumRouteHealthBytes {
		return nil, errors.New("route health is too large")
	}
	var rows [][3]string
	if err := json.Unmarshal([]byte(text), &rows); err != nil || len(rows) > mapsession.MaximumRouteHealthSites {
		return nil, errors.New("malformed route health")
	}
	sites := make([]distribution.SiteHealth, 0, len(rows))
	for _, row := range rows {
		if row[0] == "" || row[2] == "" || (row[1] != distribution.SiteHealthOK &&
			row[1] != distribution.SiteHealthDegraded && row[1] != distribution.SiteHealthFailed) {
			return nil, errors.New("malformed route health")
		}
		sites = append(sites, distribution.SiteHealth{Ref: row[0], State: row[1], Code: row[2]})
	}
	return sites, nil
}

// exitFamilies names the stored families; unknown families are stored
// empty.
var exitFamilies = map[mapsession.ExitFamilies]string{
	mapsession.ExitFamiliesUnknown: "",
	mapsession.ExitFamiliesV4:      distribution.ExitFamiliesV4,
	mapsession.ExitFamiliesV6:      distribution.ExitFamiliesV6,
	mapsession.ExitFamiliesBoth:    distribution.ExitFamiliesBoth,
}

// encodeExitHealth writes an exit node's pool health as [ref, state, code,
// families]; empty when it reported none.
func encodeExitHealth(health *mapsession.ExitHealth) (string, error) {
	if health == nil {
		return "", nil
	}
	encoded, err := json.Marshal([4]string{health.Ref, routeHealthStates[health.State], health.Code,
		exitFamilies[health.Families]})
	if err != nil {
		return "", errors.New("exit health does not fit")
	}
	return string(encoded), nil
}

// decodeExitHealth reads what encodeExitHealth wrote; empty is none.
func decodeExitHealth(text string) (*distribution.ExitHealth, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > 512 {
		return nil, errors.New("exit health is too large")
	}
	var row [4]string
	if err := json.Unmarshal([]byte(text), &row); err != nil {
		return nil, errors.New("malformed exit health")
	}
	health := distribution.ExitHealth{Ref: row[0], State: row[1], Code: row[2], Families: row[3]}
	if !health.IsValid() {
		return nil, errors.New("malformed exit health")
	}
	return &health, nil
}

// decodeRouteSummary reads a route digest and entry count that are both
// present or both empty.
func decodeRouteSummary(digestText, entriesText string) (distribution.RouteSummary, error) {
	if digestText == "" && entriesText == "" {
		return distribution.RouteSummary{}, nil
	}
	digest, err := policydigest.Parse(digestText)
	if err != nil {
		return distribution.RouteSummary{}, errors.New("malformed route digest")
	}
	entries, err := strconv.Atoi(entriesText)
	if err != nil || entries < 0 || entries > routedigest.MaximumEntries {
		return distribution.RouteSummary{}, errors.New("malformed route entries")
	}
	return distribution.RouteSummary{Digest: digest, Entries: entries}, nil
}
