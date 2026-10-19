package mapsession

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// A Network's subnet routes (schema 191), read with its policy.
const (
	routesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_sites_v1(integer)'), 'EXECUTE'), FALSE)
    AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_site_routers_v1(integer)'), 'EXECUTE'), FALSE)
    AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_route_rules_v1(bigint,integer)'), 'EXECUTE'), FALSE)`
	loadNetworkSitesSQL = `SELECT site_id, site_public_id::TEXT, prefixes, masquerade,
    probe_addresses, probe_kinds, probe_ports
FROM mesh_ops.load_map_network_sites_v1($1::INTEGER)`
	electionGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_sites_v2(integer)'), 'EXECUTE'), FALSE)`
	loadElectedNetworkSitesSQL = `SELECT site_id, site_public_id::TEXT, prefixes, masquerade,
    probe_addresses, probe_kinds, probe_ports, elected, COALESCE(primary_device_id, 0)
FROM mesh_ops.load_map_network_sites_v2($1::INTEGER)`
	loadNetworkSiteRoutersSQL = `SELECT site_id, device_id, device_public_id::TEXT, priority, router_state,
    workspace_owned, offered
FROM mesh_ops.load_map_network_site_routers_v1($1::INTEGER)`
	loadNetworkRouteRulesSQL = `SELECT access_rule_public_id::TEXT, source_kind, source_ref, site_id, prefixes,
    protocol, port_first, port_last
FROM mesh_ops.load_map_network_route_rules_v1($1::BIGINT, $2::INTEGER)`

	// Technical ceilings (schema 188, 189): Sites per Network, routers per
	// Site and rules per release.
	maximumNetworkSites       = appmapsession.MaximumRouteSites
	maximumNetworkSiteRouters = 32 * appmapsession.MaximumRouteSites
	maximumNetworkRouteRules  = 10_000
)

// readNetworkRoutes adds the Network's Sites, routers and rules to Sites to
// params, in the inventory transaction. Before schema 191 is installed there
// are none: maps carry no routes rather than failing.
func readNetworkRoutes(ctx context.Context, transaction databaseTransaction, params *appmapsession.NetworkPolicyParams) error {
	granted, err := functionGranted(ctx, transaction, routesGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check route readers: %w", err))
	}
	if !granted {
		return nil
	}
	elected, err := functionGranted(ctx, transaction, electionGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check elected route readers: %w", err))
	}
	if params.Sites, err = readNetworkSites(ctx, transaction, elected); err != nil {
		return err
	}
	if len(params.Sites) == 0 {
		return nil
	}
	if params.RouteRouters, err = readNetworkSiteRouters(ctx, transaction); err != nil {
		return err
	}
	if params.ReleaseActive {
		if params.RouteRules, err = readNetworkRouteRules(ctx, transaction, params.Revision); err != nil {
			return err
		}
	}
	return nil
}

// readNetworkSites reads the Sites with their elected primaries once schema
// 193 is installed, and without before.
func readNetworkSites(ctx context.Context, transaction databaseTransaction, elected bool) ([]appmapsession.RouteSite, error) {
	query := loadNetworkSitesSQL
	if elected {
		query = loadElectedNetworkSitesSQL
	}
	rows, err := transaction.Query(ctx, query, maximumNetworkSites+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network sites: %w", nonNil(err)))
	}
	defer rows.Close()
	var sites []appmapsession.RouteSite
	for rows.Next() {
		if len(sites) == maximumNetworkSites {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var site appmapsession.RouteSite
		var addresses []netip.Prefix
		var kinds []string
		var ports []int32
		targets := []any{&site.Site, &site.Ref, &site.Prefixes, &site.Masquerade, &addresses, &kinds, &ports}
		if elected {
			targets = append(targets, &site.Elected, &site.Primary)
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network site: %w", err))
		}
		if len(addresses) != len(kinds) || len(addresses) != len(ports) || site.Primary < 0 ||
			(!site.Elected && site.Primary != 0) {
			return nil, ErrSnapshotEvidence
		}
		for index, address := range addresses {
			port, tcp := ports[index], kinds[index] == "tcp"
			if port < 0 || port > 65535 || (kinds[index] != "icmp" && !tcp) {
				return nil, ErrSnapshotEvidence
			}
			// Site writes validate probes; one a node would refuse is dropped
			// rather than sent (mtcp-v1 §7.6).
			inside := slices.ContainsFunc(site.Prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(address.Addr()) })
			if !inside || tcp != (port != 0) {
				continue
			}
			site.Probes = append(site.Probes, appmapsession.RouteProbe{Address: address.Addr(), TCP: tcp,
				Port: uint16(port)})
		}
		sites = append(sites, site)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network sites: %w", err))
	}
	return sites, nil
}

func readNetworkSiteRouters(ctx context.Context, transaction databaseTransaction) ([]appmapsession.RouteRouter, error) {
	rows, err := transaction.Query(ctx, loadNetworkSiteRoutersSQL, maximumNetworkSiteRouters+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network site routers: %w", nonNil(err)))
	}
	defer rows.Close()
	var routers []appmapsession.RouteRouter
	for rows.Next() {
		if len(routers) == maximumNetworkSiteRouters {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var router appmapsession.RouteRouter
		var publicID, state string
		var priority int32
		if err := rows.Scan(&router.Site, &router.Device, &publicID, &priority, &state, &router.WorkspaceOwned,
			&router.Offered); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network site router: %w", err))
		}
		if router.NodeID, err = node.ParseID(publicID); err != nil || (state != "active" && state != "draining") {
			return nil, ErrSnapshotEvidence
		}
		router.Priority, router.Active = int(priority), state == "active"
		routers = append(routers, router)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network site routers: %w", err))
	}
	return routers, nil
}

func readNetworkRouteRules(ctx context.Context, transaction databaseTransaction, revision int64) (
	[]appmapsession.RouteRule, error) {
	rows, err := transaction.Query(ctx, loadNetworkRouteRulesSQL, revision, maximumNetworkRouteRules+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network route rules: %w", nonNil(err)))
	}
	defer rows.Close()
	var rules []appmapsession.RouteRule
	for rows.Next() {
		if len(rules) == maximumNetworkRouteRules {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var rule appmapsession.RouteRule
		var ruleID, sourceKind, protocol string
		var first, last []int32
		if err := rows.Scan(&ruleID, &sourceKind, &rule.SourceRef, &rule.Site, &rule.Prefixes, &protocol,
			&first, &last); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network route rule: %w", err))
		}
		if rule.ID, err = policy.ParseRuleID(ruleID); err != nil {
			return nil, ErrSnapshotEvidence
		}
		if rule.Protocol, err = protocolFromText(protocol); err != nil {
			return nil, err
		}
		if rule.Ports, err = portRanges(first, last); err != nil {
			return nil, err
		}
		rule.SourceKind = selectorKindFromText(sourceKind)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network route rules: %w", err))
	}
	return rules, nil
}
