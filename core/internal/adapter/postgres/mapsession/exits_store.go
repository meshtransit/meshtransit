package mapsession

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/shared/internet"
)

// A Network's Exit Pools (schema 205), read with its policy.
const (
	exitsGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_exit_pools_v1(integer)'), 'EXECUTE'), FALSE)
    AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_exit_nodes_v1(integer)'), 'EXECUTE'), FALSE)
    AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_exit_rules_v1(bigint,integer)'), 'EXECUTE'), FALSE)`
	loadNetworkExitPoolsSQL = `SELECT pool_id, pool_public_id::TEXT, pool_name, smtp_allowed, conntrack_per_consumer,
    dns_upstreams, probe_addresses, probe_ports, elected, COALESCE(primary_device_id, 0)
FROM mesh_ops.load_map_network_exit_pools_v1($1::INTEGER)`
	loadNetworkExitNodesSQL = `SELECT pool_id, device_id, device_public_id::TEXT, priority, node_state,
    workspace_owned, offered
FROM mesh_ops.load_map_network_exit_nodes_v1($1::INTEGER)`
	loadNetworkExitRulesSQL = `SELECT access_rule_public_id::TEXT, source_kind, source_ref, pool_id, protocol,
    port_first, port_last
FROM mesh_ops.load_map_network_exit_rules_v1($1::BIGINT, $2::INTEGER)`

	// Technical ceilings (schema 201): pools per Network and exit nodes per
	// pool; rules per release as for Sites.
	maximumNetworkExitPools = appmapsession.MaximumExitPools
	maximumNetworkExitNodes = appmapsession.MaximumExitPools * appmapsession.MaximumExitCandidates
	maximumNetworkExitRules = maximumNetworkRouteRules
)

// readNetworkExits adds the Network's Exit Pools, exit nodes and rules to
// pools to params, in the inventory transaction. Before schema 205 is
// installed there are none: maps carry no pools rather than failing.
func readNetworkExits(ctx context.Context, transaction databaseTransaction, params *appmapsession.NetworkPolicyParams) error {
	granted, err := functionGranted(ctx, transaction, exitsGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check exit readers: %w", err))
	}
	if !granted {
		return nil
	}
	if params.ExitPools, err = readNetworkExitPools(ctx, transaction); err != nil {
		return err
	}
	if len(params.ExitPools) == 0 {
		return nil
	}
	if params.ExitNodes, err = readNetworkExitNodes(ctx, transaction); err != nil {
		return err
	}
	if params.ReleaseActive {
		if params.ExitRules, err = readNetworkExitRules(ctx, transaction, params.Revision); err != nil {
			return err
		}
	}
	return nil
}

func readNetworkExitPools(ctx context.Context, transaction databaseTransaction) ([]appmapsession.ExitPool, error) {
	rows, err := transaction.Query(ctx, loadNetworkExitPoolsSQL, maximumNetworkExitPools+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network exit pools: %w", nonNil(err)))
	}
	defer rows.Close()
	var pools []appmapsession.ExitPool
	for rows.Next() {
		if len(pools) == maximumNetworkExitPools {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var pool appmapsession.ExitPool
		var conntrack int32
		var upstreams, addresses []netip.Prefix
		var ports []int32
		if err := rows.Scan(&pool.Pool, &pool.Ref, &pool.Name, &pool.SMTPAllowed, &conntrack, &upstreams,
			&addresses, &ports, &pool.Elected, &pool.Primary); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network exit pool: %w", err))
		}
		if len(addresses) != len(ports) || len(upstreams) > appmapsession.MaximumExitUpstreams ||
			len(addresses) > appmapsession.MaximumExitProbes || conntrack <= 0 || pool.Primary < 0 ||
			(!pool.Elected && pool.Primary != 0) {
			return nil, ErrSnapshotEvidence
		}
		pool.ConntrackPerConsumer = int(conntrack)
		// Pool writes keep only Internet addresses; one a node would refuse
		// is dropped rather than sent (mtcp-v1 §7.7).
		for _, upstream := range upstreams {
			if address := upstream.Addr().Unmap(); upstream.IsSingleIP() && internet.Contains(address) {
				pool.DNSUpstreams = append(pool.DNSUpstreams, address)
			}
		}
		for index, address := range addresses {
			port, probe := ports[index], address.Addr().Unmap()
			if port < 1 || port > 65535 || !address.IsSingleIP() || !internet.Contains(probe) {
				continue
			}
			pool.Probes = append(pool.Probes, appmapsession.ExitProbe{Address: probe, Port: uint16(port)})
		}
		pools = append(pools, pool)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network exit pools: %w", err))
	}
	return pools, nil
}

func readNetworkExitNodes(ctx context.Context, transaction databaseTransaction) ([]appmapsession.ExitNode, error) {
	rows, err := transaction.Query(ctx, loadNetworkExitNodesSQL, maximumNetworkExitNodes+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network exit nodes: %w", nonNil(err)))
	}
	defer rows.Close()
	var nodes []appmapsession.ExitNode
	for rows.Next() {
		if len(nodes) == maximumNetworkExitNodes {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var exitNode appmapsession.ExitNode
		var publicID, state string
		var priority int32
		if err := rows.Scan(&exitNode.Pool, &exitNode.Device, &publicID, &priority, &state,
			&exitNode.WorkspaceOwned, &exitNode.Offered); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network exit node: %w", err))
		}
		if exitNode.NodeID, err = node.ParseID(publicID); err != nil || (state != "active" && state != "draining") {
			return nil, ErrSnapshotEvidence
		}
		exitNode.Priority, exitNode.Active = int(priority), state == "active"
		nodes = append(nodes, exitNode)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network exit nodes: %w", err))
	}
	return nodes, nil
}

func readNetworkExitRules(ctx context.Context, transaction databaseTransaction, revision int64) (
	[]appmapsession.ExitRule, error) {
	rows, err := transaction.Query(ctx, loadNetworkExitRulesSQL, revision, maximumNetworkExitRules+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network exit rules: %w", nonNil(err)))
	}
	defer rows.Close()
	var rules []appmapsession.ExitRule
	for rows.Next() {
		if len(rules) == maximumNetworkExitRules {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var rule appmapsession.ExitRule
		var ruleID, sourceKind, protocol string
		var first, last []int32
		if err := rows.Scan(&ruleID, &sourceKind, &rule.SourceRef, &rule.Pool, &protocol, &first, &last); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network exit rule: %w", err))
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
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network exit rules: %w", err))
	}
	return rules, nil
}
