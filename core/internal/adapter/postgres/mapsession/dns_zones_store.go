package mapsession

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/internet"
)

// A Network's DNS zones (schema 214), read with its policy.
const (
	dnsZonesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_dns_zones_v1(integer)'), 'EXECUTE'), FALSE)
    AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_dns_resolvers_v1(integer)'), 'EXECUTE'), FALSE)`
	loadNetworkDNSZonesSQL = `SELECT zone_id, domain, failure_mode, group_ids, search_position
FROM mesh_ops.load_map_network_dns_zones_v1($1::INTEGER)`
	loadNetworkDNSResolversSQL = `SELECT zone_id, resolver_position, device_id, device_public_id, address, port,
    eligible
FROM mesh_ops.load_map_network_dns_resolvers_v1($1::INTEGER)`

	// Technical ceilings: zones of one Network (200 forward zones and the
	// root) and their resolvers.
	maximumNetworkDNSZones     = appmapsession.MaximumDNSZones
	maximumNetworkDNSResolvers = appmapsession.MaximumDNSZones * appmapsession.MaximumDNSZoneResolvers
)

// readNetworkDNSZones adds the Network's DNS zones to params, in the
// inventory transaction. Before schema 214 is installed there are none: maps
// carry no zones rather than failing.
func readNetworkDNSZones(ctx context.Context, transaction databaseTransaction,
	params *appmapsession.NetworkPolicyParams) error {
	granted, err := functionGranted(ctx, transaction, dnsZonesGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check DNS zone readers: %w", err))
	}
	if !granted {
		return nil
	}
	zones, err := readNetworkDNSZoneRows(ctx, transaction)
	if err != nil || len(zones) == 0 {
		return err
	}
	if err := readNetworkDNSResolvers(ctx, transaction, zones); err != nil {
		return err
	}
	params.DNSZones = zones
	return nil
}

func readNetworkDNSZoneRows(ctx context.Context, transaction databaseTransaction) ([]appmapsession.DNSZone, error) {
	rows, err := transaction.Query(ctx, loadNetworkDNSZonesSQL, maximumNetworkDNSZones+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network DNS zones: %w", nonNil(err)))
	}
	defer rows.Close()
	var zones []appmapsession.DNSZone
	for rows.Next() {
		if len(zones) == maximumNetworkDNSZones {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var zone appmapsession.DNSZone
		var failureMode string
		var position int32
		if err := rows.Scan(&zone.Zone, &zone.Domain, &failureMode, &zone.Groups, &position); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network DNS zone: %w", err))
		}
		if failureMode != "open" && failureMode != "closed" {
			return nil, ErrSnapshotEvidence
		}
		zone.FailOpen, zone.SearchPosition = failureMode == "open", int(position)
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network DNS zones: %w", err))
	}
	return zones, nil
}

// readNetworkDNSResolvers adds each zone's resolvers in order. A resolver of
// a zone the first read did not see (a later commit cannot appear in the
// same transaction) is evidence of a broken read.
func readNetworkDNSResolvers(ctx context.Context, transaction databaseTransaction,
	zones []appmapsession.DNSZone) error {
	rows, err := transaction.Query(ctx, loadNetworkDNSResolversSQL, maximumNetworkDNSResolvers+1)
	if err != nil || rows == nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("read network DNS resolvers: %w", nonNil(err)))
	}
	defer rows.Close()
	index := make(map[int64]int, len(zones))
	for position, zone := range zones {
		index[zone.Zone] = position
	}
	read := 0
	last := make(map[int64]int32, len(zones)) // each zone's last resolver position read
	for rows.Next() {
		if read == maximumNetworkDNSResolvers {
			return errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		read++
		var zoneID, device int64
		var resolverPosition, port int32
		var publicID, address string
		var resolver appmapsession.DNSZoneResolver
		if err := rows.Scan(&zoneID, &resolverPosition, &device, &publicID, &address, &port,
			&resolver.Eligible); err != nil {
			return errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network DNS resolver: %w", err))
		}
		position, known := index[zoneID]
		if !known || port < 1 || port > 65535 || resolverPosition != last[zoneID]+1 {
			return ErrSnapshotEvidence
		}
		last[zoneID] = resolverPosition
		resolver.Device, resolver.Port = device, uint16(port)
		switch {
		case address != "" && publicID == "":
			if resolver.Address, err = netip.ParseAddr(address); err != nil {
				return ErrSnapshotEvidence
			}
			// Zone writes keep only Internet addresses on port 53; one a
			// map would refuse is dropped, its zone kept (unavailable when
			// nothing is left), rather than failing every map of the
			// Network.
			if !internet.Contains(resolver.Address) || port != 53 {
				continue
			}
		case address == "" && publicID != "":
			if resolver.NodeID, err = node.ParseID(publicID); err != nil {
				return ErrSnapshotEvidence
			}
		default:
			return ErrSnapshotEvidence
		}
		zones[position].Resolvers = append(zones[position].Resolvers, resolver)
	}
	if err := rows.Err(); err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network DNS resolvers: %w", err))
	}
	return nil
}
