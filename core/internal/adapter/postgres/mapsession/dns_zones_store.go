package mapsession

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/sharing"
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

	// Schema 216: zones of every kind and the names they hold.
	dnsNamesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_dns_zones_v2(integer)'), 'EXECUTE'), FALSE)
    AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_dns_names_v1(integer)'), 'EXECUTE'), FALSE)`
	loadNetworkDNSZonesV2SQL = `SELECT zone_id, domain, other_names, failure_mode, group_ids, search_position
FROM mesh_ops.load_map_network_dns_zones_v2($1::INTEGER)`
	loadNetworkDNSNamesSQL = `SELECT zone_id, fqdn, kind, device_id, device_public_id, addresses, cname, ''
FROM mesh_ops.load_map_network_dns_names_v1($1::INTEGER)`

	// Schema 219: the names that point at a share too.
	dnsShareNamesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_dns_names_v2(integer)'), 'EXECUTE'), FALSE)`
	loadNetworkDNSShareNamesSQL = `SELECT zone_id, fqdn, kind, device_id, device_public_id, addresses, cname,
    share_public_id
FROM mesh_ops.load_map_network_dns_names_v2($1::INTEGER)`

	// Technical ceilings: zones of one Network (200 forward zones and the
	// root) and their resolvers.
	maximumNetworkDNSZones     = appmapsession.MaximumDNSZones
	maximumNetworkDNSResolvers = appmapsession.MaximumDNSZones * appmapsession.MaximumDNSZoneResolvers
	maximumNetworkDNSNames     = appmapsession.MaximumDNSNames
)

var dnsOtherNames = map[string]appmapsession.DNSOtherNames{
	"forward": appmapsession.DNSOtherForward, "nxdomain": appmapsession.DNSOtherNXDomain,
	"host": appmapsession.DNSOtherHost,
}

// readNetworkDNSZones adds the Network's DNS zones, and from schema 216 the
// names they hold, to params, in the inventory transaction. Before schema
// 214 is installed there are none: maps carry no zones rather than failing;
// before 216, forward zones only; before 219, no name that points at a
// share.
func readNetworkDNSZones(ctx context.Context, transaction databaseTransaction,
	params *appmapsession.NetworkPolicyParams, protected []string) error {
	granted, err := functionGranted(ctx, transaction, dnsZonesGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check DNS zone readers: %w", err))
	}
	if !granted {
		return nil
	}
	names, err := functionGranted(ctx, transaction, dnsNamesGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check DNS name readers: %w", err))
	}
	zones, err := readNetworkDNSZoneRows(ctx, transaction, names)
	if err != nil || len(zones) == 0 {
		return err
	}
	if err := readNetworkDNSResolvers(ctx, transaction, zones); err != nil {
		return err
	}
	params.DNSZones = zones
	if names {
		if params.DNSNames, err = readNetworkDNSNames(ctx, transaction, zones); err != nil {
			return err
		}
	}
	params.DNSZones, params.DNSNames = withoutProtectedZones(params.DNSZones, params.DNSNames, protected)
	return nil
}

// withoutProtectedZones leaves out every zone (but the root, which waits
// for D1b) that is or holds a protected name, and its names: zone writes
// refuse such a domain, but a name protected later (a new relay) must still
// reach the deployment.
func withoutProtectedZones(zones []appmapsession.DNSZone, names []appmapsession.DNSName,
	protected []string) ([]appmapsession.DNSZone, []appmapsession.DNSName) {
	dropped := make(map[int64]struct{})
	kept := zones[:0:0]
	for _, zone := range zones {
		if zone.Domain != "." && slices.ContainsFunc(protected, func(name string) bool {
			return name == zone.Domain || strings.HasSuffix(name, "."+zone.Domain)
		}) {
			dropped[zone.Zone] = struct{}{}
			continue
		}
		kept = append(kept, zone)
	}
	if len(dropped) == 0 {
		return zones, names
	}
	return kept, slices.DeleteFunc(slices.Clone(names), func(name appmapsession.DNSName) bool {
		_, gone := dropped[name.Zone]
		return gone
	})
}

func readNetworkDNSZoneRows(ctx context.Context, transaction databaseTransaction,
	kinds bool) ([]appmapsession.DNSZone, error) {
	query := loadNetworkDNSZonesSQL
	if kinds {
		query = loadNetworkDNSZonesV2SQL
	}
	rows, err := transaction.Query(ctx, query, maximumNetworkDNSZones+1)
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
		otherNames, failureMode := "forward", ""
		var position int32
		var err error
		if kinds {
			err = rows.Scan(&zone.Zone, &zone.Domain, &otherNames, &failureMode, &zone.Groups, &position)
		} else {
			err = rows.Scan(&zone.Zone, &zone.Domain, &failureMode, &zone.Groups, &position)
		}
		if err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network DNS zone: %w", err))
		}
		other, known := dnsOtherNames[otherNames]
		if !known || (failureMode != "open" && failureMode != "closed") {
			return nil, ErrSnapshotEvidence
		}
		zone.OtherNames = other
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

// readNetworkDNSNames reads the names of zones, in name order. A name of a
// zone the first read did not see, or of a shape the database never holds,
// is evidence of a broken read.
func readNetworkDNSNames(ctx context.Context, transaction databaseTransaction,
	zones []appmapsession.DNSZone) ([]appmapsession.DNSName, error) {
	shares, err := functionGranted(ctx, transaction, dnsShareNamesGrantedSQL)
	if err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("check DNS share name reader: %w", err))
	}
	query := loadNetworkDNSNamesSQL
	if shares {
		query = loadNetworkDNSShareNamesSQL
	}
	rows, err := transaction.Query(ctx, query, maximumNetworkDNSNames+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network DNS names: %w", nonNil(err)))
	}
	defer rows.Close()
	known := make(map[int64]struct{}, len(zones))
	for _, zone := range zones {
		known[zone.Zone] = struct{}{}
	}
	var names []appmapsession.DNSName
	read := 0
	for rows.Next() {
		if read == maximumNetworkDNSNames {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		read++
		var name appmapsession.DNSName
		var kind, publicID, cname, share string
		var addresses []string
		if err := rows.Scan(&name.Zone, &name.FQDN, &kind, &name.Device, &publicID, &addresses,
			&cname, &share); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network DNS name: %w", err))
		}
		if _, found := known[name.Zone]; !found || name.Device < 0 {
			return nil, ErrSnapshotEvidence
		}
		switch {
		case kind == "cname" && cname != "" && publicID == "" && len(addresses) == 0 && share == "":
			name.CNAME = cname
		case kind == "address" && share != "" && publicID == "" && len(addresses) == 0 && cname == "" &&
			name.Device == 0:
			if name.Share, err = sharing.ParseImportedResourceID(share); err != nil {
				return nil, ErrSnapshotEvidence
			}
		case kind == "address" && share == "" && publicID != "" && len(addresses) == 0 && cname == "":
			if name.NodeID, err = node.ParseID(publicID); err != nil {
				return nil, ErrSnapshotEvidence
			}
		case kind == "address" && share == "" && publicID == "" && len(addresses) > 0 && cname == "" &&
			name.Device == 0:
			name.Addresses = make([]netip.Addr, 0, len(addresses))
			for _, text := range addresses {
				address, err := netip.ParseAddr(text)
				if err != nil {
					return nil, ErrSnapshotEvidence
				}
				name.Addresses = append(name.Addresses, address)
			}
		default:
			return nil, ErrSnapshotEvidence
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network DNS names: %w", err))
	}
	return names, nil
}
