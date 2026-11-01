package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 269: a Network's directory for the connection log receiver
// (connection logs design §16d, C61), read in one REPEATABLE READ READ ONLY
// snapshot: the Network part, then its Devices by pages.
const (
	readFlowlogDirectoryNetworkSQL = `SELECT pg_catalog.transaction_timestamp(),
    mesh_ops.flowlog_directory_network_v1($1::UUID, $2::UUID)::TEXT`
	readFlowlogDirectoryDevicesSQL = `SELECT pg_catalog.transaction_timestamp(),
    mesh_ops.flowlog_directory_devices_v1($1::UUID, $2::UUID, $3::UUID, $4::INTEGER)::TEXT`
	readOnlySnapshotSQL = `SET TRANSACTION READ ONLY`

	// flowlogDirectoryPage is the Devices one statement reads.
	flowlogDirectoryPage = 10000
	// flowlogDirectoryTimeout bounds a whole build; each statement keeps the
	// store's own timeout.
	flowlogDirectoryTimeout = 30 * time.Second
	// maxFlowlogDirectoryPage bounds one decoded page: 10 000 Devices of 64
	// tags and 64 groups each.
	maxFlowlogDirectoryPage = 96 << 20
)

// ErrFlowlogDirectoryTooLarge reports a Network with more Devices than one
// directory holds: refused, never cut (C61).
var ErrFlowlogDirectoryTooLarge = errors.New("postgres: connection log directory too large")

type flowlogDirectoryNetworkRow struct {
	Revision      int64                  `json:"revision"`
	BuiltAt       time.Time              `json:"built_at"`
	MeshPrefixes  []string               `json:"mesh_prefixes"`
	AliasPrefixes []string               `json:"alias_prefixes"`
	Sites         []flowlogDirectorySite `json:"sites"`
	ExitPools     []flowlogDirectoryPool `json:"exit_pools"`
	Tags          []flowlogDirectoryName `json:"tags"`
	Groups        []flowlogDirectoryName `json:"groups"`
	Devices       int                    `json:"devices"`
}

type flowlogDirectorySite struct {
	ID       string   `json:"id"`
	Prefixes []string `json:"prefixes"`
	Routers  []string `json:"routers"`
}

type flowlogDirectoryPool struct {
	ID         string   `json:"id"`
	Candidates []string `json:"candidates"`
}

type flowlogDirectoryName struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type flowlogDirectoryDeviceRow struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	State     string   `json:"state"`
	Hostname  string   `json:"hostname"`
	OwnerKind string   `json:"owner_kind"`
	Pseudonym *string  `json:"pseudonym"`
	Addresses []string `json:"addresses"`
	Tags      []string `json:"tags"`
	Groups    []string `json:"groups"`
	Truncated bool     `json:"truncated"`
}

// Directory reads the exact (Workspace, Network) pair's directory;
// ErrFlowlogNotFound when it has no destination, ErrFlowlogDirectoryTooLarge
// when it has more Devices than one directory holds.
func (store *FlowlogReceiverStore) Directory(ctx context.Context, scope network.Scope,
) (_ connectionlog.ReceiverDirectory, resultErr error) {
	if store == nil || store.database == nil || ctx == nil || !scope.IsValid() {
		return connectionlog.ReceiverDirectory{}, ErrFlowlogReceiver
	}
	startedAt := time.Now()
	defer func() {
		if store.metrics != nil && !errors.Is(resultErr, ErrFlowlogNotFound) {
			store.metrics.observeOperation(postgresOperationFlowlogReceiver, time.Since(startedAt), resultErr)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, flowlogDirectoryTimeout)
	defer cancel()
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return connectionlog.ReceiverDirectory{}, errors.Join(ErrFlowlogReceiver, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if err := transaction.Exec(ctx, readOnlySnapshotSQL); err != nil {
		return connectionlog.ReceiverDirectory{}, errors.Join(ErrFlowlogReceiver, err)
	}
	if err := transaction.Exec(ctx, configureFlowlogReadSQL, flowlogStatementTimeout); err != nil {
		return connectionlog.ReceiverDirectory{}, errors.Join(ErrFlowlogReceiver, err)
	}
	workspaceID, networkID := scope.WorkspaceID().String(), scope.NetworkID().String()
	document, err := readFlowlogDirectoryDocument(ctx, transaction, readFlowlogDirectoryNetworkSQL,
		workspaceID, networkID)
	if err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	if document == nil {
		return connectionlog.ReceiverDirectory{}, ErrFlowlogNotFound
	}
	var head flowlogDirectoryNetworkRow
	if decodeStrictJSON(*document, maxFlowlogDocument, &head) != nil || head.Revision < 1 || head.Devices < 0 {
		return connectionlog.ReceiverDirectory{}, ErrFlowlogReceiver
	}
	if head.Devices > connectionlog.MaxReceiverDirectoryDevices {
		return connectionlog.ReceiverDirectory{}, ErrFlowlogDirectoryTooLarge
	}
	directory, err := newReceiverDirectory(head)
	if err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	devices, err := readFlowlogDirectoryDevices(ctx, transaction, workspaceID, networkID, head.Devices)
	if err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	if directory.Devices, err = receiverDevices(devices, head.Tags, head.Groups); err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return connectionlog.ReceiverDirectory{}, errors.Join(ErrFlowlogReceiver, err)
	}
	return directory, nil
}

func readFlowlogDirectoryDocument(ctx context.Context, transaction resourceAuthorityDatabaseTransaction,
	sql string, arguments ...any,
) (*string, error) {
	var at time.Time
	var document *string
	if err := transaction.QueryRow(ctx, sql, arguments...).Scan(&at, &document); err != nil {
		return nil, errors.Join(ErrFlowlogReceiver, err)
	}
	return document, nil
}

// readFlowlogDirectoryDevices reads the snapshot's Devices by pages; the
// pages hold exactly the count the Network part read in the same snapshot.
func readFlowlogDirectoryDevices(ctx context.Context, transaction resourceAuthorityDatabaseTransaction,
	workspaceID, networkID string, count int,
) ([]flowlogDirectoryDeviceRow, error) {
	devices := make([]flowlogDirectoryDeviceRow, 0, count)
	var after any
	for {
		document, err := readFlowlogDirectoryDocument(ctx, transaction, readFlowlogDirectoryDevicesSQL,
			workspaceID, networkID, after, flowlogDirectoryPage)
		if err != nil {
			return nil, err
		}
		var page []flowlogDirectoryDeviceRow
		if document == nil || decodeStrictJSON(*document, maxFlowlogDirectoryPage, &page) != nil {
			return nil, ErrFlowlogReceiver
		}
		devices = append(devices, page...)
		if len(devices) > count {
			return nil, ErrFlowlogReceiver
		}
		if len(page) < flowlogDirectoryPage {
			break
		}
		after = page[len(page)-1].ID
	}
	if len(devices) != count {
		return nil, ErrFlowlogReceiver
	}
	return devices, nil
}

func newReceiverDirectory(head flowlogDirectoryNetworkRow) (connectionlog.ReceiverDirectory, error) {
	directory := connectionlog.ReceiverDirectory{Revision: head.Revision, BuiltAt: head.BuiltAt.UTC()}
	var err error
	if directory.MeshPrefixes, err = parseDirectoryPrefixes(head.MeshPrefixes); err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	if directory.AliasPrefixes, err = parseDirectoryPrefixes(head.AliasPrefixes); err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	if directory.Tags, err = parseDirectoryNames(head.Tags); err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	if directory.Groups, err = parseDirectoryNames(head.Groups); err != nil {
		return connectionlog.ReceiverDirectory{}, err
	}
	for _, row := range head.Sites {
		id, err := publicid.Parse(row.ID)
		if err != nil {
			return connectionlog.ReceiverDirectory{}, ErrFlowlogReceiver
		}
		site := connectionlog.ReceiverSite{ID: id}
		if site.Prefixes, err = parseDirectoryPrefixes(row.Prefixes); err != nil {
			return connectionlog.ReceiverDirectory{}, err
		}
		if site.Routers, err = parseNodeIDs(row.Routers); err != nil {
			return connectionlog.ReceiverDirectory{}, err
		}
		directory.Sites = append(directory.Sites, site)
	}
	for _, row := range head.ExitPools {
		id, err := publicid.Parse(row.ID)
		if err != nil {
			return connectionlog.ReceiverDirectory{}, ErrFlowlogReceiver
		}
		pool := connectionlog.ReceiverExitPool{ID: id}
		if pool.Candidates, err = parseNodeIDs(row.Candidates); err != nil {
			return connectionlog.ReceiverDirectory{}, err
		}
		directory.ExitPools = append(directory.ExitPools, pool)
	}
	return directory, nil
}

var (
	directoryKinds = map[string]bool{
		connectionlog.DeviceKindStandard: true, connectionlog.DeviceKindKubernetesGateway: true,
	}
	directoryStates = map[string]bool{
		connectionlog.DeviceStateActive: true, connectionlog.DeviceStateExpired: true,
		connectionlog.DeviceStateSuspended: true, connectionlog.DeviceStateRevoked: true,
		connectionlog.DeviceStateDeleted: true,
	}
	directoryOwnerKinds = map[string]bool{connectionlog.OwnerKindMember: true, connectionlog.OwnerKindWorkspace: true}
)

// receiverDevices turns the rows into Devices whose tags and groups index
// the dictionaries; a name outside them is a broken snapshot.
func receiverDevices(rows []flowlogDirectoryDeviceRow, tags, groups []flowlogDirectoryName,
) ([]connectionlog.ReceiverDevice, error) {
	tagIndex, groupIndex := nameIndexes(tags), nameIndexes(groups)
	devices := make([]connectionlog.ReceiverDevice, 0, len(rows))
	for _, row := range rows {
		id, err := node.ParseID(row.ID)
		if err != nil || !directoryKinds[row.Kind] || !directoryStates[row.State] ||
			!directoryOwnerKinds[row.OwnerKind] || len(row.Tags) > connectionlog.MaxReceiverDeviceNames ||
			len(row.Groups) > connectionlog.MaxReceiverDeviceNames {
			return nil, ErrFlowlogReceiver
		}
		device := connectionlog.ReceiverDevice{
			ID: id, Kind: row.Kind, State: row.State, Hostname: row.Hostname, OwnerKind: row.OwnerKind,
			NamesTruncated: row.Truncated,
		}
		if row.Pseudonym != nil {
			if device.Pseudonym, err = parsePseudonym(*row.Pseudonym); err != nil {
				return nil, err
			}
		}
		for _, text := range row.Addresses {
			address, err := netip.ParseAddr(text)
			if err != nil || address.Zone() != "" {
				return nil, ErrFlowlogReceiver
			}
			device.Addresses = append(device.Addresses, address)
		}
		if device.Tags, err = nameIndexesOf(row.Tags, tagIndex); err != nil {
			return nil, err
		}
		if device.Groups, err = nameIndexesOf(row.Groups, groupIndex); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func nameIndexes(names []flowlogDirectoryName) map[string]int {
	index := make(map[string]int, len(names))
	for position, name := range names {
		index[name.ID] = position
	}
	return index
}

func nameIndexesOf(ids []string, index map[string]int) ([]int, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	positions := make([]int, 0, len(ids))
	for _, id := range ids {
		position, ok := index[id]
		if !ok {
			return nil, ErrFlowlogReceiver
		}
		positions = append(positions, position)
	}
	return positions, nil
}

func parseDirectoryPrefixes(texts []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(texts))
	for _, text := range texts {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix != prefix.Masked() {
			return nil, ErrFlowlogReceiver
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseDirectoryNames(rows []flowlogDirectoryName) ([]connectionlog.ReceiverName, error) {
	names := make([]connectionlog.ReceiverName, 0, len(rows))
	for _, row := range rows {
		id, err := publicid.Parse(row.ID)
		if err != nil || row.Name == "" {
			return nil, ErrFlowlogReceiver
		}
		names = append(names, connectionlog.ReceiverName{ID: id, Name: row.Name})
	}
	return names, nil
}

func parseNodeIDs(texts []string) ([]node.ID, error) {
	ids := make([]node.ID, 0, len(texts))
	for _, text := range texts {
		id, err := node.ParseID(text)
		if err != nil {
			return nil, ErrFlowlogReceiver
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// parsePseudonym reads a canonical UUID of any version: pseudonyms are
// random (version 4), so they carry no time.
func parsePseudonym(text string) ([16]byte, error) {
	var pseudonym [16]byte
	if len(text) != 36 || strings.Count(text, "-") != 4 || text[8] != '-' || text[13] != '-' ||
		text[18] != '-' || text[23] != '-' || strings.ToLower(text) != text {
		return pseudonym, ErrFlowlogReceiver
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(raw) != len(pseudonym) || [16]byte(raw) == pseudonym {
		return pseudonym, ErrFlowlogReceiver
	}
	return [16]byte(raw), nil
}
