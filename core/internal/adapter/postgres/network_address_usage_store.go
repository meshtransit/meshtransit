package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/addressusage"
)

const maximumAddressUsageBytes = 4096

const readNetworkAddressUsageSQL = `SELECT mesh_ops.read_network_address_usage_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ)::TEXT`

// NetworkAddressUsageStore reads how full a Network's address ranges are
// through the runtime pool, in one short exact-Network transaction.
type NetworkAddressUsageStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ addressusage.Store = (*NetworkAddressUsageStore)(nil)

// NewNetworkAddressUsageStore uses the runtime pool.
func NewNetworkAddressUsageStore(pool *Pool, options AccountSessionOptions) (*NetworkAddressUsageStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, addressusage.ErrInvalid
	}
	return &NetworkAddressUsageStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func networkAddressUsageError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return addressusage.ErrForbidden
		case "22023", "22P02":
			return addressusage.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return addressusage.ErrForbidden
	}
	return errors.Join(addressusage.ErrUnavailable, err)
}

// Read authorizes network.read and returns the use of every range, both
// decided on the database clock of its transaction.
func (store *NetworkAddressUsageStore) Read(ctx context.Context, session accountsession.Session,
	scope network.Scope) (_ addressusage.State, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !scope.IsValid() {
		return addressusage.State{}, addressusage.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return addressusage.State{}, errors.Join(addressusage.ErrUnavailable, err)
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return addressusage.State{}, errors.Join(addressusage.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return addressusage.State{}, networkAddressUsageError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return addressusage.State{}, addressusage.ErrForbidden
	}
	evaluatedAt, err := readTransactionTime(ctx, tx.QueryRow)
	if err != nil {
		return addressusage.State{}, errors.Join(addressusage.ErrUnavailable, err)
	}
	args := append(sessionQueryArguments(session), scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt)
	var encoded string
	if err := tx.QueryRow(ctx, readNetworkAddressUsageSQL, args...).Scan(&encoded); err != nil {
		return addressusage.State{}, networkAddressUsageError(err)
	}
	return decodeNetworkAddressUsage([]byte(encoded))
}

type addressUsageRecord struct {
	Prefixes []struct {
		Family              int        `json:"family"`
		Prefix              string     `json:"prefix"`
		Capacity            *int64     `json:"capacity"`
		InUse               int64      `json:"in_use"`
		HeldByExpired       int64      `json:"held_by_expired"`
		HeldAfterRevocation int64      `json:"held_after_revocation"`
		NextRelease         *time.Time `json:"next_release"`
	} `json:"prefixes"`
}

func decodeNetworkAddressUsage(encoded []byte) (addressusage.State, error) {
	if len(encoded) == 0 || len(encoded) > maximumAddressUsageBytes {
		return addressusage.State{}, addressusage.ErrInvalid
	}
	var record addressUsageRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return addressusage.State{}, addressusage.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return addressusage.State{}, addressusage.ErrInvalid
	}
	state := addressusage.State{Ranges: make([]addressusage.Range, 0, len(record.Prefixes))}
	for _, item := range record.Prefixes {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil || (item.Family == 4) != prefix.Addr().Is4() || (item.Family != 4 && item.Family != 6) {
			return addressusage.State{}, addressusage.ErrInvalid
		}
		usage := addressusage.Range{Prefix: prefix, InUse: item.InUse, HeldByExpired: item.HeldByExpired,
			HeldAfterRevocation: item.HeldAfterRevocation}
		if item.Capacity != nil {
			usage.Capacity = *item.Capacity
		}
		if item.NextRelease != nil {
			usage.NextRelease = item.NextRelease.UTC()
		}
		state.Ranges = append(state.Ranges, usage)
	}
	if !state.IsValid() {
		return addressusage.State{}, addressusage.ErrInvalid
	}
	return state, nil
}
