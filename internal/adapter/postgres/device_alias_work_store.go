package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/sharing/devicealias"
	"io"
	"time"
)

const loadDeviceAliasWorkSQL = `SELECT mesh_ops.load_device_alias_work_v1($1::UUID,$2::UUID,$3::UUID,$4::INTEGER)`

var _ devicealias.Work = (*DeviceAliasWorkerStore)(nil)

// List owns one bounded read-only unit; all cleanup completes before any hint
// leaves the adapter. Discovery does not append mutation, audit or outbox rows.
func (store *DeviceAliasWorkerStore) List(ctx context.Context, installation deployment.ID, after devicealias.Cursor, limit int) (result devicealias.Page, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !after.IsValid() || limit < 1 || limit > 128 {
		return devicealias.Page{}, ErrInvalidDeviceAliasWorker
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return devicealias.Page{}, errors.Join(ErrDeviceAliasChange, err)
	}
	tx, err := store.database.Begin(ctx, true)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(tx))
			}
			if resultErr != nil {
				result = devicealias.Page{}
			}
		}()
	}
	if err != nil {
		return devicealias.Page{}, errors.Join(ErrDeviceAliasChange, err)
	}
	if tx == nil {
		return devicealias.Page{}, ErrDeviceAliasChange
	}
	if err := tx.Exec(ctx, configureAuthTransactionSQL, "3000", "1000", "5000"); err != nil {
		return devicealias.Page{}, errors.Join(ErrDeviceAliasChange, err)
	}
	var endpoint, consumer any
	if after.EndpointID.IsValid() {
		endpoint = after.EndpointID.String()
	}
	if after.ConsumerID.IsValid() {
		consumer = after.ConsumerID.String()
	}
	var encoded []byte
	if err := tx.QueryRow(ctx, loadDeviceAliasWorkSQL, installation.String(), endpoint, consumer, limit).Scan(&encoded); err != nil {
		return devicealias.Page{}, errors.Join(ErrDeviceAliasChange, err)
	}
	page, err := decodeDeviceAliasWork(encoded, installation, after, limit)
	if err != nil {
		return devicealias.Page{}, err
	}
	if err := ctx.Err(); err != nil {
		return devicealias.Page{}, errors.Join(ErrDeviceAliasChange, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return devicealias.Page{}, errors.Join(ErrDeviceAliasChange, err)
	}
	committed = true
	if err := ctx.Err(); err != nil {
		return devicealias.Page{}, errors.Join(ErrDeviceAliasChange, err)
	}
	return page, nil
}

func decodeDeviceAliasWork(encoded []byte, installation deployment.ID, after devicealias.Cursor, limit int) (devicealias.Page, error) {
	if len(encoded) == 0 || len(encoded) > 262144 {
		return devicealias.Page{}, ErrDeviceAliasChange
	}
	var record struct {
		Items []struct {
			EndpointID    string `json:"endpoint_id"`
			ConsumerID    string `json:"consumer_id"`
			Generation    int64  `json:"generation"`
			ProviderEpoch int64  `json:"provider_node_epoch"`
			ConsumerEpoch int64  `json:"consumer_node_epoch"`
			Mode          string `json:"mode"`
		} `json:"items"`
		Cursor *struct {
			EndpointID *string `json:"endpoint_id"`
			ConsumerID *string `json:"consumer_id"`
		} `json:"cursor"`
		Done *bool `json:"done"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Cursor == nil || record.Done == nil || record.Items == nil || len(record.Items) > limit {
		return devicealias.Page{}, ErrDeviceAliasChange
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return devicealias.Page{}, ErrDeviceAliasChange
	}
	page := devicealias.Page{Done: *record.Done, Items: make([]devicealias.ChangeIntent, 0, len(record.Items))}
	if record.Cursor.EndpointID != nil {
		id, err := sharing.ParsePrivateEndpointID(*record.Cursor.EndpointID)
		if err != nil {
			return devicealias.Page{}, ErrDeviceAliasChange
		}
		page.Next.EndpointID = id
	}
	if record.Cursor.ConsumerID != nil {
		id, err := node.ParseID(*record.Cursor.ConsumerID)
		if err != nil {
			return devicealias.Page{}, ErrDeviceAliasChange
		}
		page.Next.ConsumerID = id
	}
	for _, item := range record.Items {
		endpoint, endpointErr := sharing.ParsePrivateEndpointID(item.EndpointID)
		consumer, consumerErr := node.ID{}, error(nil)
		if item.ConsumerID != "" {
			consumer, consumerErr = node.ParseID(item.ConsumerID)
		}
		if endpointErr != nil || consumerErr != nil {
			return devicealias.Page{}, ErrDeviceAliasChange
		}
		page.Items = append(page.Items, devicealias.ChangeIntent{DeploymentID: installation, EndpointID: endpoint, ConsumerID: consumer, EndpointGeneration: item.Generation, ProviderNodeEpoch: item.ProviderEpoch, ConsumerNodeEpoch: item.ConsumerEpoch, Mode: devicealias.ChangeMode(item.Mode)})
	}
	if !page.IsValid(installation, after, limit) {
		return devicealias.Page{}, ErrDeviceAliasChange
	}
	return page, nil
}
