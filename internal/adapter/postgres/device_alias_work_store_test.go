package postgres

import (
	"context"
	"errors"
	"github.com/meshtransit/meshtransit/internal/sharing/devicealias"
	"testing"
)

const aliasWorkFixtureJSON = `{"items":[{"endpoint_id":"01890f00-0000-7000-8000-000000000010","consumer_id":"01890f00-0000-7000-8000-000000000011","generation":1,"provider_node_epoch":1,"consumer_node_epoch":1,"mode":"reserve"}],"cursor":{"endpoint_id":"01890f00-0000-7000-8000-000000000010","consumer_id":"01890f00-0000-7000-8000-000000000011"},"done":false}`

func TestDeviceAliasWorkReadOwnsCleanupBeforeReleasingHints(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"valid", "query", "configure", "commit", "cleanup", "cancel", "begin", "missing shape", "stalled", "trailing data"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			intent := aliasWorkerIntentFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tx := &aliasWorkTestTransaction{mode: mode, cancel: cancel}
			database := &fakeOutboxDatabase{transaction: tx}
			synthetic := errors.New("synthetic work read failure")
			switch mode {
			case "configure":
				tx.execErr = synthetic
			case "commit":
				tx.commitErr = synthetic
			case "cleanup":
				tx.rollbackErr = synthetic
			case "begin":
				database.beginErr = synthetic
			}
			store := &DeviceAliasWorkerStore{database: database}
			page, err := store.List(ctx, intent.DeploymentID, devicealias.Cursor{}, 1)
			if mode == "valid" {
				if err != nil || len(page.Items) != 1 || page.Items[0] != intent || !tx.committed || tx.rollbackCalls != 0 {
					t.Fatal("valid read failed", err)
				}
			} else if err == nil || len(page.Items) != 0 || tx.rollbackCalls != 1 || tx.committed {
				t.Fatal("failed read released hints", err)
			}
			if !database.readOnly {
				t.Fatal("discovery opened a write transaction")
			}
		})
	}
}

type aliasWorkTestTransaction struct {
	fakeOutboxTransaction
	mode   string
	cancel context.CancelFunc
}

func (tx *aliasWorkTestTransaction) QueryRow(_ context.Context, query string, _ ...any) outboxRow {
	return fakeOutboxRow{scan: func(values ...any) error {
		if query != loadDeviceAliasWorkSQL {
			return errors.New("unexpected work query")
		}
		if tx.mode == "query" || tx.mode == "cleanup" {
			return errors.New("synthetic read query failure")
		}
		body := aliasWorkFixtureJSON
		switch tx.mode {
		case "cancel":
			tx.cancel()
		case "missing shape":
			body = `{"items":[],"cursor":{}}`
		case "stalled":
			body = `{"items":[],"cursor":{"endpoint_id":null,"consumer_id":null},"done":false}`
		case "trailing data":
			body += `{}`
		}
		*values[0].(*[]byte) = []byte(body)
		return nil
	}}
}
