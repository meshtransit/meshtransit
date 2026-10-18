package site

import (
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

func validDeviceID(t *testing.T) node.ID {
	t.Helper()
	id, err := node.ParseID("01a144c0-4852-7022-87a5-57e5cdc78c7f")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
