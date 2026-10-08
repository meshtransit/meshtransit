package postgres

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/node/distribution"
)

func TestDecodeDeviceDistribution(t *testing.T) {
	t.Parallel()
	target, err := decodeDeviceDistribution(`{"workspace_id":"01890f00-0000-7000-8000-000000000101",` +
		`"network_id":"01890f00-0000-7000-8000-000000000201","network_revision":7,"policy_revision":3,` +
		`"devices":[{"id":"01890f00-0000-7000-8000-000000000301","hostname":"poc-01","state":"active"}]}`)
	if err != nil {
		t.Fatalf("decodeDeviceDistribution() error = %v", err)
	}
	if target.NetworkRevision != 7 || target.PolicyRevision != 3 || len(target.Devices) != 1 ||
		target.Devices[0].Hostname != "poc-01" || target.Devices[0].State != "active" ||
		target.Scope.NetworkID().String() != "01890f00-0000-7000-8000-000000000201" {
		t.Fatalf("target = %+v", target)
	}
	for name, encoded := range map[string]string{
		"unknown field": `{"workspace_id":"01890f00-0000-7000-8000-000000000101","network_id":"01890f00-0000-7000-8000-000000000201","network_revision":1,"policy_revision":0,"devices":[],"extra":1}`,
		"no devices":    `{"workspace_id":"01890f00-0000-7000-8000-000000000101","network_id":"01890f00-0000-7000-8000-000000000201","network_revision":1,"policy_revision":0}`,
		"bad scope":     `{"workspace_id":"x","network_id":"01890f00-0000-7000-8000-000000000201","network_revision":1,"policy_revision":0,"devices":[]}`,
		"bad device":    `{"workspace_id":"01890f00-0000-7000-8000-000000000101","network_id":"01890f00-0000-7000-8000-000000000201","network_revision":1,"policy_revision":0,"devices":[{"id":"x","hostname":"a","state":"active"}]}`,
		"trailing":      `{"workspace_id":"01890f00-0000-7000-8000-000000000101","network_id":"01890f00-0000-7000-8000-000000000201","network_revision":1,"policy_revision":0,"devices":[]}{}`,
	} {
		if _, err := decodeDeviceDistribution(encoded); !errors.Is(err, distribution.ErrInvalidResult) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}
