package postgres

import (
	"errors"
	"reflect"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment/registration"
)

func TestCheckNewDeviceLimit(t *testing.T) {
	t.Parallel()
	authority := browserCompletionAuthority{workspaceInternalID: 103, networkInternalID: 203, principalInternalID: 11}
	for _, scenario := range []struct {
		recent int64
		want   error
	}{
		{recent: 0},
		{recent: registration.NewDeviceLimit - 1},
		{recent: registration.NewDeviceLimit, want: registration.ErrNewDeviceLimit},
		{recent: -1, want: ErrRegistrationEvidence},
	} {
		tx := newFakeRegistrationDatabaseTransaction()
		tx.enqueueRow(countRecentBrowserDevicesSQL, registrationTestRow{scan: func(destinations ...any) error {
			*destinations[0].(*int64) = scenario.recent
			return nil
		}})
		err := checkNewDeviceLimit(t.Context(), tx, authority)
		if (scenario.want == nil && err != nil) || (scenario.want != nil && !errors.Is(err, scenario.want)) {
			t.Errorf("%d recent Devices: error = %v, want %v", scenario.recent, err, scenario.want)
		}
		if len(tx.calls) != 1 || !reflect.DeepEqual(tx.calls[0].arguments,
			[]any{int64(103), int64(203), int64(11), registration.NewDeviceWindow.Milliseconds()}) {
			t.Errorf("count arguments = %#v", tx.calls)
		}
	}
}
