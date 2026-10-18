package httpapi

import (
	"errors"
	"net/http"
	"testing"

	authority "meshtransit.net/core/internal/domain/resource/authority"
)

func TestResourceAuthorityErrorNamesConflicts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "name taken", err: errors.Join(authority.ErrMutationFailed, authority.ErrNameTaken),
			status: http.StatusConflict, code: "resource_name_taken"},
		{name: "Device has a Resource", err: errors.Join(authority.ErrMutationFailed, authority.ErrDeviceResourceExists),
			status: http.StatusConflict, code: "device_resource_exists"},
		{name: "stale revision", err: errors.Join(authority.ErrMutationFailed, authority.ErrConflict),
			status: http.StatusPreconditionFailed, code: "precondition_failed"},
	} {
		got := classifyResourceAuthorityError(test.err)
		if got.Status != test.status || got.Code != test.code {
			t.Errorf("%s: %d %s, want %d %s", test.name, got.Status, got.Code, test.status, test.code)
		}
	}
}
