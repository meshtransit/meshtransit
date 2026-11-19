package mobile

import (
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
)

func TestRefusalError(t *testing.T) {
	t.Parallel()
	refused := fmt.Errorf("%w: %w", daemon.ErrRegistration,
		&controlplane.RejectedError{Code: "conflict", Message: "This computer is already a Device in another Network."})
	other := errors.New("dial control: timeout")
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"refused", refused, "registration_conflict: This computer is already a Device in another Network."},
		{"bad code", fmt.Errorf("%w: %w", daemon.ErrRegistration,
			&controlplane.RejectedError{Code: "Conflict!", Message: "x"}), ""},
		{"not a registration", &controlplane.RejectedError{Code: "conflict", Message: "x"}, ""},
		{"other", other, other.Error()},
		{"not ended", errors.Join(refused, errors.New("ending the refused sign-in: disk full")), ""},
	} {
		got := refusalError(test.err)
		switch {
		case test.want == "" && got != test.err: //nolint:errorlint // identity: the error is returned unchanged
			t.Errorf("%s: refusalError changed %v into %v", test.name, test.err, got)
		case test.want != "" && (got == nil || got.Error() != test.want):
			t.Errorf("%s: refusalError = %v, want %q", test.name, got, test.want)
		}
	}
	if refusalError(nil) != nil {
		t.Error("refusalError(nil) != nil")
	}
}
