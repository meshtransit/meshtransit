package localapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/daemon"
)

// A1: status carries the sign-in; A6: an added account names the account
// it was added from.
func TestSignInAndPreviousProfileJSON(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 11, 19, 8, 0, 0, 0, time.FixedZone("ICT", 7*3600))
	refused, err := json.Marshal(mapSignIn(daemon.SignInStatus{
		State: daemon.SignInRefused, Code: "conflict", Message: "No.", At: at,
	}))
	if err != nil || string(refused) != `{"state":"refused","code":"conflict","message":"No.","at":"2026-11-19T01:00:00Z"}` {
		t.Fatalf("refused sign-in JSON = %s, %v", refused, err)
	}
	none, err := json.Marshal(mapSignIn(daemon.SignInStatus{State: daemon.SignInNone}))
	if err != nil || string(none) != `{"state":"none"}` {
		t.Fatalf("no sign-in JSON = %s, %v", none, err)
	}
	added := profileResponse{ID: "p2"}.withDisplay(daemon.Display{
		CreatedByAddAccount: true, PreviousProfileID: "p1",
	}, true, true)
	encoded, err := json.Marshal(added)
	if err != nil || !strings.Contains(string(encoded), `"can_cancel":true`) ||
		!strings.Contains(string(encoded), `"previous_profile_id":"p1"`) {
		t.Fatalf("added account JSON = %s, %v", encoded, err)
	}
	own, err := json.Marshal(profileResponse{ID: "p1"}.withDisplay(daemon.Display{PreviousProfileID: "p0"}, true, false))
	if err != nil || strings.Contains(string(own), "previous_profile_id") {
		t.Fatalf("an account not added here names a previous one: %s, %v", own, err)
	}
}
