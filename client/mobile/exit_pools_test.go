package mobile

import (
	"encoding/json"
	"strings"
	"testing"

	"meshtransit.net/client/internal/daemon"
)

// TD-CLI-120 on Android: the app chooses a pool from the ones the Network
// grants, so status names them; without a map they are left out.
func TestStatusNamesTheGrantedExitPools(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		granted []daemon.GrantedExitPool
		want    string
	}{
		{
			name: "granted", granted: []daemon.GrantedExitPool{{Ref: "r1", Name: "World"}},
			want: `"exitPools":[{"ref":"r1","name":"World"}]`,
		},
		{name: "none granted", granted: []daemon.GrantedExitPool{}, want: `"exitPools":[]`},
		{name: "no map", granted: nil},
	} {
		encoded, err := newStatus(true, daemon.Status{ExitPools: test.granted}).marshal()
		if err != nil {
			t.Fatal(err)
		}
		if test.want == "" {
			var decoded map[string]any
			if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
				t.Fatal(err)
			}
			if _, present := decoded["exitPools"]; present {
				t.Errorf("%s: exitPools present in %s", test.name, encoded)
			}
			continue
		}
		if !strings.Contains(encoded, test.want) {
			t.Errorf("%s: status = %s", test.name, encoded)
		}
	}
}

// SetExitNode refuses a pool the Network does not grant before it writes
// the choice: behind the VPN's kill switch it would drop the phone's
// Internet traffic. Off, auto and any choice without a map are taken.
func TestExitPoolRefusal(t *testing.T) {
	t.Parallel()
	granted := []daemon.GrantedExitPool{{Ref: "r1", Name: "World"}, {Ref: "r2", Name: "Office"}, {Ref: "r3", Name: "Office"}}
	for _, test := range []struct {
		use     string
		known   bool
		refused bool
	}{
		{use: "world", known: true, refused: true},
		{use: "Office", known: true, refused: true},
		{use: "World", known: true},
		{use: "r3", known: true},
		{use: "auto", known: true},
		{use: "", known: true},
		{use: "off", known: true, refused: true}, // SetExitNode makes "off" none first; never a pool named off
		{use: "anything"},
	} {
		err := exitPoolRefusal(test.use, granted, test.known)
		if (err != nil) != test.refused {
			t.Errorf("exitPoolRefusal(%q, known %v) = %v, refused want %v", test.use, test.known, err, test.refused)
		}
		if err != nil && !strings.Contains(err.Error(), test.use) {
			t.Errorf("refusal %q does not name %q", err, test.use)
		}
	}
}
