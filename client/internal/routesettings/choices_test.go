package routesettings

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func pointer[T any](value T) *T { return &value }

func TestOperatorsAllowedFollowsTheHost(t *testing.T) {
	t.Parallel()
	byDefault := runtime.GOOS != "windows"
	cases := []struct {
		name     string
		settings Settings
		want     bool
	}{
		{"neither", Settings{}, byDefault},
		{"on", Settings{OperatorsOn: true}, true},
		{"off", Settings{OperatorsOff: true}, false},
		{"off wins over on", Settings{OperatorsOff: true, OperatorsOn: true}, false},
	}
	for _, test := range cases {
		if got := test.settings.OperatorsAllowed(); got != test.want {
			t.Errorf("%s: OperatorsAllowed = %v, want %v", test.name, got, test.want)
		}
		if got := test.settings.Choices().Operators; got != test.want {
			t.Errorf("%s: Choices().Operators = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestOperatorsOnSurvivesTheFile(t *testing.T) {
	t.Parallel()
	encoded, err := Encode(Settings{OperatorsOn: true})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || !decoded.OperatorsOn {
		t.Fatalf("operators_on did not survive the file: %+v, %v", decoded, err)
	}
	if old, err := Decode([]byte(`{"accept_routes":true,"accept_public_routes":false,"router_mode":false,` +
		`"advertise_routes":[]}`)); err != nil || old.OperatorsOn {
		t.Fatalf("a file without operators_on = %+v, %v", old, err)
	}
}

func TestApplyChoicesChangesOnlyTheChoices(t *testing.T) {
	t.Parallel()
	root := Settings{ExitMode: true, RouterMode: true, ExitAllowManaged: true, ExitUse: "World"}
	changed, err := ApplyChoices(root, ChoiceChange{
		ExitUse: pointer(ExitUseAuto), AcceptRoutes: pointer(true), ExitAllowLAN: pointer(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := root
	want.ExitUse, want.AcceptRoutes, want.ExitAllowLAN = ExitUseAuto, true, true
	if changed.ExitUse != want.ExitUse || changed.AcceptRoutes != want.AcceptRoutes ||
		changed.ExitAllowLAN != want.ExitAllowLAN || !changed.ExitMode || !changed.RouterMode ||
		!changed.ExitAllowManaged {
		t.Fatalf("ApplyChoices = %+v, want %+v", changed, want)
	}
	if off, err := ApplyChoices(changed, ChoiceChange{ExitUse: pointer(ExitUseOff)}); err != nil || off.ExitUse != "" {
		t.Fatalf("exit-use off = %+v, %v", off, err)
	}
	if same, err := ApplyChoices(changed, ChoiceChange{}); err != nil || same.ExitUse != ExitUseAuto {
		t.Fatalf("an empty change = %+v, %v", same, err)
	}
	if !(ChoiceChange{}).Empty() || (ChoiceChange{AcceptRoutes: pointer(false)}).Empty() {
		t.Fatal("Empty is wrong")
	}
}

func TestApplyChoicesRefusesRootsSettingsAndBadValues(t *testing.T) {
	t.Parallel()
	public := Settings{AcceptPublicRoutes: true}
	if _, err := ApplyChoices(public, ChoiceChange{AcceptRoutes: pointer(true)}); !errors.Is(err, ErrRootSetting) {
		t.Fatalf("accept with root's accept-public = %v, want ErrRootSetting", err)
	}
	if off, err := ApplyChoices(public, ChoiceChange{AcceptRoutes: pointer(false)}); err != nil || off.AcceptRoutes {
		t.Fatalf("accept off with accept-public = %+v, %v", off, err)
	}
	for _, use := range []string{" World", "a\nb", string(make([]byte, 65)), "managed"} {
		if _, err := ApplyChoices(Settings{}, ChoiceChange{ExitUse: pointer(use)}); !errors.Is(err, ErrInvalid) {
			t.Errorf("exit-use %q = %v, want ErrInvalid", use, err)
		}
	}
}

// The writer UpdateExisting uses never prepares the directory: a missing
// one stays missing (review R1).
func TestWriteAtomicallyPreparesNothing(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "settings")
	if err := writeAtomically(filepath.Join(missing, "routes.json"), Settings{}); err == nil {
		t.Fatal("writeAtomically wrote into a missing directory")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writeAtomically created %s: %v", missing, err)
	}
}
