package routesettings

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func prefixes(texts ...string) []netip.Prefix {
	parsed := make([]netip.Prefix, len(texts))
	for index, text := range texts {
		parsed[index] = netip.MustParsePrefix(text)
	}
	return parsed
}

func TestDecodeAndEncodeRoundTrip(t *testing.T) {
	t.Parallel()
	settings, err := Decode([]byte(`{"accept_routes":true,"router_mode":true,
		"advertise_routes":["2001:db8::/48","10.20.0.0/16"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !settings.AcceptRoutes || settings.AcceptPublicRoutes || !settings.RouterMode ||
		!slices.Equal(settings.AdvertiseRoutes, prefixes("10.20.0.0/16", "2001:db8::/48")) {
		t.Fatalf("settings = %+v", settings)
	}
	encoded, err := Encode(settings)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := Decode(encoded); err != nil || !slices.Equal(again.AdvertiseRoutes, settings.AdvertiseRoutes) {
		t.Fatalf("round trip = %+v, %v", again, err)
	}
	for name, document := range map[string]string{
		"unknown field":   `{"accept_route":true}`,
		"trailing data":   `{} {}`,
		"default route":   `{"advertise_routes":["0.0.0.0/0"]}`,
		"overlay":         `{"advertise_routes":["100.64.0.0/24"]}`,
		"host bits":       `{"advertise_routes":["10.20.0.1/16"]}`,
		"listed twice":    `{"advertise_routes":["10.20.0.0/16","10.20.0.0/16"]}`,
		"not a prefix":    `{"advertise_routes":["lan"]}`,
		"not an object":   `[]`,
		"wrong flag type": `{"router_mode":"yes"}`,
	} {
		if _, err := Decode([]byte(document)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestLoadAndSave(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "routes.json")
	if settings, err := Load(path); err != nil || settings.AcceptRoutes || len(settings.AdvertiseRoutes) != 0 {
		t.Fatalf("a missing file = %+v, %v", settings, err)
	}
	want := Settings{AcceptRoutes: true, AdvertiseRoutes: prefixes("192.168.1.0/24")}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("saved file mode = %v, %v", info, err)
	}
	// Only root owns the file in production; a test user's file is refused.
	if os.Geteuid() != 0 {
		if _, err := Load(path); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("a file not owned by root: %v", err)
		}
	}
	if err := Save(path, Settings{AdvertiseRoutes: prefixes("0.0.0.0/0")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("saving invalid settings: %v", err)
	}
}

func TestAdmit(t *testing.T) {
	t.Parallel()
	granted := prefixes("10.20.0.0/16", "8.8.8.0/24", "10.20.0.0/16", "0.0.0.0/0", "100.64.1.0/24",
		"fd12::/48", "fc12::/48", "fd00::/48", "169.254.0.0/16", "10.0.0.1/8", "2001:db8::/48")
	accepted, refused := Admit(Settings{}, granted)
	if len(accepted) != 0 || len(refused) != len(granted) {
		t.Fatalf("routes off: accepted %v, refused %d", accepted, len(refused))
	}
	accepted, refused = Admit(Settings{AcceptRoutes: true}, granted)
	if !slices.Equal(accepted, prefixes("10.20.0.0/16", "fc12::/48", "fd12::/48")) {
		t.Fatalf("private routes = %v", accepted)
	}
	reasons := map[string]string{}
	for _, refusal := range refused {
		reasons[refusal.Prefix.String()] = refusal.Reason
	}
	for prefix, reason := range map[string]string{
		"8.8.8.0/24": ReasonPublic, "0.0.0.0/0": ReasonTooWide, "100.64.1.0/24": ReasonReserved,
		"fd00::/48": ReasonReserved, "169.254.0.0/16": ReasonReserved, "10.0.0.1/8": ReasonMalformed,
		"2001:db8::/48": ReasonPublic,
	} {
		if reasons[prefix] != reason {
			t.Errorf("%s refused for %q, want %q", prefix, reasons[prefix], reason)
		}
	}
	if accepted, _ := Admit(Settings{AcceptRoutes: true, AcceptPublicRoutes: true}, granted); len(accepted) != 5 {
		t.Fatalf("with public routes = %v", accepted)
	}
	many := make([]netip.Prefix, 0, MaximumRoutes+1)
	for index := range MaximumRoutes + 1 {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24))
	}
	if accepted, refused := Admit(Settings{AcceptRoutes: true}, many); len(accepted) != 0 || len(refused) != len(many) {
		t.Fatalf("over the bound: accepted %d, refused %d", len(accepted), len(refused))
	}
}
