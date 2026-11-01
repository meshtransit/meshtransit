package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"meshtransit.net/core/internal/platform/app"
)

func TestLoadFlowLogInternalConfig(t *testing.T) {
	t.Parallel()
	key := func(fill byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)) }
	full := map[string]string{
		envFlowLogInternalAddr:     ":9443",
		envFlowLogInternalCertFile: "/run/secrets/flowlog/tls.crt",
		envFlowLogInternalKeyFile:  "/run/secrets/flowlog/tls.key",
		envFlowLogInternalClientCA: "/run/secrets/flowlog/receiver-ca.pem",
		envFlowLogInternalClientID: "spiffe://01890f00-0000-7000-8000-000000000123/meshflow",
		envFlowLogTokenPublicKeys:  "current=" + key(1) + ", next=" + key(2),
	}
	with := func(name, value string) map[string]string {
		values := make(map[string]string, len(full))
		for setting, current := range full {
			if setting != name {
				values[setting] = current
			}
		}
		if value != "" {
			values[name] = value
		}
		return values
	}
	if none, err := loadFlowLogInternalConfig(mapLookup(nil), app.RoleAPI); err != nil || none != nil {
		t.Fatalf("none: %v %v", none, err)
	}
	loaded, err := loadFlowLogInternalConfig(mapLookup(full), app.RoleAll)
	if err != nil || loaded.Address != ":9443" || len(loaded.TokenKeys) != 2 || loaded.TokenKeys[1].State != "next" ||
		loaded.ClientURI.String() != full[envFlowLogInternalClientID] {
		t.Fatalf("loaded: %+v %v", loaded, err)
	}
	if printed := fmt.Sprintf("%v %+v %#v", *loaded, *loaded, *loaded); strings.Contains(printed, "secrets") {
		t.Errorf("printed %q", printed)
	}
	cases := map[string]map[string]string{
		"no address":       with(envFlowLogInternalAddr, ""),
		"no CA":            with(envFlowLogInternalClientCA, ""),
		"no keys":          with(envFlowLogTokenPublicKeys, ""),
		"relative cert":    with(envFlowLogInternalCertFile, "tls.crt"),
		"bad address":      with(envFlowLogInternalAddr, "9443"),
		"https identity":   with(envFlowLogInternalClientID, "https://meshflow.example.com/"),
		"no identity path": with(envFlowLogInternalClientID, "spiffe://trust.example"),
		"identity query":   with(envFlowLogInternalClientID, "spiffe://trust.example/meshflow?x=1"),
		"two current":      with(envFlowLogTokenPublicKeys, "current="+key(1)+",current="+key(2)),
		"no current":       with(envFlowLogTokenPublicKeys, "next="+key(1)),
		"same key twice":   with(envFlowLogTokenPublicKeys, "current="+key(1)+",retiring="+key(1)),
		"unknown state":    with(envFlowLogTokenPublicKeys, "current="+key(1)+",spare="+key(2)),
		"short key":        with(envFlowLogTokenPublicKeys, "current=AAAA"),
		"five keys":        with(envFlowLogTokenPublicKeys, "current="+key(1)+",next="+key(2)+",retiring="+key(3)+",revoked="+key(4)+",revoked="+key(5)),
	}
	cases["another path"] = with(envFlowLogInternalClientID, "spiffe://trust.example/other")
	cases["upper-case domain"] = with(envFlowLogInternalClientID, "spiffe://Trust.example/meshflow")
	emptyAddress := with(envFlowLogInternalAddr, "")
	emptyAddress[envFlowLogInternalAddr] = ""
	cases["set but empty"] = emptyAddress
	for name, values := range cases {
		if _, err := loadFlowLogInternalConfig(mapLookup(values), app.RoleAPI); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := loadFlowLogInternalConfig(mapLookup(full), app.RoleControl); err == nil {
		t.Error("loaded for the control role")
	}
}
