package mtcpclient

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func TestProbeUsesTheUpgradeAndFallsBackToWebSocket(t *testing.T) {
	t.Parallel()
	for _, refuse := range []bool{false, true} {
		core := newFakeCore(t)
		core.set(func(core *fakeCore) { core.refuseUp = refuse })
		result, err := core.client().Probe(t.Context(), core.origin())
		if err != nil {
			t.Fatalf("refuse upgrade %t: %v", refuse, err)
		}
		if result.Protocol != Protocol || result.KeyFingerprint != controlplane.ControlKeyFingerprint(core.controlKey().Public()) {
			t.Fatalf("result %+v", result)
		}
		_, modes := core.sessions()
		want := "upgrade"
		if refuse {
			want = "websocket"
		}
		if len(modes) != 1 || modes[0] != want {
			t.Fatalf("refuse upgrade %t: sessions %v, want %s", refuse, modes, want)
		}
	}
}

func TestBootstrapTrust(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	public := core.controlKey().Public()
	for name, pin := range map[string]string{
		"control key fingerprint": strings.ToUpper(controlplane.ControlKeyFingerprint(public)[:6]) +
			controlplane.ControlKeyFingerprint(public)[6:],
		"enrollment link fingerprint": sharedmtcp.ControlFingerprint(public),
	} {
		trust, err := core.client().BootstrapTrust(t.Context(), core.origin(), pin)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if trust.Fingerprint != controlplane.ControlKeyFingerprint(public) {
			t.Fatalf("%s: stored pin %q", name, trust.Fingerprint)
		}
		control, err := controlplane.ParseControlPublicKey(trust.Material.ControlPublicKey)
		if err != nil || key.ControlPublic(control) != public {
			t.Fatalf("%s: material control key %v", name, err)
		}
		if _, err := controlplane.ParsePrivateKey(trust.Material.MachinePrivateKey); err != nil {
			t.Fatalf("%s: machine key %v", name, err)
		}
	}
	other := controlplane.ControlKeyFingerprint([32]byte{9})
	if _, err := core.client().BootstrapTrust(t.Context(), core.origin(), other); !errors.Is(err,
		controlplane.ErrFingerprintMismatch) {
		t.Fatalf("other key's pin: %v", err)
	}
	if _, err := core.client().BootstrapTrust(t.Context(), core.origin(), "sha256:nope"); !errors.Is(err,
		controlplane.ErrInvalidFingerprint) {
		t.Fatalf("malformed pin: %v", err)
	}
}

func TestVerifyTrust(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	client := core.client()
	trust, err := client.BootstrapTrust(t.Context(), core.origin(), controlplane.ControlKeyFingerprint(core.controlKey().Public()))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyTrust(t.Context(), core.origin(), trust.Material, trust.Fingerprint); err != nil {
		t.Fatalf("VerifyTrust: %v", err)
	}
	if err := client.VerifyTrust(t.Context(), core.origin(), trust.Material,
		controlplane.ControlKeyFingerprint([32]byte{9})); !errors.Is(err, controlplane.ErrControlKeyChanged) {
		t.Fatalf("another pin: %v", err)
	}
	rotated, _ := key.NewControlPrivate(nil)
	core.set(func(core *fakeCore) { core.documented = []key.ControlPublic{rotated.Public()} })
	if err := client.VerifyTrust(t.Context(), core.origin(), trust.Material, trust.Fingerprint); !errors.Is(err,
		controlplane.ErrControlKeyChanged) {
		t.Fatalf("key no longer offered: %v", err)
	}
}

func TestUnknownKeyIsNotRetriedOverWebSocket(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	trust, err := core.client().BootstrapTrust(t.Context(), core.origin(), controlplane.ControlKeyFingerprint(core.controlKey().Public()))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := key.NewControlPrivate(nil)
	profileKey := mustControl(t, trust.Material.ControlPublicKey)
	core.set(func(core *fakeCore) {
		core.control = other // the origin lost the profile's key
		core.documented = []key.ControlPublic{other.Public(), profileKey}
	})
	err = core.client().VerifyTrust(t.Context(), core.origin(), trust.Material, trust.Fingerprint)
	if !errors.Is(err, errUnknownKey) {
		t.Fatalf("VerifyTrust = %v, want unknown key", err)
	}
	if _, modes := core.sessions(); len(modes) != 1 {
		t.Fatalf("sessions %v: an unknown key must not be retried", modes)
	}
}

func mustControl(t *testing.T, text []byte) key.ControlPublic {
	t.Helper()
	raw, err := controlplane.ParseControlPublicKey(text)
	if err != nil {
		t.Fatal(err)
	}
	return key.ControlPublic(raw)
}

func TestOriginValidation(t *testing.T) {
	t.Parallel()
	client := New()
	for _, bad := range []string{
		"http://control.example", "https://control.example:8443", "https://u@control.example",
		"https://control.example/path", "https://control.example?x=1", "https://",
	} {
		if _, err := client.origin(bad); err == nil {
			t.Errorf("origin(%q) accepted", bad)
		}
	}
	for _, good := range []string{"https://control.example", "https://control.example:443", "https://control.example/"} {
		if origin, err := client.origin(good); err != nil || origin.Host != "control.example:443" {
			t.Errorf("origin(%q) = %v, %v", good, origin, err)
		}
	}
}
