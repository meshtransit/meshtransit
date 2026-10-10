package controlselect

import (
	"context"
	"errors"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/mtcpclient"
)

// fakeProtocol records calls and fails with err.
type fakeProtocol struct {
	name  string
	err   error
	calls *[]string
}

func (p fakeProtocol) record(op string) { *p.calls = append(*p.calls, p.name+"."+op) }

func (p fakeProtocol) Probe(context.Context, string) (controlplane.Result, error) {
	p.record("probe")
	return controlplane.Result{Protocol: p.name}, p.err
}

func (p fakeProtocol) BootstrapTrust(context.Context, string, string) (controlplane.TrustResult, error) {
	p.record("trust")
	return controlplane.TrustResult{}, p.err
}

func (p fakeProtocol) VerifyTrust(context.Context, string, controlplane.KeyMaterial, string) error {
	p.record("verify")
	return p.err
}

func (p fakeProtocol) Register(context.Context, string, controlplane.KeyMaterial, controlplane.RegisterOptions) (
	controlplane.RegistrationResult, error,
) {
	p.record("register")
	return controlplane.RegistrationResult{}, p.err
}

func (p fakeProtocol) RotateNodeKey(context.Context, string, controlplane.KeyMaterial, []byte,
	controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	p.record("rotate")
	return controlplane.RegistrationResult{}, p.err
}

func (p fakeProtocol) StreamNetmap(context.Context, string, controlplane.KeyMaterial, controlplane.NetmapOptions,
	controlplane.NetmapHandler,
) error {
	p.record("stream")
	return p.err
}

func TestAutoFallsBackOnlyWhenMTCPIsNotServed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		mode     Mode
		mtcpErr  error
		want     []string
		wantName string
	}{
		{name: "auto uses MTCP", mode: ModeAuto, want: []string{"mtcp.probe"}, wantName: "mtcp"},
		{
			name: "auto falls back when not served", mode: ModeAuto, mtcpErr: mtcpclient.ErrUnavailable,
			want: []string{"mtcp.probe", "legacy.probe"}, wantName: "legacy",
		},
		{
			name: "auto keeps other MTCP errors", mode: ModeAuto, mtcpErr: controlplane.ErrControlKeyChanged,
			want: []string{"mtcp.probe"}, wantName: "mtcp",
		},
		{
			name: "mtcp only", mode: ModeMTCP, mtcpErr: mtcpclient.ErrUnavailable, want: []string{"mtcp.probe"},
			wantName: "mtcp",
		},
		{name: "legacy only", mode: ModeLegacy, want: []string{"legacy.probe"}, wantName: "legacy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var calls []string
			client, err := New(test.mode, fakeProtocol{name: "mtcp", err: test.mtcpErr, calls: &calls},
				fakeProtocol{name: "legacy", calls: &calls})
			if err != nil {
				t.Fatal(err)
			}
			result, _ := client.Probe(t.Context(), "https://control.example")
			if result.Protocol != test.wantName || len(calls) != len(test.want) {
				t.Fatalf("result %q, calls %v; want %q via %v", result.Protocol, calls, test.wantName, test.want)
			}
			for i := range calls {
				if calls[i] != test.want[i] {
					t.Fatalf("calls %v, want %v", calls, test.want)
				}
			}
		})
	}
}

func TestEveryOperationFallsBack(t *testing.T) {
	t.Parallel()
	var calls []string
	client, err := New(ModeAuto, fakeProtocol{name: "mtcp", err: mtcpclient.ErrUnavailable, calls: &calls},
		fakeProtocol{name: "legacy", calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	material := controlplane.KeyMaterial{}
	_, _ = client.BootstrapTrust(ctx, "u", "p")
	_ = client.VerifyTrust(ctx, "u", material, "p")
	_, _ = client.Register(ctx, "u", material, controlplane.RegisterOptions{})
	_, _ = client.RotateNodeKey(ctx, "u", material, nil, controlplane.RegisterOptions{})
	_ = client.StreamNetmap(ctx, "u", material, controlplane.NetmapOptions{}, nil)
	want := []string{
		"mtcp.trust", "legacy.trust", "mtcp.verify", "legacy.verify", "mtcp.register",
		"legacy.register", "mtcp.rotate", "legacy.rotate", "mtcp.stream", "legacy.stream",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls %v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls %v, want %v", calls, want)
		}
	}
}

func TestModes(t *testing.T) {
	t.Parallel()
	if _, err := ParseMode("ts2021"); !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("unknown mode: %v", err)
	}
	var calls []string
	if _, err := New(ModeAuto, fakeProtocol{calls: &calls}, nil); !errors.Is(err, ErrInvalidMode) {
		t.Fatal("auto needs both protocols")
	}
	if _, err := New(ModeMTCP, fakeProtocol{calls: &calls}, nil); err != nil {
		t.Fatalf("mtcp alone: %v", err)
	}
}
