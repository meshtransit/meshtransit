package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/client/internal/cli/localapi"
)

func TestNetcheck(t *testing.T) {
	t.Parallel()
	ready := localapi.NATStatus{
		State:           "ready",
		Mapping:         "address-and-port-dependent",
		Filtering:       "unknown",
		Allocation:      "sequential",
		SequentialStep:  2,
		Difficulty:      "hard",
		PublicEndpoint:  "203.0.113.7:41641",
		ServersAnswered: 4,
		ObservedAt:      "2026-10-09T08:00:00Z",
	}
	tests := []struct {
		name     string
		args     []string
		nat      localapi.NATStatus
		err      error
		wantCode int
		want     []string
	}{
		{
			name: "hard", args: []string{"netcheck"}, nat: ready, wantCode: 0,
			want: []string{
				"NAT type: hard", "Mapping: address-and-port-dependent", "Port allocation: sequential (step 2)",
				"Public endpoint: 203.0.113.7:41641", "STUN servers answered: 4",
				"some peers will use a relay", "RFC 5780",
			},
		},
		{
			name: "failed", args: []string{"netcheck"}, nat: localapi.NATStatus{State: "failed", Error: "no_response"},
			wantCode: 1, want: []string{"NAT: failed (no_response)"},
		},
		{name: "daemon error", args: []string{"netcheck"}, err: errors.New("boom"), wantCode: 1},
		{name: "extra argument", args: []string{"netcheck", "now"}, wantCode: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeClient{netcheck: localapi.Netcheck{APIVersion: "v1", NAT: tt.nat}, err: tt.err}
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			if code := Run(t.Context(), tt.args, stdout, stderr, testOptions(client)); code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr=%s", code, tt.wantCode, stderr)
			}
			for _, w := range tt.want {
				if !strings.Contains(stdout.String(), w) {
					t.Errorf("output missing %q:\n%s", w, stdout)
				}
			}
		})
	}
}

func TestNetcheckJSON(t *testing.T) {
	t.Parallel()
	client := &fakeClient{netcheck: localapi.Netcheck{APIVersion: "v1", NAT: localapi.NATStatus{State: "ready", Difficulty: "easy"}}}
	stdout := &bytes.Buffer{}
	if code := Run(t.Context(), []string{"--json", "netcheck"}, stdout, &bytes.Buffer{}, testOptions(client)); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	var got localapi.Netcheck
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil || got.NAT.Difficulty != "easy" {
		t.Fatalf("json = %s, %v", stdout, err)
	}
}

func TestFormatNATSummary(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		nat  *localapi.NATStatus
		want string
	}{
		{nil, "unavailable"},
		{&localapi.NATStatus{State: "pending"}, "pending"},
		{&localapi.NATStatus{State: "failed"}, "failed (none)"},
		{
			&localapi.NATStatus{State: "stale", Difficulty: "easy", Mapping: "none", Filtering: "endpoint-independent", Allocation: "port-preserving"},
			"easy (none mapping, endpoint-independent filtering, port-preserving), stale",
		},
	} {
		if got := formatNATSummary(tt.nat); got != tt.want {
			t.Errorf("formatNATSummary(%+v) = %q, want %q", tt.nat, got, tt.want)
		}
	}
}

func TestFormatPortMapping(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		mapping *localapi.PortMappingStatus
		want    string
	}{
		{nil, "unavailable"},
		{&localapi.PortMappingStatus{State: "off"}, "off"},
		{&localapi.PortMappingStatus{State: "mapped", Protocol: "upnp", ExpiresAt: "2026-10-10T07:00:00Z"}, "upnp, expires 2026-10-10T07:00:00Z"},
		{&localapi.PortMappingStatus{State: "double_nat", Protocol: "nat-pmp"}, "nat-pmp, behind another NAT (not offered to peers)"},
		{&localapi.PortMappingStatus{State: "unavailable", Error: "no_gateway"}, "unavailable (no_gateway)"},
	} {
		if got := formatPortMapping(tt.mapping); got != tt.want {
			t.Errorf("formatPortMapping(%+v) = %q, want %q", tt.mapping, got, tt.want)
		}
	}
}

func TestNetcheckShowsThePortMapping(t *testing.T) {
	t.Parallel()
	client := &fakeClient{netcheck: localapi.Netcheck{
		APIVersion:  "v1",
		NAT:         localapi.NATStatus{State: "ready", Difficulty: "hard"},
		PortMapping: &localapi.PortMappingStatus{State: "mapped", Protocol: "pcp", External: "203.0.113.7:50000"},
	}}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if code := Run(t.Context(), []string{"netcheck"}, stdout, stderr, testOptions(client)); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr)
	}
	for _, want := range []string{"Port mapping: pcp", "Mapped endpoint: 203.0.113.7:50000"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}
}

func TestFormatCloud(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		cloud *localapi.CloudStatus
		want  string
	}{
		{nil, "unavailable"},
		{&localapi.CloudStatus{State: "off"}, "off"},
		{&localapi.CloudStatus{State: "none"}, "not a cloud instance"},
		{&localapi.CloudStatus{State: "ready", Platform: "aws", AddressCount: 1}, "aws (1 public address)"},
		{&localapi.CloudStatus{State: "ready", Platform: "gcp", AddressCount: 2}, "gcp (2 public addresses)"},
		{&localapi.CloudStatus{State: "failed", Platform: "azure", Error: "network"}, "azure (failed: network)"},
	} {
		if got := formatCloud(tt.cloud); got != tt.want {
			t.Errorf("formatCloud(%+v) = %q, want %q", tt.cloud, got, tt.want)
		}
	}
}
