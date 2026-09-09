package ts2021

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestFingerprintVerification(t *testing.T) {
	t.Parallel()

	actual := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name      string
		expected  string
		want      string
		wantError error
	}{
		{
			name:     "canonical",
			expected: actual,
			want:     actual,
		},
		{
			name:     "uppercase hex normalizes",
			expected: "SHA256:" + strings.Repeat("A", 64),
			want:     actual,
		},
		{
			name:      "malformed",
			expected:  "sha256:short",
			wantError: ErrInvalidFingerprint,
		},
		{
			name:      "mismatch",
			expected:  "sha256:" + strings.Repeat("b", 64),
			wantError: ErrFingerprintMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := verifyFingerprint(test.expected, actual)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("verifyFingerprint() error = %v, want %v", err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("verifyFingerprint() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMaterialRoundTripAndRedaction(t *testing.T) {
	t.Parallel()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	controlKey := key.NewMachine().Public()
	material, err := marshalMaterial(machineKey, nodeKey, controlKey)
	if err != nil {
		t.Fatalf("marshalMaterial() error = %v", err)
	}
	parsedMachine, parsedNode, parsedControl, err := parseMaterial(material)
	if err != nil {
		t.Fatalf("parseMaterial() error = %v", err)
	}
	if !parsedMachine.Equal(machineKey) || !parsedNode.Equal(nodeKey) || parsedControl != controlKey {
		t.Fatal("parsed material does not match generated keys")
	}

	for _, rendered := range []string{fmt.Sprintf("%v", material), fmt.Sprintf("%#v", material)} {
		for _, secret := range [][]byte{
			material.MachinePrivateKey,
			material.NodePrivateKey,
			material.ControlPublicKey,
		} {
			if strings.Contains(rendered, string(secret)) {
				t.Fatalf("formatted material contains secret: %q", rendered)
			}
		}
	}
}

func TestNewRegisterRequest_OmitsNetworkSelector(t *testing.T) {
	t.Parallel()

	request := newRegisterRequest(key.NewNode(), RegisterOptions{
		Hostname:          "node-a",
		Version:           "meshd/dev",
		PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
		AuthKey:           "credential-value",
	})
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"network_id", `"Tailnet"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("registration request contains forbidden field %q: %s", forbidden, encoded)
		}
	}
	if request.Version != tailcfg.CurrentCapabilityVersion {
		t.Fatalf("Version = %d, want %d", request.Version, tailcfg.CurrentCapabilityVersion)
	}
	if request.Auth == nil || request.Auth.AuthKey == "" {
		t.Fatal("registration request omitted supplied in-memory auth key")
	}
}

func TestDecodeRegistrationResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		wantState RegistrationState
		wantError error
	}{
		{
			name:      "authorized",
			body:      `{"MachineAuthorized":true}`,
			wantState: RegistrationStateAuthorized,
		},
		{
			name:      "browser authorization",
			body:      `{"AuthURL":"https://control.example.com/register/opaque"}`,
			wantState: RegistrationStateAuthorizationRequired,
		},
		{
			name:      "cross-origin authorization url",
			body:      `{"AuthURL":"https://evil.example.net/register/opaque"}`,
			wantError: ErrRegistration,
		},
		{
			name:      "expired node key",
			body:      `{"NodeKeyExpired":true}`,
			wantError: ErrNodeKeyExpired,
		},
		{
			name:      "ambiguous",
			body:      `{"MachineAuthorized":true,"AuthURL":"https://control.example.com/register/opaque"}`,
			wantError: ErrRegistration,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			response := &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"application/json; charset=utf-8"},
				},
				Body: io.NopCloser(strings.NewReader(test.body)),
			}
			result, err := decodeRegistrationResponse(response, "https://control.example.com")
			if !errors.Is(err, test.wantError) {
				t.Fatalf("decodeRegistrationResponse() error = %v, want %v", err, test.wantError)
			}
			if result.State != test.wantState {
				t.Fatalf("State = %q, want %q", result.State, test.wantState)
			}
		})
	}
}

func TestValidateRegisterOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		options RegisterOptions
	}{
		{
			name: "auth and followup together",
			options: RegisterOptions{
				Hostname:          "node-a",
				Version:           "meshd/dev",
				PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
				AuthKey:           "credential",
				FollowupURL:       "https://control.example.com/register/opaque",
			},
		},
		{
			name: "auth key surrounding whitespace",
			options: RegisterOptions{
				Hostname:          "node-a",
				Version:           "meshd/dev",
				PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
				AuthKey:           " credential ",
			},
		},
		{
			name: "auth key internal whitespace",
			options: RegisterOptions{
				Hostname:          "node-a",
				Version:           "meshd/dev",
				PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
				AuthKey:           "credential value",
			},
		},
		{
			name: "auth key invalid utf8",
			options: RegisterOptions{
				Hostname:          "node-a",
				Version:           "meshd/dev",
				PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
				AuthKey:           string([]byte{0xff}),
			},
		},
		{
			name: "empty hostname",
			options: RegisterOptions{
				Version:           "meshd/dev",
				PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := validateRegisterOptions("https://control.example.com", test.options); err == nil {
				t.Fatal("validateRegisterOptions() error = nil, want validation error")
			}
		})
	}
}

func TestSanitizeServerError_PreservesUTF8(t *testing.T) {
	t.Parallel()

	message := strings.Repeat("ổ", maxServerErrorRunes+1)
	got := sanitizeServerError(message)
	if !utf8.ValidString(got) {
		t.Fatal("sanitizeServerError() returned invalid UTF-8")
	}
	if got != strings.Repeat("ổ", maxServerErrorRunes) {
		t.Fatalf("sanitizeServerError() rune count = %d, want %d", len([]rune(got)), maxServerErrorRunes)
	}
}

func TestNodePrivateRaw(t *testing.T) {
	t.Parallel()

	nodeKey := key.NewNode()
	encoded, err := nodeKey.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	got, err := NodePrivateRaw(KeyMaterial{NodePrivateKey: encoded})
	if err != nil {
		t.Fatalf("NodePrivateRaw() error = %v", err)
	}
	if got != nodeKey.Raw32() {
		t.Fatal("NodePrivateRaw() returned different key bytes")
	}
	clear(got[:])
	if _, err := NodePrivateRaw(KeyMaterial{NodePrivateKey: []byte("invalid")}); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("invalid NodePrivateRaw() error = %v", err)
	}
}
