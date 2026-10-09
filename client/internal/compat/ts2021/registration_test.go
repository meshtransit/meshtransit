package ts2021

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

func TestNewNodeKeyRotationRequestBindsExactOldAndNewKeys(t *testing.T) {
	t.Parallel()

	oldNodeKey := key.NewNode()
	newNodeKey := key.NewNode()
	request := newNodeKeyRotationRequest(oldNodeKey, newNodeKey, RegisterOptions{
		Hostname:          "node-a",
		Version:           "meshd/dev",
		PinnedFingerprint: "sha256:" + strings.Repeat("a", 64),
	})
	if request.OldNodeKey != oldNodeKey.Public() || request.NodeKey != newNodeKey.Public() {
		t.Fatal("Node-key rotation request did not bind exact old/new public keys")
	}
	if request.Auth != nil || request.Followup != "" {
		t.Fatal("Node-key rotation request carried login authority")
	}
}

func TestGenerateNodePrivateKeyProducesValidDistinctKeys(t *testing.T) {
	t.Parallel()

	first, err := GenerateNodePrivateKey()
	if err != nil {
		t.Fatalf("GenerateNodePrivateKey(first) error = %v", err)
	}
	defer clear(first)
	second, err := GenerateNodePrivateKey()
	if err != nil {
		t.Fatalf("GenerateNodePrivateKey(second) error = %v", err)
	}
	defer clear(second)
	var firstKey, secondKey key.NodePrivate
	if err := firstKey.UnmarshalText(first); err != nil || firstKey.IsZero() {
		t.Fatalf("generated first Node key is invalid: %v", err)
	}
	if err := secondKey.UnmarshalText(second); err != nil || secondKey.IsZero() {
		t.Fatalf("generated second Node key is invalid: %v", err)
	}
	if firstKey.Public() == secondKey.Public() {
		t.Fatal("generated Node keys are identical")
	}
}

func TestDecodeRegistrationResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		status        int
		body          string
		wantState     RegistrationState
		wantError     error
		wantTemporary bool
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
		{
			name:          "rate limited",
			status:        http.StatusTooManyRequests,
			wantError:     ErrRegistration,
			wantTemporary: true,
		},
		{
			name:          "service unavailable",
			status:        http.StatusServiceUnavailable,
			wantError:     ErrRegistration,
			wantTemporary: true,
		},
		{
			name:      "unauthorized",
			status:    http.StatusUnauthorized,
			wantError: ErrRegistration,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			status := test.status
			if status == 0 {
				status = http.StatusOK
			}
			response := &http.Response{
				StatusCode: status,
				Header: http.Header{
					"Content-Type": []string{"application/json; charset=utf-8"},
				},
				Body: io.NopCloser(strings.NewReader(test.body)),
			}
			result, err := decodeRegistrationResponse(response, "https://control.example.com")
			if !errors.Is(err, test.wantError) {
				t.Fatalf("decodeRegistrationResponse() error = %v, want %v", err, test.wantError)
			}
			if got := errors.Is(err, ErrRegistrationTemporary); got != test.wantTemporary {
				t.Fatalf("temporary classification = %t, want %t: %v", got, test.wantTemporary, err)
			}
			if result.State != test.wantState {
				t.Fatalf("State = %q, want %q", result.State, test.wantState)
			}
		})
	}
}

func TestClient_RegisterClassifiesTemporaryDiscoveryFailures(t *testing.T) {
	t.Parallel()

	controlKey := key.NewMachine().Public()
	material, err := marshalMaterial(key.NewMachine(), key.NewNode(), controlKey)
	if err != nil {
		t.Fatalf("marshalMaterial() error = %v", err)
	}
	options := RegisterOptions{
		Hostname:          "node-a",
		Version:           "meshd/test",
		PinnedFingerprint: controlKeyFingerprint(controlKey),
	}
	tests := []struct {
		name          string
		status        int
		transportErr  error
		wantTemporary bool
	}{
		{
			name:          "control key service unavailable",
			status:        http.StatusServiceUnavailable,
			wantTemporary: true,
		},
		{
			name:   "control key unauthorized",
			status: http.StatusUnauthorized,
		},
		{
			name: "control key lookup timeout",
			transportErr: &net.DNSError{
				Err:       "test timeout",
				Name:      "control.example.com",
				IsTimeout: true,
			},
			wantTemporary: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := newWithHTTPClient(&http.Client{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					if test.transportErr != nil {
						return nil, test.transportErr
					}

					return jsonResponse(test.status, `{}`), nil
				}),
			})
			_, err := client.Register(
				t.Context(),
				"https://control.example.com",
				material,
				options,
			)
			if err == nil {
				t.Fatal("Register() error = nil, want discovery failure")
			}
			if got := errors.Is(err, ErrRegistrationTemporary); got != test.wantTemporary {
				t.Fatalf("temporary classification = %t, want %t: %v", got, test.wantTemporary, err)
			}
		})
	}
}

func TestRegistrationOperationError(t *testing.T) {
	t.Parallel()

	parentCtx, cancelParent := context.WithCancel(t.Context())
	cancelParent()
	if err := registrationOperationError(
		parentCtx,
		t.Context(),
		errors.New("test transport failure"),
	); !errors.Is(err, context.Canceled) || errors.Is(err, ErrRegistrationTemporary) {
		t.Fatalf("parent cancellation error = %v", err)
	}

	operationCtx, cancelOperation := context.WithTimeout(t.Context(), 0)
	defer cancelOperation()
	err := registrationOperationError(
		t.Context(),
		operationCtx,
		errors.New("test stalled response body"),
	)
	if !errors.Is(err, ErrRegistrationTemporary) {
		t.Fatalf("operation deadline error = %v, want ErrRegistrationTemporary", err)
	}

	protocolErr := errors.New("test malformed response")
	if err := registrationOperationError(t.Context(), t.Context(), protocolErr); !errors.Is(err, protocolErr) || errors.Is(err, ErrRegistrationTemporary) {
		t.Fatalf("permanent protocol error = %v", err)
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
