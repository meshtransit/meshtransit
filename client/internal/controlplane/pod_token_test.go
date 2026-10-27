package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// A pod token never shows, whatever prints the struct that holds it (K1.1).
func TestPodTokenRedacts(t *testing.T) {
	t.Parallel()
	options := RegisterOptions{Hostname: "meshgw-0", GatewayToken: "secret-pod-token"}
	encoded, err := json.Marshal(options) //nolint:gosec // G117: the test proves the token is redacted
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("rotate", "options", options, "token", options.GatewayToken)
	for _, text := range []string{
		fmt.Sprintf("%v", options), fmt.Sprintf("%+v", options),
		fmt.Sprintf("%#v", options), string(encoded), logged.String(),
	} {
		if strings.Contains(text, "secret-pod-token") {
			t.Fatalf("the token shows in %s", text)
		}
	}
	if options.GatewayToken.Reveal() != "secret-pod-token" {
		t.Fatal("Reveal() lost the token")
	}
}
