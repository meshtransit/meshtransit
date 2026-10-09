package key

import (
	"fmt"
	"strings"
	"testing"
)

func TestRelayPrivateText(t *testing.T) {
	t.Parallel()
	k, err := NewRelayPrivate()
	if err != nil {
		t.Fatal(err)
	}
	text := k.PrivateText()
	if !strings.HasPrefix(text, "privkey:") || len(text) != len("privkey:")+64 {
		t.Fatalf("text form %d bytes", len(text))
	}
	back, err := ParseRelayPrivateText(text)
	if err != nil || back.Public() != k.Public() {
		t.Fatalf("round trip: %v", err)
	}
	if s := fmt.Sprint(back); strings.Contains(s, text[8:]) {
		t.Fatal("formatting reveals the private key")
	}
	for _, bad := range []string{"", text[:len(text)-1], strings.ToUpper(text), "privkey:" + strings.Repeat("0", 64), "mtrelay:" + text[8:]} {
		if _, err := ParseRelayPrivateText(bad); err == nil {
			t.Errorf("accepted %q", bad[:min(len(bad), 12)])
		}
	}
	fromFile, err := ParseRelayPrivateBytes([]byte("  " + text + "\n"))
	if err != nil || fromFile.Public() != k.Public() {
		t.Fatalf("bytes form: %v", err)
	}
	if _, err := ParseRelayPrivateBytes([]byte(strings.ToUpper(text))); err == nil {
		t.Fatal("upper-case hex accepted")
	}
	if (RelayPrivate{}).PrivateText() != "" {
		t.Fatal("zero key has a text form")
	}
}
