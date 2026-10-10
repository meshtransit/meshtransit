package key

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestMachineAndControlKeys(t *testing.T) {
	machine, err := MachinePrivateFromBytes(bytes.Repeat([]byte{0x11}, Size))
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedMachine, err := ParseMachinePublic(machine.Public().String())
	if err != nil || parsedMachine != machine.Public() || !strings.HasPrefix(machine.Public().String(), "mtmachine:") {
		t.Fatalf("machine key text form: %v", err)
	}
	parsedControl, err := ParseControlPublic(control.Public().String())
	if err != nil || parsedControl != control.Public() {
		t.Fatalf("control key text form: %v", err)
	}
	if _, err := ParseControlPublic(machine.Public().String()); err == nil {
		t.Fatal("a machine key parsed as a control key")
	}
	if _, err := MachinePrivateFromBytes(make([]byte, Size)); err == nil {
		t.Fatal("zero private key accepted")
	}
	node, _ := NodePrivateFromBytes(bytes.Repeat([]byte{0x77}, Size))
	nodeSecret, err := node.SharedWithControl(control.Public())
	if err != nil {
		t.Fatal(err)
	}
	controlSecret, err := control.SharedWithPublic(node.Public())
	if err != nil || nodeSecret != controlSecret {
		t.Fatalf("X25519 disagreed: %v", err)
	}
	for _, private := range []fmt.Stringer{machine, control, node} {
		if text := fmt.Sprintf("%v %+v %s", private, private, private); !strings.Contains(text, "REDACTED") ||
			strings.Contains(text, "1111") {
			t.Fatalf("private key formatted as %q", text)
		}
	}
	if control.Public().ID() == (KeyID{}) || control.Public().ID() == ControlPublic(machine.Public()).ID() {
		t.Fatal("control key IDs collide")
	}
}
