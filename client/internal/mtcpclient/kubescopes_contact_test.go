package mtcpclient

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// A table's access contact is kept in form, else shown as none; it never
// makes the table unusable (mtcp-v1 §7.12).
func TestCompileKubernetesScopesKeepsTheAccessContact(t *testing.T) {
	t.Parallel()
	for contact, want := range map[string]string{
		"#k8s-access on Slack":   "#k8s-access on Slack",
		"":                       "",
		strings.Repeat("a", 257): "",
		"line\nbreak":            "",
		"rtl\u202eoverride":      "",
		string([]byte{0xff}):     "",
	} {
		compiled := compileKubernetesScopes(&mtcpv1.KubernetesScopeTable{AccessContact: contact})
		if compiled.withheld || compiled.contact != want {
			t.Errorf("contact %q: kept %q, withheld %t", contact, compiled.contact, compiled.withheld)
		}
	}
}

// A delta whose table changes only its contact reaches the snapshot; an
// empty table clears it (review d4b M3).
func TestAccessContactAcrossDeltas(t *testing.T) {
	t.Parallel()
	message, _ := fixture(t)
	message.KubernetesScopes.AccessContact = "#k8s-access"
	state := gatewayState(true)
	if err := state.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	if got := build(t, state).KubernetesAccessContact; got != "#k8s-access" {
		t.Fatalf("snapshot contact = %q", got)
	}
	changed, ok := proto.Clone(message.KubernetesScopes).(*mtcpv1.KubernetesScopeTable)
	if !ok {
		t.Fatal("clone")
	}
	changed.AccessContact = "platform@example.com"
	for seq, test := range []struct {
		table *mtcpv1.KubernetesScopeTable
		want  string
	}{{changed, "platform@example.com"}, {&mtcpv1.KubernetesScopeTable{}, ""}} {
		if err := state.applyDelta(&mtcpv1.MapDelta{
			View:             &mtcpv1.View{Epoch: 7, Seq: uint64(seq) + 2},
			KubernetesScopes: test.table,
		}); err != nil {
			t.Fatal(err)
		}
		if got := build(t, state).KubernetesAccessContact; got != test.want {
			t.Fatalf("delta %d: contact = %q", seq, got)
		}
	}
}
