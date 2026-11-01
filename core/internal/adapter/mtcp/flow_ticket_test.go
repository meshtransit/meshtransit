package mtcp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/flowlog"
	"meshtransit.net/shared/key"
)

func testFlowSigner(t *testing.T, now func() time.Time) (*FlowSigner, ed25519.PublicKey, string, []byte) {
	t.Helper()
	signing, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := signing.Public()
	receiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := must(deployment.ParseID("01890f00-0000-7000-8000-000000000123"))
	signer, err := NewFlowSigner(signing, ed25519.PublicKey(public[:]), deploymentID, receiver.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	return signer, ed25519.PublicKey(public[:]), "meshflow:" + deploymentID.String(), receiver.PublicKey().Bytes()
}

func testFlowGrant(t *testing.T, machine key.MachinePublic) mapsession.FlowGrant {
	t.Helper()
	snapshot := snapshotFixture(t, 7)
	return mapsession.FlowGrant{
		Scope: snapshot.Scope(), Device: snapshot.NodeID(), MachineKey: node.MachineKey(machine),
		Roles:         []mapsession.FlowRole{mapsession.FlowRoleDevice, mapsession.FlowRoleRouter},
		Sites:         []publicid.ID{must(publicid.Parse("01890f00-0000-7000-8000-0000000000a1"))},
		WindowSeconds: 120, NotAfter: time.Now().Add(time.Hour),
	}
}

// A session that negotiated flow.report1 gets a token the receiver
// accepts, for its own machine key only; logging off is an empty ticket.
func TestSinkSendsFlowTickets(t *testing.T) {
	session, peer, control := testSession(t)
	session.capabilities = append(session.capabilities, CapabilityFlowReport)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	signer, public, audience, receiverKey := testFlowSigner(t, time.Now)
	sink.flow = signer
	grant := testFlowGrant(t, session.Machine())

	expires, err := sink.SendFlowTicket(t.Context(), grant, true)
	if err != nil || expires.IsZero() {
		t.Fatalf("SendFlowTicket() = %v, %v", expires, err)
	}
	_, message, _ := peer.read()
	ticket, ok := message.(*mtcpv1.FlowTicket)
	if !ok || !bytes.Equal(ticket.GetReceiverKey(), receiverKey) || ticket.GetNotAfterMs() != expires.UnixMilli() {
		t.Fatalf("sent %T %v", message, message)
	}
	keys := map[string]ed25519.PublicKey{flowlog.SigningKeyID(public): public}
	verified, err := flowlog.VerifyToken(ticket.GetToken(), keys, audience, time.Now())
	if err != nil {
		t.Fatalf("VerifyToken() = %v", err)
	}
	machine := session.Machine()
	claims, err := verified.Claims(machine[:])
	if err != nil {
		t.Fatalf("Claims() = %v", err)
	}
	device := publicid.ID(grant.Device).Bytes()
	site := grant.Sites[0].Bytes()
	if !bytes.Equal(claims.GetDeviceId(), device[:]) || claims.GetWindowS() != 120 ||
		len(claims.GetRoles()) != 2 || claims.GetRoles()[1] != flowlogv1.FlowTokenClaims_ROUTER ||
		len(claims.GetSiteIds()) != 1 || !bytes.Equal(claims.GetSiteIds()[0], site[:]) ||
		claims.GetExpiresAtMs()-claims.GetIssuedAtMs() != flowlog.MaxTokenLifetime.Milliseconds() {
		t.Fatalf("claims = %v", claims)
	}

	if _, err := sink.SendFlowTicket(t.Context(), grant, false); err != nil {
		t.Fatal(err)
	}
	if _, message, _ := peer.read(); len(message.(*mtcpv1.FlowTicket).GetToken()) != 0 {
		t.Fatalf("off sent %v", message)
	}

	// Another machine key, or an authority about to end, gets nothing.
	other := grant
	other.MachineKey = node.MachineKey{9}
	if expires, err := sink.SendFlowTicket(t.Context(), other, true); err != nil || !expires.IsZero() {
		t.Fatalf("another key: %v %v", expires, err)
	}
	ending := grant
	ending.NotAfter = time.Now().Add(time.Minute)
	if expires, err := sink.SendFlowTicket(t.Context(), ending, true); err != nil || !expires.IsZero() {
		t.Fatalf("an ending authority: %v %v", expires, err)
	}
	// A shorter authority bounds the token.
	short := grant
	short.NotAfter = time.Now().Add(5 * time.Minute)
	if expires, err := sink.SendFlowTicket(t.Context(), short, true); err != nil ||
		expires.After(short.NotAfter) {
		t.Fatalf("a short authority: %v %v", expires, err)
	}
}

// Without flow.report1, or without a signer, the session takes none.
func TestSinkRefusesFlowTicketsWithoutTheCapability(t *testing.T) {
	session, _, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	grant := testFlowGrant(t, session.Machine())
	if _, err := sink.SendFlowTicket(t.Context(), grant, true); !errors.Is(err, mapsession.ErrNoFlowTickets) {
		t.Fatalf("without a signer: %v", err)
	}
	sink.flow, _, _, _ = testFlowSigner(t, time.Now)
	if _, err := sink.SendFlowTicket(t.Context(), grant, true); !errors.Is(err, mapsession.ErrNoFlowTickets) {
		t.Fatalf("without flow.report1: %v", err)
	}
}

func TestNewFlowSignerRefusesMissingKeys(t *testing.T) {
	t.Parallel()
	signing, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := signing.Public()
	receiver, _ := ecdh.X25519().GenerateKey(rand.Reader)
	deploymentID := must(deployment.ParseID("01890f00-0000-7000-8000-000000000123"))
	for name, build := range map[string]func() (*FlowSigner, error){
		"no signer": func() (*FlowSigner, error) {
			return NewFlowSigner(nil, ed25519.PublicKey(public[:]), deploymentID, receiver.PublicKey(), time.Now)
		},
		"short public": func() (*FlowSigner, error) {
			return NewFlowSigner(signing, ed25519.PublicKey(public[:8]), deploymentID, receiver.PublicKey(), time.Now)
		},
		"no deployment": func() (*FlowSigner, error) {
			return NewFlowSigner(signing, ed25519.PublicKey(public[:]), deployment.ID{}, receiver.PublicKey(), time.Now)
		},
		"no receiver": func() (*FlowSigner, error) {
			return NewFlowSigner(signing, ed25519.PublicKey(public[:]), deploymentID, nil, time.Now)
		},
	} {
		if _, err := build(); !errors.Is(err, ErrInvalidFlowSigner) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A paused or withdrawn map takes back the token the node holds, once.
func TestSinkWithdrawsTheFlowTicketWithTheMap(t *testing.T) {
	session, peer, control := testSession(t)
	session.capabilities = append(session.capabilities, CapabilityFlowReport)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	sink.flow, _, _, _ = testFlowSigner(t, time.Now)
	if err := sink.SendAuthorityWithdrawal(t.Context(), mapsession.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.SendFlowTicket(t.Context(), testFlowGrant(t, session.Machine()), true); err != nil {
		t.Fatal(err)
	}
	peer.read()
	if err := sink.SendAuthorityPause(t.Context(), mapsession.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, message, _ := peer.read(); len(message.(*mtcpv1.FlowTicket).GetToken()) != 0 {
		t.Fatalf("pause sent %v first", message)
	}
	if _, message, _ := peer.read(); message.(*mtcpv1.Lifecycle).GetState() != mtcpv1.Lifecycle_SUSPENDED {
		t.Fatalf("then %v", message)
	}
	if err := sink.SendAuthorityWithdrawal(t.Context(), mapsession.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if sink.flowSent.Load() {
		t.Fatal("the ticket is still held")
	}
}

// A Kubernetes gateway takes no tickets yet (C36).
func TestGatewaySessionsTakeNoFlowTickets(t *testing.T) {
	session, _, control := testSession(t)
	session.capabilities = append(session.capabilities, CapabilityFlowReport)
	session.gate.Gateway = true
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	sink.flow, _, _, _ = testFlowSigner(t, time.Now)
	if sink.TakesFlowTickets() {
		t.Fatal("a gateway takes tickets")
	}
}

// A public key that is not the signer's would name the wrong kid.
func TestNewFlowSignerRefusesAnotherPublicKey(t *testing.T) {
	t.Parallel()
	signing, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x63}, 32))
	other, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x64}, 32))
	public := other.Public()
	receiver, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := NewFlowSigner(signing, ed25519.PublicKey(public[:]),
		must(deployment.ParseID("01890f00-0000-7000-8000-000000000123")), receiver.PublicKey(), time.Now); !errors.Is(err, ErrInvalidFlowSigner) {
		t.Fatalf("NewFlowSigner() = %v", err)
	}
}
