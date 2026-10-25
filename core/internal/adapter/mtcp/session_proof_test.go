package mtcp

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// gatewayGuard answers handshakes as schema 226 would for the machine keys
// it knows, and records the gateway timestamps committed after a proof.
type gatewayGuard struct {
	mu        sync.Mutex
	checks    map[[32]byte]TimestampCheck
	commitOK  bool
	committed []int64
}

func (guard *gatewayGuard) AcceptTimestamp(_ context.Context, machine [32]byte, _ []byte, _ int64) (
	TimestampCheck, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if check, found := guard.checks[machine]; found {
		return check, nil
	}
	return TimestampCheck{Accepted: true, Machine: MachineUnbound}, nil
}

func (guard *gatewayGuard) CommitGatewayTimestamp(_ context.Context, _ [32]byte, _ []byte, timestamp int64) (
	bool, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.committed = append(guard.committed, timestamp)
	return guard.commitOK, nil
}

func (guard *gatewayGuard) commits() int {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return len(guard.committed)
}

type provingNode struct {
	machine key.MachinePrivate
	node    key.NodePrivate
}

func newProvingNode(t *testing.T, seed byte) provingNode {
	t.Helper()
	machine, err := key.MachinePrivateFromBytes(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := key.NodePrivateFromBytes(bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return provingNode{machine: machine, node: nodeKey}
}

func (n provingNode) fingerprint() [32]byte {
	return node.MachineKey(n.machine.Public()).Fingerprint()
}

func (c *client) proveNodeKey(nodeKey key.NodePrivate, control key.ControlPublic) {
	c.t.Helper()
	proof, err := sharedmtcp.NodeKeySessionProof(nodeKey, control, c.session.HandshakeHash())
	if err != nil {
		c.t.Fatal(err)
	}
	c.send(sharedmtcp.MessageNodeKeyProof, &mtcpv1.NodeKeyProof{Proof: proof[:]})
}

// expectClosedWith reads an Error, then the end of the session.
func (c *client) expectClosedWith(code mtcpv1.Error_Code, message string) {
	c.t.Helper()
	failure := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
	if failure.GetCode() != code || !failure.GetFatal() || failure.GetMessage() != message {
		c.t.Fatalf("error %+v, want fatal %v %q", failure, code, message)
	}
	if _, _, err := c.receive(); err == nil {
		c.t.Fatal("the session stayed open")
	}
}

func newGatewayFixture(t *testing.T, gateway provingNode, check TimestampCheck) (*fixture, *gatewayGuard) {
	t.Helper()
	guard := &gatewayGuard{checks: map[[32]byte]TimestampCheck{gateway.fingerprint(): check}, commitOK: true}
	return newFixture(t, func(options *Options) { options.Guard = guard }), guard
}

var currentGateway = TimestampCheck{Accepted: true, Gateway: true, Machine: MachineCurrent, NodeCurrent: true}

func TestGatewayMustProveItsNodeKeyFirst(t *testing.T) {
	gateway := newProvingNode(t, 0x21)
	f, guard := newGatewayFixture(t, gateway, currentGateway)
	timestamp := f.nextHelloTimestamp()
	c, _, _ := f.dial(dialOptions{machine: gateway.machine, nodeKey: gateway.node.Public(), timestamp: timestamp})
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, "a Kubernetes gateway must prove its node key first")
	if f.handler.opened.Load() != 0 || guard.commits() != 0 {
		t.Fatal("an unproven gateway session was established")
	}
	// The refused handshake recorded nothing: the real gateway still
	// connects with that timestamp (plan §12.9 N3).
	genuine, _, _ := f.dial(dialOptions{machine: gateway.machine, nodeKey: gateway.node.Public(), timestamp: timestamp})
	if genuine == nil {
		t.Fatal("the refused handshake's timestamp was recorded")
	}
	genuine.proveNodeKey(gateway.node, f.control.Public())
	genuine.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	genuine.expect(sharedmtcp.MessagePong)
}

func TestGatewayProvesItsNodeKey(t *testing.T) {
	gateway := newProvingNode(t, 0x31)
	f, guard := newGatewayFixture(t, gateway, currentGateway)
	c, _, _ := f.dial(dialOptions{machine: gateway.machine, nodeKey: gateway.node.Public()})
	c.proveNodeKey(gateway.node, f.control.Public())
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expect(sharedmtcp.MessagePong)
	session := f.handler.last()
	proven, ok := session.ProvenNodeKey()
	if !ok || proven != node.Key(gateway.node.Public()) || !session.IsGateway() || guard.commits() != 1 {
		t.Fatalf("proven %v %t gateway %t commits %d", proven, ok, session.IsGateway(), guard.commits())
	}
	f.handler.mu.Lock()
	received := slices.Clone(f.handler.received)
	f.handler.mu.Unlock()
	if len(received) != 0 {
		t.Fatalf("the proof reached the conversation: %v", received)
	}
	// An unproven copy of the machine key never replaces the session.
	copied, _, _ := f.dial(dialOptions{machine: gateway.machine, nodeKey: gateway.node.Public()})
	copied.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	copied.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, "a Kubernetes gateway must prove its node key first")
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expect(sharedmtcp.MessagePong)
}

func TestGatewayGateRefusals(t *testing.T) {
	for _, test := range []struct {
		name    string
		check   TimestampCheck
		wrong   bool // prove another node key
		commit  bool
		message string
	}{
		{name: "retired machine key", check: TimestampCheck{Accepted: true, Gateway: true, Machine: MachineRetired},
			commit: true, message: "machine key is retired"},
		{name: "node key not current", check: TimestampCheck{Accepted: true, Gateway: true, Machine: MachineCurrent},
			commit: true, message: "node key is not current"},
		{name: "wrong proof", check: currentGateway, wrong: true, commit: true, message: "invalid node key proof"},
		{name: "timestamp taken since", check: currentGateway, message: "handshake replayed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := newProvingNode(t, 0x41)
			f, guard := newGatewayFixture(t, gateway, test.check)
			guard.commitOK = test.commit
			c, _, _ := f.dial(dialOptions{machine: gateway.machine, nodeKey: gateway.node.Public()})
			proving := gateway.node
			if test.wrong {
				proving = newProvingNode(t, 0x51).node
			}
			c.proveNodeKey(proving, f.control.Public())
			c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, test.message)
			if f.handler.opened.Load() != 0 {
				t.Fatal("a refused gateway session was established")
			}
		})
	}
}

// An ordinary node may prove its node key; the answer never ends its
// session (plan §12.9 N1).
func TestOrdinaryNodeKeyProofIsInformational(t *testing.T) {
	member := newProvingNode(t, 0x61)
	guard := &gatewayGuard{checks: map[[32]byte]TimestampCheck{
		member.fingerprint(): {Accepted: true, Machine: MachineCurrent, NodeCurrent: true}}, commitOK: true}
	f := newFixture(t, func(options *Options) { options.Guard = guard })
	c, _, _ := f.dial(dialOptions{machine: member.machine, nodeKey: member.node.Public()})
	c.proveNodeKey(member.node, f.control.Public())
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expect(sharedmtcp.MessagePong)
	session := f.handler.last()
	if proven, ok := session.ProvenNodeKey(); !ok || proven != node.Key(member.node.Public()) || session.IsGateway() ||
		guard.commits() != 0 {
		t.Fatalf("proven %v %t gateway %t commits %d", proven, ok, session.IsGateway(), guard.commits())
	}

	// A machine key bound to nothing is told so, and goes on to register.
	fresh := newProvingNode(t, 0x71)
	unbound, _, _ := f.dial(dialOptions{machine: fresh.machine, nodeKey: fresh.node.Public()})
	unbound.proveNodeKey(fresh.node, f.control.Public())
	failure := unbound.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
	if failure.GetCode() != mtcpv1.Error_NOT_AUTHORIZED || failure.GetFatal() ||
		failure.GetMessage() != "machine key is not bound" {
		t.Fatalf("unbound key answered %+v", failure)
	}
	unbound.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	unbound.expect(sharedmtcp.MessagePong)
	if _, ok := f.handler.last().ProvenNodeKey(); ok {
		t.Fatal("an unbound machine key's node key is proven")
	}

	// A wrong proof is answered and the session goes on, unproven.
	other := newProvingNode(t, 0x81)
	guard.mu.Lock()
	guard.checks[other.fingerprint()] = TimestampCheck{Accepted: true, Machine: MachineCurrent, NodeCurrent: true}
	guard.mu.Unlock()
	wrong, _, _ := f.dial(dialOptions{machine: other.machine, nodeKey: other.node.Public()})
	wrong.proveNodeKey(member.node, f.control.Public())
	if failure := wrong.expect(sharedmtcp.MessageError).(*mtcpv1.Error); failure.GetFatal() ||
		failure.GetCode() != mtcpv1.Error_INVALID {
		t.Fatalf("wrong proof answered %+v", failure)
	}
	wrong.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	wrong.expect(sharedmtcp.MessagePong)
	if _, ok := f.handler.last().ProvenNodeKey(); ok {
		t.Fatal("a wrong proof proved the node key")
	}
}

// A proof that is not the first record is refused without ending the
// session.
func TestLateNodeKeyProofIsRefused(t *testing.T) {
	member := newProvingNode(t, 0x91)
	f := newFixture(t, nil)
	c, _, _ := f.dial(dialOptions{machine: member.machine, nodeKey: member.node.Public()})
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expect(sharedmtcp.MessagePong)
	c.proveNodeKey(member.node, f.control.Public())
	if failure := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error); failure.GetFatal() ||
		failure.GetCode() != mtcpv1.Error_INVALID {
		t.Fatalf("late proof answered %+v", failure)
	}
	if _, ok := f.handler.last().ProvenNodeKey(); ok {
		t.Fatal("a late proof proved the node key")
	}
}
