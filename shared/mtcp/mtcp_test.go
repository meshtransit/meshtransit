package mtcp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/key"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

type fixedReader byte

func (r fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func fixedKeys(t *testing.T) (key.MachinePrivate, key.ControlPrivate) {
	t.Helper()
	machine, err := key.MachinePrivateFromBytes(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	control, err := key.ControlPrivateFromBytes(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return machine, control
}

func sampleClientHello() *mtcpv1.ClientHello {
	return &mtcpv1.ClientHello{
		ProtocolVersion: 1, TimestampMs: 1760000000000,
		Client:       &mtcpv1.ClientInfo{Product: "meshd", Version: "0.2.0", Os: "linux", Arch: "amd64"},
		Capabilities: []string{"map.zstd", "disco.v2", "relay.mtrp1"},
		NodeKey:      bytes.Repeat([]byte{0x55}, 32),
	}
}

func sampleServerHello() *mtcpv1.ServerHello {
	return &mtcpv1.ServerHello{
		ProtocolVersion: 1, ServerTimeMs: 1760000000123, SessionId: bytes.Repeat([]byte{0x66}, 16),
		Capabilities: []string{"map.zstd", "disco.v2"},
		Limits:       &mtcpv1.Limits{KeepaliveS: 25, IdleTimeoutS: 75, MaxUnackedMap: 8},
	}
}

// handshake runs a complete handshake with the given ephemeral randomness.
func handshake(t *testing.T, clientRandom, serverRandom io.Reader) (*Session, *Session, []byte, []byte) {
	t.Helper()
	machine, control := fixedKeys(t)
	client, init, err := StartClient(ClientConfig{Machine: machine, Control: control.Public(),
		Hello: sampleClientHello(), Random: clientRandom})
	if err != nil {
		t.Fatal(err)
	}
	server, err := ReadInit(control, init, serverRandom)
	if err != nil {
		t.Fatal(err)
	}
	if server.Machine() != machine.Public() || !proto.Equal(server.Hello(), sampleClientHello()) {
		t.Fatal("server read another machine or hello")
	}
	serverSession, response, err := server.Respond(sampleServerHello())
	if err != nil {
		t.Fatal(err)
	}
	clientSession, hello, err := client.Finish(response)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(hello, sampleServerHello()) || clientSession.HandshakeHash() != serverSession.HandshakeHash() {
		t.Fatal("handshake disagreed")
	}
	return clientSession, serverSession, init, response
}

func TestHandshakeAndTransport(t *testing.T) {
	client, server, _, _ := handshake(t, nil, nil)
	for i := range 3 {
		plain := bytes.Repeat([]byte{byte(i)}, 100+i)
		sealed, err := client.Seal(nil, plain)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := server.Open(nil, sealed)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	reply, _ := server.Seal(nil, []byte("pong"))
	if opened, err := client.Open(nil, reply); err != nil || string(opened) != "pong" {
		t.Fatalf("reply: %q %v", opened, err)
	}
	// Records cannot be replayed or reordered: the implicit nonce moved on.
	if _, err := client.Open(nil, reply); !errors.Is(err, ErrAuth) {
		t.Fatalf("replayed record: %v", err)
	}
	if _, err := client.Open(nil, reply); !errors.Is(err, ErrRekey) {
		t.Fatalf("session kept receiving after a failure: %v", err)
	}
	if _, err := server.Seal(nil, make([]byte, MaxTransportPlaintext+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized record: %v", err)
	}
}

func TestHandshakeRejectsWrongKeysAndTampering(t *testing.T) {
	machine, control := fixedKeys(t)
	other, _ := key.NewControlPrivate(nil)
	_, init, err := StartClient(ClientConfig{Machine: machine, Control: control.Public(), Hello: sampleClientHello()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadInit(other, init, nil); !errors.Is(err, ErrHandshake) {
		t.Fatalf("INIT for another control key: %v", err)
	}
	tampered := bytes.Clone(init)
	tampered[len(tampered)-1] ^= 1
	if _, err := ReadInit(control, tampered, nil); !errors.Is(err, ErrHandshake) {
		t.Fatalf("tampered INIT: %v", err)
	}
	client, init, _ := StartClient(ClientConfig{Machine: machine, Control: control.Public(), Hello: sampleClientHello()})
	server, _ := ReadInit(control, init, nil)
	_, response, _ := server.Respond(sampleServerHello())
	response[40] ^= 1
	if _, _, err := client.Finish(response); !errors.Is(err, ErrHandshake) {
		t.Fatalf("tampered RESPONSE: %v", err)
	}
	if _, _, err := client.Finish(response); !errors.Is(err, ErrHandshake) {
		t.Fatal("a spent handshake was reused")
	}
	bad := sampleClientHello()
	bad.Capabilities = append(bad.Capabilities, strings.Repeat("x", 65))
	if _, _, err := StartClient(ClientConfig{Machine: machine, Control: control.Public(), Hello: bad}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized capability: %v", err)
	}
}

func TestRecordFraming(t *testing.T) {
	stream, err := AppendRecord(nil, RecordInit, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	stream, _ = AppendRecord(stream, RecordTransport, bytes.Repeat([]byte{9}, 1000))
	reader := NewRecordReader(bytes.NewReader(stream))
	if typ, body, err := reader.Next(); err != nil || typ != RecordInit || !bytes.Equal(body, []byte{1, 2, 3}) {
		t.Fatalf("first record: %v %v %v", typ, body, err)
	}
	if typ, body, err := reader.Next(); err != nil || typ != RecordTransport || len(body) != 1000 {
		t.Fatalf("second record: %v %d %v", typ, len(body), err)
	}
	if _, _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("end: %v", err)
	}
	for name, raw := range map[string][]byte{
		"zero length":     {0, 0},
		"unknown type":    {0, 2, 9, 1},
		"empty body":      {0, 1, 3},
		"large handshake": append([]byte{0x08, 0x02, 1}, make([]byte, 0x0801)...),
		"truncated":       {0, 9, 3, 1},
	} {
		if _, _, err := NewRecordReader(bytes.NewReader(raw)).Next(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	message, _ := AppendMessageRecord(nil, RecordTransport, []byte{7, 7})
	if typ, body, err := ParseMessageRecord(message); err != nil || typ != RecordTransport || len(body) != 2 {
		t.Fatalf("WebSocket record: %v %v %v", typ, body, err)
	}
	if _, err := AppendRecord(nil, RecordResponse, make([]byte, MaxHandshakeRecord+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized RESPONSE: %v", err)
	}
}

func largeSnapshot(peers int) *mtcpv1.MapSnapshot {
	snapshot := &mtcpv1.MapSnapshot{View: &mtcpv1.View{Epoch: 3, Seq: 1}}
	for i := range peers {
		snapshot.Peers = append(snapshot.Peers, &mtcpv1.Device{
			DeviceId: strings.Repeat("d", 30) + string(rune('a'+i%26)), Name: "peer.example.mesh.",
			NodeKey: bytes.Repeat([]byte{byte(i)}, 32), DiscoKey: bytes.Repeat([]byte{byte(i + 1)}, 32),
		})
	}
	return snapshot
}

func TestMessageFragmentationAndCompression(t *testing.T) {
	snapshot := largeSnapshot(2000)
	for _, compress := range []bool{false, true} {
		fragments, err := EncodeMessage(MessageMapSnapshot, snapshot, CoreToNode, EncodeOptions{Compress: compress})
		if err != nil {
			t.Fatal(err)
		}
		if !compress && len(fragments) < 2 {
			t.Fatalf("uncompressed snapshot fit in %d fragment", len(fragments))
		}
		assembler := NewAssembler(CoreToNode)
		var payload []byte
		for index, fragment := range fragments {
			if len(fragment) > MaxTransportPlaintext {
				t.Fatalf("fragment of %d bytes", len(fragment))
			}
			typ, decoded, complete, err := assembler.Add(fragment)
			if err != nil || complete != (index == len(fragments)-1) || (complete && typ != MessageMapSnapshot) {
				t.Fatalf("fragment %d: %v %v %v", index, typ, complete, err)
			}
			payload = decoded
		}
		decoded, err := DecodeMessage(MessageMapSnapshot, payload)
		if err != nil || !proto.Equal(decoded, snapshot) {
			t.Fatalf("compress=%t: snapshot did not survive: %v", compress, err)
		}
	}
	if _, err := EncodeMessage(MessageMapSnapshot, snapshot, NodeToCore, EncodeOptions{}); !errors.Is(err, ErrDirection) {
		t.Fatalf("node sending a map: %v", err)
	}
	ping, _ := EncodeMessage(MessagePing, &mtcpv1.Ping{Nonce: []byte{1}}, NodeToCore, EncodeOptions{})
	if _, _, _, err := NewAssembler(NodeToCore).Add(ping[0]); err != nil {
		t.Fatalf("Core refused a node Ping: %v", err)
	}
	ack, _ := EncodeMessage(MessageMapAck, &mtcpv1.MapAck{}, NodeToCore, EncodeOptions{})
	if _, _, _, err := NewAssembler(CoreToNode).Add(ack[0]); !errors.Is(err, ErrDirection) {
		t.Fatalf("node accepted a MapAck: %v", err)
	}
}

func TestAssemblerRejectsBombsAndInterleaving(t *testing.T) {
	// A frame declaring more than the limit is refused before decoding.
	big, _ := zstd.NewWriter(nil)
	bomb := big.EncodeAll(make([]byte, 4097), nil)
	if _, _, _, err := NewAssembler(CoreToNode).Add(append([]byte{byte(MessageLifecycle), flagZstd}, bomb...)); err == nil {
		t.Fatal("4 KiB+ decompressed Lifecycle accepted")
	}
	// A frame without a declared content size is refused.
	var streamed bytes.Buffer
	writer, _ := zstd.NewWriter(&streamed)
	_, _ = writer.Write([]byte("hello"))
	_ = writer.Close()
	if _, _, _, err := NewAssembler(CoreToNode).Add(append([]byte{byte(MessageLifecycle), flagZstd}, streamed.Bytes()...)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("frame without content size: %v", err)
	}
	// Reassembly stops at the limit, before the final fragment.
	assembler := NewAssembler(CoreToNode)
	chunk := append([]byte{byte(MessageLifecycle), flagMore}, make([]byte, 3000)...)
	if _, _, _, err := assembler.Add(chunk); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := assembler.Add(chunk); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("reassembly over the limit: %v", err)
	}
	interleaved := NewAssembler(CoreToNode)
	_, _, _, _ = interleaved.Add([]byte{byte(MessageNotice), flagMore, 1})
	if _, _, _, err := interleaved.Add([]byte{byte(MessageLifecycle), 0, 1}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("interleaved fragments: %v", err)
	}
	for name, fragment := range map[string][]byte{
		"unknown type":  {0x7f, 0},
		"reserved flag": {byte(MessagePing), 0x04},
		"short":         {byte(MessagePing)},
	} {
		if _, _, _, err := NewAssembler(Both).Add(fragment); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestKeyProofsAndFingerprint(t *testing.T) {
	_, control := fixedKeys(t)
	node, _ := key.NodePrivateFromBytes(bytes.Repeat([]byte{0x77}, 32))
	disco, _ := key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x88}, 32))
	hash := [32]byte{0x99}
	nodeProof, err := NodeKeyProof(node, control.Public(), hash)
	if err != nil {
		t.Fatal(err)
	}
	discoProof, _ := DiscoKeyProof(disco, control.Public(), hash)
	if !VerifyKeyProof(control, hash, node.Public(), nodeProof[:]) ||
		!VerifyKeyProof(control, hash, disco.Public(), discoProof[:]) {
		t.Fatal("valid proof refused")
	}
	if VerifyKeyProof(control, [32]byte{0x9a}, node.Public(), nodeProof[:]) {
		t.Fatal("proof accepted in another session")
	}
	if VerifyKeyProof(control, hash, disco.Public(), nodeProof[:]) {
		t.Fatal("node key proof accepted for the disco key")
	}
	fingerprint := ControlFingerprint(control.Public())
	if len(fingerprint) != 32 || !FingerprintMatches(control.Public(), fingerprint) ||
		FingerprintMatches(control.Public(), strings.ToUpper(fingerprint)) {
		t.Fatalf("fingerprint %q", fingerprint)
	}
}

type vectors struct {
	MachinePrivate     string            `json:"machine_private"`
	ControlPrivate     string            `json:"control_private"`
	MachinePublic      string            `json:"machine_public"`
	ControlPublic      string            `json:"control_public"`
	ControlKeyID       string            `json:"control_key_id"`
	ControlFingerprint string            `json:"control_fingerprint"`
	ClientEphemeral    string            `json:"client_ephemeral_private"`
	ServerEphemeral    string            `json:"server_ephemeral_private"`
	ClientHello        string            `json:"client_hello"`
	ServerHello        string            `json:"server_hello"`
	Init               string            `json:"init"`
	Response           string            `json:"response"`
	HandshakeHash      string            `json:"handshake_hash"`
	Records            []vectorRecord    `json:"records"`
	Proofs             map[string]string `json:"proofs"`
	Fragments          map[string]string `json:"fragments"`
}

type vectorRecord struct {
	Direction string `json:"direction"`
	Plaintext string `json:"plaintext"`
	Record    string `json:"record"`
}

func buildVectors(t *testing.T) vectors {
	t.Helper()
	machine, control := fixedKeys(t)
	clientSession, serverSession, init, response := handshake(t, fixedReader(0x33), fixedReader(0x44))
	hash := clientSession.HandshakeHash()
	clientHello, _ := marshal.Marshal(sampleClientHello())
	serverHello, _ := marshal.Marshal(sampleServerHello())
	v := vectors{
		MachinePrivate: hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		ControlPrivate: hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
		MachinePublic:  machine.Public().String(), ControlPublic: control.Public().String(),
		ControlKeyID: control.Public().ID().String(), ControlFingerprint: ControlFingerprint(control.Public()),
		ClientEphemeral: hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
		ServerEphemeral: hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
		ClientHello:     hex.EncodeToString(clientHello), ServerHello: hex.EncodeToString(serverHello),
		Init: hex.EncodeToString(init), Response: hex.EncodeToString(response),
		HandshakeHash: hex.EncodeToString(hash[:]),
		Proofs:        map[string]string{}, Fragments: map[string]string{},
	}
	ping, _ := EncodeMessage(MessagePing, &mtcpv1.Ping{Nonce: []byte{1, 2, 3, 4}}, NodeToCore, EncodeOptions{})
	pong, _ := EncodeMessage(MessagePong, &mtcpv1.Pong{Nonce: []byte{1, 2, 3, 4}}, CoreToNode, EncodeOptions{})
	lifecycle, _ := EncodeMessage(MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_SUSPENDED,
		Reason: "suspended by an administrator", RetryAfterMs: 3000}, CoreToNode, EncodeOptions{})
	for _, step := range []struct {
		direction string
		sender    *Session
		receiver  *Session
		plaintext []byte
	}{
		{"node_to_core", clientSession, serverSession, ping[0]},
		{"core_to_node", serverSession, clientSession, pong[0]},
		{"core_to_node", serverSession, clientSession, lifecycle[0]},
	} {
		record, err := step.sender.Seal(nil, step.plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if opened, err := step.receiver.Open(nil, record); err != nil || !bytes.Equal(opened, step.plaintext) {
			t.Fatalf("vector record: %v", err)
		}
		v.Records = append(v.Records, vectorRecord{Direction: step.direction,
			Plaintext: hex.EncodeToString(step.plaintext), Record: hex.EncodeToString(record)})
	}
	node, _ := key.NodePrivateFromBytes(bytes.Repeat([]byte{0x77}, 32))
	disco, _ := key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x88}, 32))
	nodeProof, _ := NodeKeyProof(node, control.Public(), hash)
	discoProof, _ := DiscoKeyProof(disco, control.Public(), hash)
	v.Proofs["node_private"] = hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	v.Proofs["node_public"] = node.Public().String()
	v.Proofs["node_proof"] = hex.EncodeToString(nodeProof[:])
	v.Proofs["disco_private"] = hex.EncodeToString(bytes.Repeat([]byte{0x88}, 32))
	v.Proofs["disco_public"] = disco.Public().String()
	v.Proofs["disco_proof"] = hex.EncodeToString(discoProof[:])
	v.Fragments["ping"] = hex.EncodeToString(ping[0])
	v.Fragments["lifecycle"] = hex.EncodeToString(lifecycle[0])
	return v
}

// TestVectors pins the wire format; testdata/crosscheck.py recomputes the
// handshake, records, proofs and fingerprint independently.
func TestVectors(t *testing.T) {
	got := buildVectors(t)
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *update {
		if err := os.WriteFile(vectorsPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, encoded) {
		t.Fatal("implementation no longer reproduces testdata/vectors.json")
	}
}

func FuzzAssembler(f *testing.F) {
	ping, _ := EncodeMessage(MessagePing, &mtcpv1.Ping{Nonce: []byte{1}}, NodeToCore, EncodeOptions{})
	compressed, _ := EncodeMessage(MessageNotice, &mtcpv1.Notice{}, CoreToNode, EncodeOptions{Compress: true})
	f.Add(ping[0], []byte{})
	f.Add(compressed[0], ping[0])
	f.Fuzz(func(t *testing.T, first, second []byte) {
		assembler := NewAssembler(Both)
		for _, fragment := range [][]byte{first, second} {
			typ, payload, complete, err := assembler.Add(fragment)
			if err != nil || !complete {
				continue
			}
			if len(payload) > typ.Limit() {
				t.Fatalf("message of %d bytes over the %d limit", len(payload), typ.Limit())
			}
			_, _ = DecodeMessage(typ, payload)
		}
	})
}

func FuzzRecordReader(f *testing.F) {
	record, _ := AppendRecord(nil, RecordTransport, []byte{1, 2, 3})
	f.Add(record)
	f.Fuzz(func(t *testing.T, stream []byte) {
		reader := NewRecordReader(bytes.NewReader(stream))
		for range 4 {
			typ, body, err := reader.Next()
			if err != nil {
				return
			}
			if checkRecord(typ, len(body)) != nil {
				t.Fatal("reader returned an invalid record")
			}
		}
	})
}

func TestFilterDigestMatchesTheSharedVector(t *testing.T) {
	// The PacketFilter of shared/policydigest/testdata/packet-filter-v1.json
	// written as MTCP: an ICMP destination without ports means every port.
	prefix := func(text string) *mtcpv1.Prefix { return AppendPrefix(netip.MustParsePrefix(text)) }
	filter := &mtcpv1.PacketFilter{Rules: []*mtcpv1.FilterRule{
		{
			Sources: []*mtcpv1.Prefix{prefix("100.64.0.2/32"), prefix("fd7a:115c:a1e0::2/128")},
			Destinations: []*mtcpv1.Destination{
				{Prefix: prefix("100.64.0.1/32"), Ports: []*mtcpv1.PortRange{{First: 22, Last: 22}}},
				{Prefix: prefix("fd7a:115c:a1e0::1/128"), Ports: []*mtcpv1.PortRange{{First: 22, Last: 22}}},
			},
			Protocols: []uint32{6},
		},
		{
			Sources:      []*mtcpv1.Prefix{prefix("100.64.0.3/32")},
			Destinations: []*mtcpv1.Destination{{Prefix: prefix("100.64.0.1/32")}},
			Protocols:    []uint32{1},
		},
	}}
	digest, grants, err := FilterDigest(filter)
	if err != nil || grants != 5 ||
		digest.String() != "sha256:65c3166a6062804e3b2a55acd157d70ce0ebf6fdd91130eecd280654a714251a" {
		t.Fatalf("digest = %s (%d), %v", digest, grants, err)
	}
	filter.Rules[0].Destinations[0].Ports[0].First = 23
	if _, _, err := FilterDigest(filter); !errors.Is(err, ErrMalformed) {
		t.Fatalf("inverted port range: %v", err)
	}
}
