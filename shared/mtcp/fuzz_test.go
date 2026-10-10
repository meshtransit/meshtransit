package mtcp

import (
	"testing"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// fixedRandom makes the fuzzed handshakes reproducible.
type fixedRandom byte

func (r fixedRandom) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r) + byte(i)
	}
	return len(p), nil
}

// FuzzReadInit feeds Core arbitrary INIT records: it must refuse them
// without panicking, and anything it accepts carries a valid ClientHello.
func FuzzReadInit(f *testing.F) {
	machine, control := fixedKeys(f)
	_, init, err := StartClient(ClientConfig{
		Machine: machine, Control: control.Public(), Hello: sampleClientHello(),
		Random: fixedRandom(1),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(init)
	f.Add(init[:len(init)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, record []byte) {
		handshake, err := ReadInit(control, record, fixedRandom(2))
		if err != nil {
			return
		}
		if handshake.Machine().IsZero() || ValidateClientHello(handshake.Hello()) != nil {
			t.Fatal("accepted an INIT without a machine key or a valid hello")
		}
	})
}

// FuzzClientFinish feeds a node arbitrary handshake responses.
func FuzzClientFinish(f *testing.F) {
	machine, control := fixedKeys(f)
	_, init, err := StartClient(ClientConfig{
		Machine: machine, Control: control.Public(), Hello: sampleClientHello(),
		Random: fixedRandom(1),
	})
	if err != nil {
		f.Fatal(err)
	}
	server, err := ReadInit(control, init, fixedRandom(2))
	if err != nil {
		f.Fatal(err)
	}
	_, response, err := server.Respond(sampleServerHello())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(response)
	f.Add(response[:len(response)/2])
	f.Fuzz(func(t *testing.T, record []byte) {
		client, _, err := StartClient(ClientConfig{
			Machine: machine, Control: control.Public(),
			Hello: sampleClientHello(), Random: fixedRandom(1),
		})
		if err != nil {
			t.Fatal(err)
		}
		session, hello, err := client.Finish(record)
		if err != nil {
			return
		}
		if session == nil || ValidateServerHello(hello) != nil {
			t.Fatal("accepted a response without a session or a valid hello")
		}
	})
}

// FuzzSessionOpen feeds an established session arbitrary transport records.
func FuzzSessionOpen(f *testing.F) {
	machine, control := fixedKeys(f)
	client, init, err := StartClient(ClientConfig{
		Machine: machine, Control: control.Public(), Hello: sampleClientHello(),
		Random: fixedRandom(1),
	})
	if err != nil {
		f.Fatal(err)
	}
	server, err := ReadInit(control, init, fixedRandom(2))
	if err != nil {
		f.Fatal(err)
	}
	_, response, err := server.Respond(sampleServerHello())
	if err != nil {
		f.Fatal(err)
	}
	session, _, err := client.Finish(response)
	if err != nil {
		f.Fatal(err)
	}
	sealed, err := session.Seal(nil, []byte("ping"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Fuzz(func(t *testing.T, record []byte) {
		_, serverInit, _ := StartClient(ClientConfig{
			Machine: machine, Control: control.Public(),
			Hello: sampleClientHello(), Random: fixedRandom(1),
		})
		handshake, err := ReadInit(control, serverInit, fixedRandom(2))
		if err != nil {
			t.Fatal(err)
		}
		receiver, _, err := handshake.Respond(sampleServerHello())
		if err != nil {
			t.Fatal(err)
		}
		plain, err := receiver.Open(nil, record)
		if err == nil && len(plain) > MaxTransportPlaintext {
			t.Fatalf("opened %d bytes over the transport limit", len(plain))
		}
	})
}

// FuzzParseMessageRecord checks the message record framing.
func FuzzParseMessageRecord(f *testing.F) {
	ping, _ := EncodeMessage(MessagePing, &mtcpv1.Ping{Nonce: []byte{1}}, NodeToCore, EncodeOptions{})
	record, _ := AppendMessageRecord(nil, RecordTransport, ping[0])
	f.Add(record)
	f.Fuzz(func(t *testing.T, message []byte) {
		typ, body, err := ParseMessageRecord(message)
		if err != nil {
			return
		}
		if checkRecord(typ, len(body)) != nil {
			t.Fatal("parsed an invalid record")
		}
	})
}

// FuzzFilterDigest decodes arbitrary PacketFilters the way meshd and Core do
// before digesting them: a filter is either refused or digests stably.
func FuzzFilterDigest(f *testing.F) {
	seed, _ := proto.Marshal(&mtcpv1.PacketFilter{Rules: []*mtcpv1.FilterRule{{
		Sources:      []*mtcpv1.Prefix{{Ip: []byte{100, 64, 0, 2}, Bits: 32}},
		Destinations: []*mtcpv1.Destination{{Prefix: &mtcpv1.Prefix{Ip: []byte{100, 64, 0, 1}, Bits: 32}}},
		Protocols:    []uint32{1},
	}}})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		filter := &mtcpv1.PacketFilter{}
		if proto.Unmarshal(encoded, filter) != nil {
			return
		}
		first, grants, err := FilterDigest(filter)
		if err != nil {
			return
		}
		clone, ok := proto.Clone(filter).(*mtcpv1.PacketFilter)
		if !ok {
			t.Fatal("clone is not a PacketFilter")
		}
		again, regrants, err := FilterDigest(clone)
		if err != nil || again != first || regrants != grants {
			t.Fatal("digest is not stable")
		}
		if _, err := PolicyRules(filter); err != nil {
			t.Fatal("a digestible filter has no policy rules")
		}
	})
}
