package flowlog

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/shared/key"
)

type transportFixture struct {
	now      time.Time
	machine  key.MachinePrivate
	receiver *Receiver
	token    []byte
}

func newTransportFixture(t *testing.T) transportFixture {
	t.Helper()
	now := time.UnixMilli(1_800_000_000_000)
	machine, err := key.NewMachinePrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, keys := testKeys(t)
	claims := testClaims(now)
	public := machine.Public()
	claims.MachineKey = public[:]
	token, err := SignToken(claims, signing)
	if err != nil {
		t.Fatal(err)
	}
	return transportFixture{
		now: now, machine: machine, token: token,
		receiver: &Receiver{Key: receiverKey, SigningKeys: keys, Audience: audience},
	}
}

func (f transportFixture) receiverPublic() []byte { return f.receiver.Key.PublicKey().Bytes() }

func testBatch(records int) *flowlogv1.FlowBatch {
	batch := &flowlogv1.FlowBatch{ReporterSequence: 3, BootId: id(7), WindowStartMs: 1, WindowEndMs: 60_001}
	for index := range records {
		flowID := make([]byte, 16)
		_, _ = rand.Read(flowID)
		batch.Records = append(batch.Records, &flowlogv1.FlowRecord{
			Kind: flowlogv1.FlowRecord_FLOW, Class: flowlogv1.FlowRecord_MESH, Protocol: 6,
			DestinationPort: uint32(index % 65536), FlowId: flowID, PacketsOut: uint64(index),
			Direction: flowlogv1.FlowRecord_OUTBOUND,
		})
	}
	return batch
}

func compress(t testing.TB, message proto.Message) []byte {
	t.Helper()
	plain, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testRequest() *flowlogv1.FlowRequest {
	return &flowlogv1.FlowRequest{BootId: id(7), Sequence: 3, HeldFrom: 2}
}

// receive runs the receiver's steps 2, 3, 6 and 7 on a request.
func (f transportFixture) receive(header string, body []byte) (*Incoming, *flowlogv1.FlowBatch, error) {
	token, err := f.receiver.CheckToken(header, f.now)
	if err != nil {
		return nil, nil, err
	}
	incoming, err := f.receiver.ReadHandshake(token, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	batch, err := incoming.ReadBatch()
	return incoming, batch, err
}

// A batch of any size within the limit crosses, its answer opens only for
// its own request, and each answer is sealed afresh.
func TestTransportRoundTrip(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	for _, records := range []int{1, 20_000} {
		batch := testBatch(records)
		compressed := compress(t, batch)
		request, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(), compressed, nil)
		if err != nil {
			t.Fatal(err)
		}
		incoming, received, err := fixture.receive(request.TokenHeader(), request.Body)
		if err != nil {
			t.Fatalf("%d records: %v", records, err)
		}
		if !proto.Equal(received, batch) || int(incoming.Request.GetBatchLength()) != len(compressed) ||
			!bytes.Equal(incoming.Claims.GetDeviceId(), id(3)) {
			t.Fatalf("%d records did not cross", records)
		}
		if records > 1 && len(compressed) < 2*maxChunk {
			t.Fatalf("the large batch took one frame (%d bytes)", len(compressed))
		}
		answer := &flowlogv1.FlowBatchResponse{
			Status: flowlogv1.FlowBatchResponse_ACCEPTED, CommittedSequence: 2,
			NextSequence: 4,
		}
		first, err := incoming.Answer(answer)
		if err != nil {
			t.Fatal(err)
		}
		second, _ := incoming.Answer(answer)
		if bytes.Equal(first, second) {
			t.Fatal("two answers were sealed alike")
		}
		for _, sealed := range [][]byte{first, second} {
			opened, err := request.OpenAnswer(sealed)
			if err != nil || !proto.Equal(opened, answer) {
				t.Fatalf("answer: %v", err)
			}
		}
		other, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(), compressed, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.OpenAnswer(first); !errors.Is(err, ErrInvalidAnswer) {
			t.Fatalf("an answer to another request opened: %v", err)
		}
	}
}

// A recorded request replays as the same batch; only the node opens the
// answers.
func TestTransportReplay(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	request, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(),
		compress(t, testBatch(3)), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		incoming, _, err := fixture.receive(request.TokenHeader(), request.Body)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := incoming.Answer(&flowlogv1.FlowBatchResponse{Status: flowlogv1.FlowBatchResponse_ACCEPTED})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := request.OpenAnswer(sealed); err != nil {
			t.Fatal(err)
		}
	}
}

// Each failure gets its plain HTTP status; only content errors are INVALID.
func TestTransportRefusals(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	compressed := compress(t, testBatch(3))
	request, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(), compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	impostor, _ := key.NewMachinePrivate(nil)
	stolen, err := NewRequest(fixture.token, impostor, fixture.receiverPublic(), testRequest(), compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherReceiver, _ := ecdh.X25519().GenerateKey(rand.Reader)
	misdirected, err := NewRequest(fixture.token, fixture.machine, otherReceiver.PublicKey().Bytes(), testRequest(),
		compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := testRequest()
	mismatched.Sequence, mismatched.HeldFrom = 4, 4
	wrongBatch, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), mismatched, compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(request.TokenHeader())
	tampered[10] ^= 1
	frames := request.Body
	for name, test := range map[string]struct {
		header string
		body   []byte
		status int
	}{
		"tampered token":    {string(tampered), request.Body, 401},
		"no token":          {"", request.Body, 401},
		"stolen token":      {stolen.TokenHeader(), stolen.Body, 403},
		"another receiver":  {misdirected.TokenHeader(), misdirected.Body, 400},
		"truncated":         {request.TokenHeader(), frames[:len(frames)-1], 400},
		"trailing byte":     {request.TokenHeader(), append(bytes.Clone(frames), 0), 400},
		"handshake only":    {request.TokenHeader(), frames[:2+int(frames[0])<<8+int(frames[1])], 400},
		"empty body":        {request.TokenHeader(), nil, 400},
		"batch not request": {wrongBatch.TokenHeader(), wrongBatch.Body, 0},
	} {
		_, _, err := fixture.receive(test.header, test.body)
		if err == nil || Status(err) != test.status {
			t.Errorf("%s: %v (status %d), want status %d", name, err, Status(err), test.status)
		}
	}
	if !errors.Is(checkRequest(&flowlogv1.FlowRequest{
		BatchLength: MaxBatchLength + 1, BootId: id(1), Sequence: 1,
		HeldFrom: 1,
	}), ErrTooLarge) || Status(ErrTooLarge) != 413 {
		t.Error("an oversized batch is not 413")
	}
}

// A FlowRequest outside flowlog-v1 §6 is never sent.
func TestTransportRefusesBadRequests(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	compressed := compress(t, testBatch(1))
	for name, change := range map[string]func(*flowlogv1.FlowRequest){
		"short boot id":      func(r *flowlogv1.FlowRequest) { r.BootId = r.BootId[:15] },
		"sequence 0":         func(r *flowlogv1.FlowRequest) { r.Sequence, r.HeldFrom = 0, 0 },
		"held past sequence": func(r *flowlogv1.FlowRequest) { r.HeldFrom = 4 },
		"lost reversed": func(r *flowlogv1.FlowRequest) {
			r.Lost = &flowlogv1.Lost{FirstSequence: 2, LastSequence: 1}
		},
		"lost past held": func(r *flowlogv1.FlowRequest) {
			r.Lost = &flowlogv1.Lost{FirstSequence: 1, LastSequence: 2}
		},
	} {
		request := testRequest()
		change(request)
		if _, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), request, compressed, nil); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if _, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(),
		make([]byte, MaxBatchLength+1), nil); err == nil {
		t.Error("an oversized batch was sent")
	}
	lost := testRequest()
	lost.Lost = &flowlogv1.Lost{FirstSequence: 1, LastSequence: 1, Records: 5}
	if _, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), lost, compressed, nil); err != nil {
		t.Errorf("a valid lost range: %v", err)
	}
}

// Decompression is bounded, single-member, and refuses unknown fields.
func TestTransportBatchContent(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	bomb := compressBytes(t, make([]byte, MaxBatchSize+1))
	twoMembers := append(compress(t, testBatch(1)), compress(t, testBatch(1))...)
	unknown, _ := proto.Marshal(testBatch(1))
	unknown = append(unknown, 0xf8, 0x01, 0x01) // field 31, varint 1
	for name, compressed := range map[string][]byte{
		"bomb": bomb, "two members": twoMembers, "unknown field": compressBytes(t, unknown),
		"not gzip": []byte("plain"),
	} {
		request, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(), compressed, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := fixture.receive(request.TokenHeader(), request.Body); !errors.Is(err, ErrInvalidBatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func compressBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer, _ := gzip.NewWriterLevel(&out, gzip.BestCompression)
	_, _ = writer.Write(plain)
	_ = writer.Close()
	return out.Bytes()
}

// handBuilt is a request as a faulty or hostile sender could make it: any
// FlowRequest payload, the batch sealed in chunks of chunk bytes.
func handBuilt(t *testing.T, fixture transportFixture, token, payload, compressed []byte, chunk int) []byte {
	t.Helper()
	static := fixture.machine.ECDH()
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Random: rand.Reader, Pattern: noise.HandshakeX, Initiator: true,
		Prologue:      requestPrologueFor(token),
		StaticKeypair: noise.DHKey{Private: static.Bytes(), Public: static.PublicKey().Bytes()},
		PeerStatic:    fixture.receiverPublic(),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, sending, _, err := handshake.WriteMessage(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	body := appendFrame(nil, first)
	for len(compressed) > 0 {
		size := min(chunk, len(compressed))
		sealed, _ := sending.Encrypt(nil, nil, compressed[:size])
		body = appendFrame(body, sealed)
		compressed = compressed[size:]
	}
	return body
}

func requestPayload(t *testing.T, request *flowlogv1.FlowRequest, extra ...byte) []byte {
	t.Helper()
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return append(payload, extra...)
}

// The receiver refuses on its own what NewRequest never sends.
func TestTransportReceiverRefusesHandBuilt(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	header := base64.RawURLEncoding.EncodeToString(fixture.token)
	compressed := compress(t, testBatch(1))
	good := testRequest()
	good.BatchLength = uint32(len(compressed)) //nolint:gosec // small
	badHeld := cloneRequest(good)
	badHeld.HeldFrom = 9
	tooLarge := cloneRequest(good)
	tooLarge.BatchLength = MaxBatchLength + 1
	// Field 5 (lost): first_sequence 1, last_sequence 1, and with the
	// unknown field 9; without it the same request is taken.
	lostKnown := append(requestPayload(t, good), 0x2a, 0x04, 0x08, 0x01, 0x10, 0x01)
	lostPayload := append(requestPayload(t, good), 0x2a, 0x06, 0x08, 0x01, 0x10, 0x01, 0x48, 0x01)
	if _, _, err := fixture.receive(header, handBuilt(t, fixture, fixture.token, lostKnown, compressed, maxChunk)); err != nil {
		t.Fatalf("a known lost range: %v", err)
	}
	for name, test := range map[string]struct {
		payload []byte
		status  int
	}{
		"held past sequence":    {requestPayload(t, badHeld), 400},
		"too large":             {requestPayload(t, tooLarge), 413},
		"unknown field":         {requestPayload(t, good, 0x48, 0x01), 400},
		"unknown field in lost": {lostPayload, 400},
	} {
		body := handBuilt(t, fixture, fixture.token, test.payload, compressed, maxChunk)
		if _, _, err := fixture.receive(header, body); Status(err) != test.status {
			t.Errorf("%s: %v, want %d", name, err, test.status)
		}
	}
	if _, _, err := fixture.receive(header, handBuilt(t, fixture, fixture.token, requestPayload(t, good), compressed,
		maxChunk)); err != nil {
		t.Fatalf("a well-formed hand-built request: %v", err)
	}
}

// Frames that are moved, missing, repeated, short or empty do not cross.
func TestTransportFrameTampering(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	compressed := compress(t, testBatch(20_000))
	request, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(), compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	for rest := request.Body; len(rest) > 0; {
		frame, next, ok := readFrame(rest)
		if !ok {
			t.Fatal("unframed body")
		}
		frames, rest = append(frames, frame), next
	}
	if len(frames) < 4 {
		t.Fatalf("only %d frames", len(frames))
	}
	join := func(parts ...[]byte) []byte {
		var body []byte
		for _, part := range parts {
			body = appendFrame(body, part)
		}
		return body
	}
	swapped := append([][]byte{frames[0], frames[2], frames[1]}, frames[3:]...)
	dropped := append([][]byte{frames[0], frames[1]}, frames[3:]...)
	repeated := append([][]byte{frames[0], frames[1], frames[1]}, frames[2:]...)
	good := testRequest()
	good.BatchLength = uint32(len(compressed)) //nolint:gosec // small
	for name, body := range map[string][]byte{
		"swapped":         join(swapped...),
		"dropped":         join(dropped...),
		"repeated":        join(repeated...),
		"zero frame":      append(join(frames[0]), 0, 0),
		"short frame":     handBuilt(t, fixture, fixture.token, requestPayload(t, good), compressed, maxChunk-1),
		"large handshake": append([]byte{0x01, 0x2c}, make([]byte, 300)...),
	} {
		if _, _, err := fixture.receive(request.TokenHeader(), body); Status(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another valid token of the same machine key cannot carry this body.
	signing, keys := testKeys(t)
	fixture.receiver.SigningKeys = keys
	claims := testClaims(fixture.now)
	public := fixture.machine.Public()
	claims.MachineKey, claims.TokenId = public[:], id(8)
	other, _ := SignToken(claims, signing)
	if _, _, err := fixture.receive(base64.RawURLEncoding.EncodeToString(other), request.Body); Status(err) != 400 {
		t.Errorf("another token: %v", err)
	}
}

// Only the receiver's own answer, intact and with a known status, opens.
func TestTransportAnswerRefusals(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	request, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(),
		compress(t, testBatch(1)), nil)
	if err != nil {
		t.Fatal(err)
	}
	incoming, _, err := fixture.receive(request.TokenHeader(), request.Body)
	if err != nil {
		t.Fatal(err)
	}
	accepted := &flowlogv1.FlowBatchResponse{Status: flowlogv1.FlowBatchResponse_ACCEPTED}
	good, _ := incoming.Answer(accepted)
	impostor, _ := ecdh.X25519().GenerateKey(rand.Reader)
	public := fixture.machine.Public()
	forged, _ := sealAnswer(impostor, public[:], incoming.binding, accepted, rand.Reader)
	flipped := bytes.Clone(good)
	flipped[len(flipped)-1] ^= 1
	unknownStatus, _ := incoming.Answer(&flowlogv1.FlowBatchResponse{Status: 7})
	noStatus, _ := incoming.Answer(&flowlogv1.FlowBatchResponse{})
	for name, body := range map[string][]byte{
		"another receiver": forged, "flipped": flipped, "trailing": append(bytes.Clone(good), 0),
		"status 7": unknownStatus, "status 0": noStatus, "empty": nil,
	} {
		if _, err := request.OpenAnswer(body); !errors.Is(err, ErrInvalidAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v %+v %#v", request, request, request, *request, *request),
		request.TokenHeader()) {
		t.Fatal("a request printed its token")
	}
}

func TestTransportStatuses(t *testing.T) {
	t.Parallel()
	for err, status := range map[error]int{
		ErrUnknownKey: 401, ErrTokenExpired: 401, ErrInvalidToken: 401, ErrWrongMachineKey: 403,
		ErrTooLarge: 413, ErrUnavailable: 503, ErrFraming: 400, ErrInvalidRequest: 400, ErrInvalidBatch: 0,
	} {
		if got := Status(err); got != status {
			t.Errorf("Status(%v) = %d, want %d", err, got, status)
		}
	}
	if MaxBodySize(MaxBatchLength) < int64(MaxBatchLength) {
		t.Fatal("body bound below the batch")
	}
}

// A gzip member followed by anything is refused.
func TestTransportGzipTrailingJunk(t *testing.T) {
	t.Parallel()
	fixture := newTransportFixture(t)
	compressed := append(compress(t, testBatch(1)), 1, 2, 3)
	request, err := NewRequest(fixture.token, fixture.machine, fixture.receiverPublic(), testRequest(), compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.receive(request.TokenHeader(), request.Body); !errors.Is(err, ErrInvalidBatch) {
		t.Fatalf("trailing junk: %v", err)
	}
}

func cloneRequest(request *flowlogv1.FlowRequest) *flowlogv1.FlowRequest {
	clone, _ := proto.Clone(request).(*flowlogv1.FlowRequest)
	return clone
}
