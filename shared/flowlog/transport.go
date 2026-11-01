package flowlog

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/shared/key"
)

// Transport constants (flowlog-v1 §4).
const (
	// Path is the fixed same-origin path a node posts batches to (ADR-054).
	Path = "/mtflow/v1/batches"
	// TokenHeader carries the token, base64url without padding.
	TokenHeader = "MeshTransit-Flow-Token"
	// NetworkHeader carries the token's Network as a lowercase UUID: ingress
	// routes on it to the replica that writes the Network.
	NetworkHeader = "MeshTransit-Flow-Network"
	// ContentType is the request and answer body's media type.
	ContentType = "application/vnd.meshtransit.flowlog.v1"
	// MaxBatchLength bounds the compressed batch; MaxBatchSize the batch
	// once decompressed.
	MaxBatchLength = 4 << 20
	MaxBatchSize   = 16 << 20
	// maxHandshakeFrame bounds frame 0; maxChunk is the most plaintext one
	// transport message carries.
	maxHandshakeFrame = 256
	maxChunk          = noise.MaxMsgLen - 16
	requestPrologue   = "meshtransit flowlog v1"
	answerPrologue    = "meshtransit flowlog v1 answer"
	maxRequestPayload = 128
)

var (
	// ErrFraming reports a body that does not frame, decrypt or add up: a
	// plain 400, never a reason for a node to drop a batch.
	ErrFraming = errors.New("flowlog: malformed request body")
	// ErrInvalidRequest reports a FlowRequest outside flowlog-v1 §6.
	ErrInvalidRequest = errors.New("flowlog: invalid request")
	// ErrTooLarge reports a batch_length past MaxBatchLength.
	ErrTooLarge = errors.New("flowlog: batch too large")
	// ErrInvalidBatch reports a decrypted batch that breaks flowlog-v1 §6:
	// the receiver answers INVALID.
	ErrInvalidBatch = errors.New("flowlog: invalid batch")
	// ErrInvalidAnswer reports an answer that does not open.
	ErrInvalidAnswer = errors.New("flowlog: invalid answer")
	// ErrUnavailable reports a receiver fault, not the request's: a plain
	// 503.
	ErrUnavailable = errors.New("flowlog: receiver unavailable")
)

var (
	cipherSuite   = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	deterministic = proto.MarshalOptions{Deterministic: true}
)

// Request is one batch on its way to the receiver: the header value, the
// body, and what opening the answer needs. It is single use. It never
// prints its token.
type Request struct {
	token   redacted
	Body    []byte
	machine key.MachinePrivate
	peer    []byte
	binding []byte
	random  io.Reader
}

// NewRequest seals compressed, a gzip-compressed FlowBatch, for the receiver
// whose Noise static key is receiverKey (FlowTicket.receiver_key), with the
// node's machine key (flowlog-v1 §4). request carries the per-send values;
// its batch_length is set here. random is crypto/rand when nil.
func NewRequest(token []byte, machine key.MachinePrivate, receiverKey []byte, request *flowlogv1.FlowRequest,
	compressed []byte, random io.Reader,
) (*Request, error) {
	if machine.IsZero() || len(receiverKey) != 32 || len(token) == 0 || len(token) > MaxTokenSize ||
		len(compressed) == 0 || len(compressed) > MaxBatchLength || request == nil {
		return nil, ErrInvalidRequest
	}
	if random == nil {
		random = rand.Reader
	}
	request, ok := proto.Clone(request).(*flowlogv1.FlowRequest)
	if !ok {
		return nil, ErrInvalidRequest
	}
	request.BatchLength = uint32(len(compressed)) //nolint:gosec // bounded above
	if err := checkRequest(request); err != nil {
		return nil, err
	}
	payload, err := deterministic.Marshal(request)
	if err != nil || len(payload) > maxRequestPayload {
		return nil, ErrInvalidRequest
	}
	static := machine.ECDH()
	private := static.Bytes()
	defer clear(private)
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Random: random, Pattern: noise.HandshakeX, Initiator: true,
		Prologue:      requestPrologueFor(token),
		StaticKeypair: noise.DHKey{Private: private, Public: static.PublicKey().Bytes()},
		PeerStatic:    bytes.Clone(receiverKey),
	})
	if err != nil {
		return nil, fmt.Errorf("flowlog: request handshake: %w", err)
	}
	first, sending, _, err := handshake.WriteMessage(nil, payload)
	if err != nil || sending == nil {
		return nil, fmt.Errorf("flowlog: request handshake message: %w", err)
	}
	body := appendFrame(make([]byte, 0, len(first)+len(compressed)+len(compressed)/maxChunk*18+64), first)
	for chunk := range chunks(compressed) {
		sealed, err := sending.Encrypt(nil, nil, chunk)
		if err != nil {
			return nil, fmt.Errorf("flowlog: seal batch: %w", err)
		}
		body = appendFrame(body, sealed)
	}
	return &Request{
		token: redacted(base64.RawURLEncoding.EncodeToString(token)), Body: body, machine: machine,
		peer: bytes.Clone(receiverKey), binding: bytes.Clone(handshake.ChannelBinding()), random: random,
	}, nil
}

// TokenHeader is the TokenHeader value of this request.
func (r *Request) TokenHeader() string { return string(r.token) }

// redacted is the token's header value; Request's Format keeps it out of
// any output.
type redacted string

// Format prints a request, or a copy of one, without its token or keys.
func (r Request) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "flowlog.Request(%d bytes)", len(r.Body))
}

// OpenAnswer opens the receiver's answer to this request. Only an answer
// that opens may make a node drop batches (flowlog-v1 §4).
func (r *Request) OpenAnswer(body []byte) (*flowlogv1.FlowBatchResponse, error) {
	frame, rest, ok := readFrame(body)
	if !ok || len(rest) != 0 {
		return nil, ErrInvalidAnswer
	}
	static := r.machine.ECDH()
	private := static.Bytes()
	defer clear(private)
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Random: r.random, Pattern: noise.HandshakeK, Initiator: false,
		Prologue:      answerPrologueFor(r.binding),
		StaticKeypair: noise.DHKey{Private: private, Public: static.PublicKey().Bytes()},
		PeerStatic:    r.peer,
	})
	if err != nil {
		return nil, fmt.Errorf("flowlog: answer handshake: %w", err)
	}
	payload, _, _, err := handshake.ReadMessage(nil, frame)
	if err != nil {
		return nil, ErrInvalidAnswer
	}
	answer := &flowlogv1.FlowBatchResponse{}
	if err := proto.Unmarshal(payload, answer); err != nil || answer.GetStatus() == 0 ||
		answer.GetStatus() > flowlogv1.FlowBatchResponse_OUT_OF_ORDER {
		return nil, ErrInvalidAnswer
	}
	return answer, nil
}

// sealAnswer is the receiver's Noise_K message carrying answer, bound to
// the request whose handshake hash is binding.
func sealAnswer(receiver *ecdh.PrivateKey, machine, binding []byte, answer *flowlogv1.FlowBatchResponse,
	random io.Reader,
) ([]byte, error) {
	payload, err := deterministic.Marshal(answer)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	private := receiver.Bytes()
	defer clear(private)
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Random: random, Pattern: noise.HandshakeK, Initiator: true,
		Prologue:      answerPrologueFor(binding),
		StaticKeypair: noise.DHKey{Private: private, Public: receiver.PublicKey().Bytes()},
		PeerStatic:    bytes.Clone(machine),
	})
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	message, _, _, err := handshake.WriteMessage(nil, payload)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return appendFrame(nil, message), nil
}

func requestPrologueFor(token []byte) []byte {
	return append(append([]byte(requestPrologue), 0), token...)
}

func answerPrologueFor(binding []byte) []byte {
	return append(append([]byte(answerPrologue), 0), binding...)
}

func appendFrame(body, frame []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, uint16(len(frame))) //nolint:gosec // at most noise.MaxMsgLen
	return append(body, frame...)
}

// readFrame splits the first frame off body.
func readFrame(body []byte) ([]byte, []byte, bool) {
	if len(body) < 2 {
		return nil, nil, false
	}
	length := int(binary.BigEndian.Uint16(body))
	if length == 0 || len(body)-2 < length {
		return nil, nil, false
	}
	return body[2 : 2+length], body[2+length:], true
}

func chunks(data []byte) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		for len(data) > 0 {
			size := min(len(data), maxChunk)
			if !yield(data[:size]) {
				return
			}
			data = data[size:]
		}
	}
}

// checkRequest holds a FlowRequest to flowlog-v1 §6 ("Refused requests").
func checkRequest(request *flowlogv1.FlowRequest) error {
	switch length := request.GetBatchLength(); {
	case length == 0:
		return ErrInvalidRequest
	case length > MaxBatchLength:
		return ErrTooLarge
	}
	sequence, heldFrom := request.GetSequence(), request.GetHeldFrom()
	if len(request.GetBootId()) != 16 || sequence == 0 || heldFrom == 0 || heldFrom > sequence {
		return ErrInvalidRequest
	}
	if lost := request.GetLost(); lost != nil {
		first, last := lost.GetFirstSequence(), lost.GetLastSequence()
		// from_ms and to_ms are what the node saw; a clock that stepped back
		// may reverse them, and that must never stop a node from sending.
		if first == 0 || first > last || last >= heldFrom {
			return ErrInvalidRequest
		}
	}
	return nil
}
