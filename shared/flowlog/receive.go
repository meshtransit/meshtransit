package flowlog

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
)

// Receiver checks requests as flowlog-v1 §4 orders it. Its fields are set
// once and read concurrently.
type Receiver struct {
	// Key is the receiver's Noise static key (X25519).
	Key *ecdh.PrivateKey
	// SigningKeys are Core's token keys by kid; Audience is this
	// deployment's ("meshflow:<deployment ID>").
	SigningKeys map[string]ed25519.PublicKey
	Audience    string
	// Random is crypto/rand when nil.
	Random io.Reader
}

// CheckToken is step 2: the header's token, before any of the body is read.
// Its errors are a plain 401.
func (r *Receiver) CheckToken(header string, now time.Time) (*Token, error) {
	if header == "" || len(header) > base64.RawURLEncoding.EncodedLen(MaxTokenSize) {
		return nil, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return VerifyToken(raw, r.SigningKeys, r.Audience, now)
}

// Incoming is a request past step 3: its sender holds the token's machine
// key. Revocation and rate limits (step 4) and the sequence rules (step 5)
// are the caller's; ReadBatch is steps 6 and 7.
type Incoming struct {
	Claims  *flowlogv1.FlowTokenClaims
	Request *flowlogv1.FlowRequest
	token   []byte
	machine []byte
	binding []byte
	cipher  *noise.CipherState
	body    io.Reader
	random  io.Reader
	key     *ecdh.PrivateKey
}

// ReadHandshake is step 3: frame 0 from body, the Noise_X message under the
// token's prologue, the sender's key against the token, and the
// FlowRequest. ErrWrongMachineKey is a plain 403, ErrTooLarge 413, any
// other error 400.
func (r *Receiver) ReadHandshake(token *Token, body io.Reader) (*Incoming, error) {
	if r == nil || r.Key == nil || token == nil {
		return nil, ErrFraming
	}
	raw := token.raw
	frame, err := nextFrame(body, maxHandshakeFrame)
	if err != nil {
		return nil, err
	}
	random := r.Random
	if random == nil {
		random = rand.Reader
	}
	private := r.Key.Bytes()
	defer clear(private)
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Random: random, Pattern: noise.HandshakeX, Initiator: false,
		Prologue:      requestPrologueFor(raw),
		StaticKeypair: noise.DHKey{Private: private, Public: r.Key.PublicKey().Bytes()},
	})
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	payload, receiving, _, err := handshake.ReadMessage(nil, frame)
	if err != nil || receiving == nil {
		return nil, ErrFraming
	}
	machine := handshake.PeerStatic()
	claims, err := token.Claims(machine)
	if err != nil {
		return nil, err
	}
	request := &flowlogv1.FlowRequest{}
	if err := proto.Unmarshal(payload, request); err != nil || hasUnknown(request.ProtoReflect()) {
		return nil, ErrInvalidRequest
	}
	if err := checkRequest(request); err != nil {
		return nil, err
	}
	return &Incoming{
		Claims: claims, Request: request, token: raw, machine: bytes.Clone(machine),
		binding: bytes.Clone(handshake.ChannelBinding()), cipher: receiving, body: body, random: random, key: r.Key,
	}, nil
}

// ReadBatch is steps 6 and 7: the transport frames, each full but the
// last, exactly batch_length bytes of plaintext and nothing after, then the
// batch decompressed and decoded. ErrFraming is a plain 400 (the node sends
// again); ErrInvalidBatch is a content error the receiver answers INVALID.
//
// Memory grows with the frames that decrypt, up to MaxBatchLength, then
// MaxBatchSize to decompress. Only the token's machine key holder, or a
// replay of its request, gets here: the caller reads at most one batch per
// (Device, boot_id) at a time and caps the body at MaxBodySize.
func (in *Incoming) ReadBatch() (*flowlogv1.FlowBatch, error) {
	want := int(in.Request.GetBatchLength())
	compressed := make([]byte, 0, min(want, maxChunk))
	frame := make([]byte, noise.MaxMsgLen)
	for len(compressed) < want {
		length, err := readFrameInto(in.body, frame)
		if err != nil {
			return nil, err
		}
		before := len(compressed)
		compressed, err = in.cipher.Decrypt(compressed, nil, frame[:length])
		chunk := len(compressed) - before
		if err != nil || chunk == 0 || len(compressed) > want || chunk < maxChunk && len(compressed) < want {
			return nil, ErrFraming
		}
	}
	var extra [1]byte
	if n, _ := io.ReadFull(in.body, extra[:]); n != 0 {
		return nil, ErrFraming
	}
	batch, err := decodeBatch(compressed)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(batch.GetBootId(), in.Request.GetBootId()) ||
		batch.GetReporterSequence() != in.Request.GetSequence() {
		return nil, ErrInvalidBatch
	}
	return batch, nil
}

// Answer seals answer for this request's sender (flowlog-v1 §4, Answer).
func (in *Incoming) Answer(answer *flowlogv1.FlowBatchResponse) ([]byte, error) {
	return sealAnswer(in.key, in.machine, in.binding, answer, in.random)
}

func decodeBatch(compressed []byte) (*flowlogv1.FlowBatch, error) {
	source := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return nil, ErrInvalidBatch
	}
	reader.Multistream(false)
	plain, err := io.ReadAll(io.LimitReader(reader, MaxBatchSize+1))
	// One gzip member and nothing after it: a bytes.Reader is read without
	// buffering, so what is left in source follows the member.
	if err != nil || len(plain) > MaxBatchSize || source.Len() != 0 {
		return nil, ErrInvalidBatch
	}
	batch := &flowlogv1.FlowBatch{}
	if err := proto.Unmarshal(plain, batch); err != nil || hasUnknown(batch.ProtoReflect()) {
		return nil, ErrInvalidBatch
	}
	return batch, nil
}

// hasUnknown reports fields this reader does not know anywhere in message,
// nested messages included: they are refused rather than ignored.
func hasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.Message() == nil:
		case field.IsMap():
			value.Map().Range(func(_ protoreflect.MapKey, entry protoreflect.Value) bool {
				if field.MapValue().Message() != nil && hasUnknown(entry.Message()) {
					unknown = true
				}
				return !unknown
			})
		case field.IsList():
			list := value.List()
			for index := range list.Len() {
				if hasUnknown(list.Get(index).Message()) {
					unknown = true
				}
			}
		default:
			unknown = hasUnknown(value.Message())
		}
		return !unknown
	})
	return unknown
}

// MaxBodySize bounds a request body whose batch is length bytes: frame 0
// and every frame full but the last.
func MaxBodySize(length int) int64 {
	frames := (length + maxChunk - 1) / maxChunk
	return int64(2+maxHandshakeFrame) + int64(length) + int64(frames)*(2+16)
}

// nextFrame reads one u16-length-prefixed frame of at most limit bytes.
func nextFrame(body io.Reader, limit int) ([]byte, error) {
	frame := make([]byte, limit)
	length, err := readFrameInto(body, frame)
	if err != nil {
		return nil, err
	}
	return frame[:length], nil
}

// readFrameInto reads one frame into buffer, which bounds it.
func readFrameInto(body io.Reader, buffer []byte) (int, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(body, prefix[:]); err != nil {
		return 0, ErrFraming
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length == 0 || length > len(buffer) {
		return 0, ErrFraming
	}
	if _, err := io.ReadFull(body, buffer[:length]); err != nil {
		return 0, ErrFraming
	}
	return length, nil
}

// Status maps a receiver error to the plain HTTP status flowlog-v1 §4 gives
// it before an answer can be sealed; 0 for ErrInvalidBatch, which is
// answered INVALID in a sealed answer.
func Status(err error) int {
	switch {
	case err == nil, errors.Is(err, ErrInvalidBatch):
		return 0
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrTokenExpired), errors.Is(err, ErrUnknownKey):
		return 401
	case errors.Is(err, ErrWrongMachineKey):
		return 403
	case errors.Is(err, ErrTooLarge):
		return 413
	case errors.Is(err, ErrNotOwner):
		return 421
	case errors.Is(err, ErrWrongNetwork):
		return 400
	case errors.Is(err, ErrUnavailable):
		return 503
	default:
		return 400
	}
}

var (
	// ErrWrongNetwork reports a NetworkHeader that is not the token's
	// Network: a plain 400.
	ErrWrongNetwork = errors.New("flowlog: network header is not the token's network")
	// ErrNotOwner reports a request for a Network another replica writes: a
	// plain 421 with Retry-After, which the node sends again (flowlog-v1 §4).
	ErrNotOwner = errors.New("flowlog: another receiver writes this network")
)

// NetworkHeaderOf is the NetworkHeader value for token: its Network, read
// without checking the signature (the node only routes with it).
func NetworkHeaderOf(token []byte) (string, error) {
	claims, err := ReadClaims(token)
	if err != nil {
		return "", err
	}
	return formatUUID(claims.GetNetworkId())
}

// CheckNetworkHeader is part of step 3: the header must name the Network of
// claims, which came out of a checked token.
func CheckNetworkHeader(header string, claims *flowlogv1.FlowTokenClaims) error {
	expected, err := formatUUID(claims.GetNetworkId())
	if err != nil || header != expected {
		return ErrWrongNetwork
	}
	return nil
}

// formatUUID writes a 16-byte ID as a lowercase UUID.
func formatUUID(id []byte) (string, error) {
	if len(id) != 16 {
		return "", ErrInvalidToken
	}
	text := hex.EncodeToString(id)
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:], nil
}
