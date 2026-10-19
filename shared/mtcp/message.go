package mtcp

import (
	"bytes"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// MessageType is the msg_type byte of a fragment (mtcp-v1 §4.2).
type MessageType uint8

// Message types.
const (
	MessageError                 MessageType = 0x01
	MessagePing                  MessageType = 0x02
	MessagePong                  MessageType = 0x03
	MessageRegisterRequest       MessageType = 0x10
	MessageRegisterResponse      MessageType = 0x11
	MessageRotateNodeKey         MessageType = 0x12
	MessageLogout                MessageType = 0x13
	MessageRotateNodeKeyResponse MessageType = 0x14
	MessageMapSnapshot           MessageType = 0x20
	MessageMapDelta              MessageType = 0x21
	MessageMapAck                MessageType = 0x22
	MessageMapResync             MessageType = 0x23
	MessageEndpointReport        MessageType = 0x30
	MessageHostinfoReport        MessageType = 0x31
	MessageHealthReport          MessageType = 0x32
	MessagePathStatsReport       MessageType = 0x33
	MessageEnforcementReport     MessageType = 0x34
	MessageRouteHealthReport     MessageType = 0x35
	MessageRelayTicket           MessageType = 0x40
	MessageLifecycle             MessageType = 0x50
	MessageKeyUpdate             MessageType = 0x51
	MessageNotice                MessageType = 0x52
)

// Direction is who sends a message.
type Direction uint8

// Directions. Both covers messages either side may send.
const (
	NodeToCore Direction = 1 << iota
	CoreToNode
	Both = NodeToCore | CoreToNode
)

// Fragment flags.
const (
	flagMore uint8 = 1 << 0
	flagZstd uint8 = 1 << 1
)

// maxZstdWindow bounds decoder memory (mtcp-v1 §4.2).
const maxZstdWindow = 8 << 20

type messageSpec struct {
	direction Direction
	limit     int
	new       func() proto.Message
}

const (
	kib = 1 << 10
	mib = 1 << 20
)

var specs = map[MessageType]messageSpec{
	MessageError:                 {Both, 4 * kib, func() proto.Message { return &mtcpv1.Error{} }},
	MessagePing:                  {Both, 256, func() proto.Message { return &mtcpv1.Ping{} }},
	MessagePong:                  {Both, 256, func() proto.Message { return &mtcpv1.Pong{} }},
	MessageRegisterRequest:       {NodeToCore, 16 * kib, func() proto.Message { return &mtcpv1.RegisterRequest{} }},
	MessageRegisterResponse:      {CoreToNode, 8 * kib, func() proto.Message { return &mtcpv1.RegisterResponse{} }},
	MessageRotateNodeKey:         {NodeToCore, 4 * kib, func() proto.Message { return &mtcpv1.RotateNodeKey{} }},
	MessageLogout:                {NodeToCore, kib, func() proto.Message { return &mtcpv1.Logout{} }},
	MessageRotateNodeKeyResponse: {CoreToNode, kib, func() proto.Message { return &mtcpv1.RotateNodeKeyResponse{} }},
	MessageMapSnapshot:           {CoreToNode, 32 * mib, func() proto.Message { return &mtcpv1.MapSnapshot{} }},
	MessageMapDelta:              {CoreToNode, 8 * mib, func() proto.Message { return &mtcpv1.MapDelta{} }},
	MessageMapAck:                {NodeToCore, 256, func() proto.Message { return &mtcpv1.MapAck{} }},
	MessageMapResync:             {NodeToCore, 256, func() proto.Message { return &mtcpv1.MapResync{} }},
	MessageEndpointReport:        {NodeToCore, 8 * kib, func() proto.Message { return &mtcpv1.EndpointReport{} }},
	MessageHostinfoReport:        {NodeToCore, 8 * kib, func() proto.Message { return &mtcpv1.HostinfoReport{} }},
	MessageHealthReport:          {NodeToCore, 16 * kib, func() proto.Message { return &mtcpv1.HealthReport{} }},
	MessagePathStatsReport:       {NodeToCore, 256 * kib, func() proto.Message { return &mtcpv1.PathStatsReport{} }},
	MessageEnforcementReport:     {NodeToCore, kib, func() proto.Message { return &mtcpv1.EnforcementReport{} }},
	// 1,024 Sites of a 64-byte reference and a 64-byte code each.
	MessageRouteHealthReport: {NodeToCore, 160 * kib, func() proto.Message { return &mtcpv1.RouteHealthReport{} }},
	MessageRelayTicket:       {CoreToNode, 256 * kib, func() proto.Message { return &mtcpv1.RelayTicket{} }}, // MTT2 zones: 17 bytes × 10,001
	MessageLifecycle:         {CoreToNode, 4 * kib, func() proto.Message { return &mtcpv1.Lifecycle{} }},
	MessageKeyUpdate:         {CoreToNode, 4 * kib, func() proto.Message { return &mtcpv1.KeyUpdate{} }},
	MessageNotice:            {CoreToNode, 8 * kib, func() proto.Message { return &mtcpv1.Notice{} }},
}

// Limit returns the decoded size limit of a message type, or 0 if unknown.
func (t MessageType) Limit() int { return specs[t].limit }

// EncodeOptions controls message encoding.
type EncodeOptions struct {
	// Compress sets ZSTD when the peer negotiated map.zstd and the message is
	// worth compressing.
	Compress bool
}

var encoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1),
	zstd.WithWindowSize(maxZstdWindow), zstd.WithZeroFrames(true))

// EncodeMessage returns the fragments (TRANSPORT plaintexts, in order) that
// carry m as message type t from a sender in direction from.
func EncodeMessage(t MessageType, m proto.Message, from Direction, options EncodeOptions) ([][]byte, error) {
	spec, known := specs[t]
	if !known {
		return nil, ErrUnsupported
	}
	if spec.direction&from == 0 {
		return nil, ErrDirection
	}
	payload, err := marshal.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("mtcp: encode message %#x: %w", uint8(t), err)
	}
	if len(payload) > spec.limit {
		return nil, ErrTooLarge
	}
	var flags uint8
	if options.Compress && len(payload) >= minCompressed {
		if compressed, ok := compress(payload); ok {
			payload, flags = compressed, flagZstd
		}
	}
	count := max(1, (len(payload)+MaxFragmentPayload-1)/MaxFragmentPayload)
	fragments := make([][]byte, 0, count)
	for start := 0; start < len(payload) || len(fragments) == 0; start += MaxFragmentPayload {
		end := min(start+MaxFragmentPayload, len(payload))
		fragmentFlags := flags
		if end < len(payload) {
			fragmentFlags |= flagMore
		}
		fragment := make([]byte, 0, fragmentHeader+end-start)
		fragment = append(fragment, byte(t), fragmentFlags)
		fragments = append(fragments, append(fragment, payload[start:end]...))
	}
	return fragments, nil
}

// Assembler reassembles fragments received in one direction into messages,
// enforcing each type's limit while reassembling and decompressing. It is
// not safe for concurrent use.
type Assembler struct {
	accept     Direction
	inProgress bool
	t          MessageType
	zstd       bool
	buf        bytes.Buffer
}

// NewAssembler accepts messages that a sender in direction from may send:
// a node assembles CoreToNode, Core assembles NodeToCore.
func NewAssembler(from Direction) *Assembler { return &Assembler{accept: from} }

// Add consumes one fragment. When it completes a message, Add returns the
// message type and the decoded protobuf payload. Any error is fatal for the
// session.
func (a *Assembler) Add(fragment []byte) (MessageType, []byte, bool, error) {
	if len(fragment) < fragmentHeader {
		return 0, nil, false, ErrMalformed
	}
	t, flags, body := MessageType(fragment[0]), fragment[1], fragment[fragmentHeader:]
	spec, known := specs[t]
	switch {
	case !known:
		return 0, nil, false, ErrUnsupported
	case spec.direction&a.accept == 0:
		return 0, nil, false, ErrDirection
	case flags&^(flagMore|flagZstd) != 0:
		return 0, nil, false, ErrMalformed
	case a.inProgress && (t != a.t || (flags&flagZstd != 0) != a.zstd):
		return 0, nil, false, ErrMalformed
	}
	if !a.inProgress {
		a.inProgress, a.t, a.zstd = true, t, flags&flagZstd != 0
		a.buf.Reset()
	}
	// A compressed message may not exceed the limit either: zstd never needs
	// more than a few bytes over the input for incompressible data.
	if a.buf.Len()+len(body) > spec.limit+compressionSlack(spec.limit) {
		return 0, nil, false, ErrTooLarge
	}
	a.buf.Write(body)
	if flags&flagMore != 0 {
		return 0, nil, false, nil
	}
	a.inProgress = false
	payload := bytes.Clone(a.buf.Bytes())
	if !a.zstd {
		if len(payload) > spec.limit {
			return 0, nil, false, ErrTooLarge
		}
		return t, payload, true, nil
	}
	decoded, err := decompress(payload, spec.limit)
	if err != nil {
		return 0, nil, false, err
	}
	return t, decoded, true, nil
}

func compressionSlack(limit int) int { return limit/128 + 64 }

// minCompressed is the smallest payload worth compressing.
const minCompressed = 1024

// compress returns payload as one zstd frame when the frame declares its
// content size, which receivers require; the encoder omits it for some
// small inputs, and those are sent uncompressed.
func compress(payload []byte) ([]byte, bool) {
	frame := encoder.EncodeAll(payload, make([]byte, 0, len(payload)/2+64))
	var header zstd.Header
	if err := header.Decode(frame); err != nil || !header.HasFCS || header.FrameContentSize != uint64(len(payload)) {
		return nil, false
	}
	return frame, true
}

// decompress decodes one zstd frame that declares its content size, which
// must not exceed limit; the declared size bounds the allocation.
func decompress(frame []byte, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, ErrMalformed
	}
	bound := uint64(limit)
	var header zstd.Header
	if err := header.Decode(frame); err != nil || !header.HasFCS || header.FrameContentSize > bound ||
		header.WindowSize > maxZstdWindow {
		return nil, ErrMalformed
	}
	size := int64(header.FrameContentSize) //nolint:gosec // bounded by limit above
	decoder, err := zstd.NewReader(bytes.NewReader(frame), zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(maxZstdWindow), zstd.WithDecoderMaxMemory(bound))
	if err != nil {
		return nil, ErrMalformed
	}
	defer decoder.Close()
	buffer := bytes.NewBuffer(make([]byte, 0, size))
	n, err := io.Copy(buffer, io.LimitReader(decoder, size+1))
	if err != nil || n != size {
		return nil, ErrMalformed
	}
	return buffer.Bytes(), nil
}

// DecodeMessage parses the payload of a completed message.
func DecodeMessage(t MessageType, payload []byte) (proto.Message, error) {
	spec, known := specs[t]
	if !known {
		return nil, ErrUnsupported
	}
	m := spec.new()
	if err := unmarshal.Unmarshal(payload, m); err != nil {
		return nil, ErrMalformed
	}
	return m, nil
}
