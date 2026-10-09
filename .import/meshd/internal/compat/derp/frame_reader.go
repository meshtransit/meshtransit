package derp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/meshtransit/meshd/internal/relay"
	protocol "tailscale.com/derp"
)

const (
	maxServerInfoFrameSize = 64 << 10
	maxHealthFrameSize     = 1 << 10
	maxPeerStateFrameSize  = 1 << 10
)

type serverFramePhase uint8

const (
	serverFrameGreeting serverFramePhase = iota + 1
	serverFrameConfirmation
	serverFrameEstablished
)

// serverFrameReader bounds and validates relay frames before the compatibility
// dependency can allocate from lengths controlled by a remote server.
type serverFrameReader struct {
	source           io.Reader
	header           [protocol.FrameHeaderLen]byte
	headerOffset     int
	payloadRemaining int
	phase            serverFramePhase
}

func newServerFrameReader(source io.Reader) *serverFrameReader {
	return &serverFrameReader{
		source: source,
		phase:  serverFrameGreeting,
	}
}

func (r *serverFrameReader) Read(destination []byte) (int, error) {
	if r == nil || r.source == nil {
		return 0, errors.New("relay protocol: frame reader is not initialized")
	}
	if len(destination) == 0 {
		return 0, nil
	}
	if r.headerOffset == len(r.header) && r.payloadRemaining == 0 {
		r.headerOffset = 0
	}
	if r.headerOffset == 0 && r.payloadRemaining == 0 {
		if _, err := io.ReadFull(r.source, r.header[:]); err != nil {
			return 0, err
		}
		frameType := protocol.FrameType(r.header[0])
		frameSize := binary.BigEndian.Uint32(r.header[1:])
		if err := r.validateFrame(frameType, frameSize); err != nil {
			return 0, err
		}
	}
	if r.headerOffset < len(r.header) {
		count := copy(destination, r.header[r.headerOffset:])
		r.headerOffset += count

		return count, nil
	}

	readLimit := min(len(destination), r.payloadRemaining)
	count, err := r.source.Read(destination[:readLimit])
	r.payloadRemaining -= count

	return count, err
}

func (r *serverFrameReader) validateFrame(frameType protocol.FrameType, frameSize uint32) error {
	if r.phase == serverFrameGreeting {
		if frameType != protocol.FrameServerKey ||
			frameSize < uint32(len(protocol.Magic)+protocol.KeyLen) || frameSize > 1<<10 {
			return errors.New("relay protocol: server greeting frame is invalid")
		}
		r.payloadRemaining = int(frameSize)
		r.phase = serverFrameConfirmation

		return nil
	}
	if r.phase == serverFrameConfirmation {
		if frameType != protocol.FrameServerInfo ||
			frameSize < protocol.NonceLen || frameSize > maxServerInfoFrameSize {
			return errors.New("relay protocol: server confirmation frame is invalid")
		}
		r.payloadRemaining = int(frameSize)
		r.phase = serverFrameEstablished

		return nil
	}

	if !isValidEstablishedFrame(frameType, frameSize) {
		return fmt.Errorf(
			"relay protocol: inbound frame type %d with size %d is invalid",
			frameType,
			frameSize,
		)
	}
	r.payloadRemaining = int(frameSize)

	return nil
}

func isValidEstablishedFrame(frameType protocol.FrameType, frameSize uint32) bool {
	switch frameType {
	case protocol.FrameServerInfo:
		return frameSize >= protocol.NonceLen && frameSize <= maxServerInfoFrameSize
	case protocol.FrameRecvPacket:
		return frameSize > protocol.KeyLen &&
			frameSize <= protocol.KeyLen+relay.MaxPacketSize
	case protocol.FrameKeepAlive:
		return frameSize == 0
	case protocol.FramePeerGone:
		return frameSize >= protocol.KeyLen && frameSize <= maxPeerStateFrameSize
	case protocol.FramePeerPresent:
		return frameSize >= protocol.KeyLen && frameSize <= maxPeerStateFrameSize
	case protocol.FramePing, protocol.FramePong:
		return frameSize == 8
	case protocol.FrameHealth:
		return frameSize <= maxHealthFrameSize
	case protocol.FrameRestarting:
		return frameSize == 8
	default:
		return false
	}
}
