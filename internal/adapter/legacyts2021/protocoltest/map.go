//go:build integration

package protocoltest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"
)

const maximumDecodedMapBytes = 64 << 10

// FullMap is the protocol-neutral evidence returned by one black-box map exchange.
type FullMap struct {
	NodeID            int64
	OwnerID           int64
	StableNodeID      string
	Name              string
	ComputedName      string
	MachineKey        [32]byte
	NodeKey           [32]byte
	Addresses         []netip.Prefix
	AllowedIPs        []netip.Prefix
	CapabilityVersion int
	MachineAuthorized bool
	PeerCount         int
	DenyAll           bool
}

func (client *Client) fetchFullMap(ctx context.Context, session *session) (FullMap, error) {
	response, err := client.requestMap(ctx, session, false)
	if err != nil {
		return FullMap{}, err
	}
	body, err := readResponse(response)
	if err != nil {
		return FullMap{}, fmt.Errorf("read map response: %w", err)
	}
	defer clear(body)
	if err := validateMapResponse(response); err != nil {
		return FullMap{}, err
	}
	return decodeFullMap(body)
}

func (client *Client) requestMap(
	ctx context.Context,
	session *session,
	streaming bool,
) (*http.Response, error) {
	if session == nil || session.connection == nil {
		return nil, ErrInvalidClient
	}
	payload, err := json.Marshal(tailcfg.MapRequest{
		Version:       testCapabilityVersion,
		Compress:      "zstd",
		KeepAlive:     true,
		NodeKey:       client.nodeKey.Public(),
		DiscoKey:      client.discoveryKey.Public(),
		Endpoints:     slices.Clone(client.connectivity.Endpoints),
		EndpointTypes: []tailcfg.EndpointType{tailcfg.EndpointSTUN},
		Stream:        streaming,
		Hostinfo:      &tailcfg.Hostinfo{Hostname: client.hostname},
	})
	if err != nil {
		return nil, fmt.Errorf("encode map request: %w", err)
	}
	defer clear(payload)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://"+client.tlsServerName+"/machine/map",
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("build map request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := session.connection.RoundTrip(request)
	if err != nil {
		return nil, fmt.Errorf("submit map request: %w", err)
	}
	return response, nil
}

func validateMapResponse(response *http.Response) error {
	if response == nil || response.Body == nil {
		return ErrInvalidClient
	}
	if response.StatusCode != http.StatusOK || !isMediaType(
		response.Header.Get("Content-Type"),
		"application/octet-stream",
	) {
		return fmt.Errorf("%w: status %d", ErrMap, response.StatusCode)
	}
	return nil
}

func readMapFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, ErrInvalidClient
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := int(header[0]) |
		int(header[1])<<8 |
		int(header[2])<<16 |
		int(header[3])<<24
	if length <= 0 || length > testResponseLimit-4 {
		return nil, ErrInvalidClient
	}
	frame := make([]byte, len(header)+length)
	copy(frame, header[:])
	if _, err := io.ReadFull(reader, frame[len(header):]); err != nil {
		clear(frame)
		return nil, err
	}
	return frame, nil
}

func decodeFullMap(frame []byte) (FullMap, error) {
	if len(frame) < 5 || int64(binary.LittleEndian.Uint32(frame[:4])) != int64(len(frame)-4) {
		return FullMap{}, ErrInvalidClient
	}
	document, err := zstdframe.AppendDecode(
		nil,
		frame[4:],
		zstdframe.MaxDecodedSize(maximumDecodedMapBytes),
	)
	if err != nil {
		return FullMap{}, fmt.Errorf("decode map compression: %w", err)
	}
	defer clear(document)
	var response tailcfg.MapResponse
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return FullMap{}, fmt.Errorf("decode map document: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return FullMap{}, ErrInvalidClient
	}
	if response.Node == nil || response.Peers == nil || response.PacketFilter == nil {
		return FullMap{}, ErrInvalidClient
	}
	machineKey, err := rawMachinePublic(response.Node.Machine)
	if err != nil {
		return FullMap{}, fmt.Errorf("decode map machine identity: %w", err)
	}
	nodeKey, err := rawNodePublic(response.Node.Key)
	if err != nil {
		return FullMap{}, fmt.Errorf("decode map node identity: %w", err)
	}
	return FullMap{
		NodeID:            int64(response.Node.ID),
		OwnerID:           int64(response.Node.User),
		StableNodeID:      string(response.Node.StableID),
		Name:              response.Node.Name,
		ComputedName:      response.Node.ComputedName,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		Addresses:         slices.Clone(response.Node.Addresses),
		AllowedIPs:        slices.Clone(response.Node.AllowedIPs),
		CapabilityVersion: int(response.Node.Cap),
		MachineAuthorized: response.Node.MachineAuthorized,
		PeerCount:         len(response.Peers),
		DenyAll:           len(response.PacketFilter) == 0,
	}, nil
}

func isMediaType(value, want string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == want
}
