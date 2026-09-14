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
	if session == nil || session.connection == nil {
		return FullMap{}, ErrInvalidClient
	}
	payload, err := json.Marshal(tailcfg.MapRequest{
		Version:  testCapabilityVersion,
		Compress: "zstd",
		NodeKey:  client.nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: client.hostname},
	})
	if err != nil {
		return FullMap{}, fmt.Errorf("encode map request: %w", err)
	}
	defer clear(payload)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://"+client.tlsServerName+"/machine/map",
		bytes.NewReader(payload),
	)
	if err != nil {
		return FullMap{}, fmt.Errorf("build map request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := session.connection.RoundTrip(request)
	if err != nil {
		return FullMap{}, fmt.Errorf("submit map request: %w", err)
	}
	body, err := readResponse(response)
	if err != nil {
		return FullMap{}, fmt.Errorf("read map response: %w", err)
	}
	defer clear(body)
	if response.StatusCode != http.StatusOK || !isMediaType(
		response.Header.Get("Content-Type"),
		"application/octet-stream",
	) {
		return FullMap{}, fmt.Errorf("%w: status %d", ErrMap, response.StatusCode)
	}
	return decodeFullMap(body)
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
