//go:build integration

package protocoltest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type registrationRequest struct {
	Version        int              `json:"Version"`
	NodeKey        string           `json:"NodeKey"`
	OldNodeKey     string           `json:"OldNodeKey"`
	NetworkLockKey string           `json:"NLKey"`
	Auth           registrationAuth `json:"Auth"`
	HostInfo       registrationHost `json:"Hostinfo"`
}

type registrationAuth struct {
	AuthKey string `json:"AuthKey"`
}

type registrationHost struct {
	Hostname string `json:"Hostname"`
}

type registrationResponse struct {
	MachineAuthorized bool `json:"MachineAuthorized"`
}

func (client *Client) register(
	ctx context.Context,
	session *session,
	credential string,
) error {
	if session == nil || session.connection == nil {
		return ErrInvalidClient
	}
	payload, err := json.Marshal(registrationRequest{
		Version:        testCapabilityVersion,
		NodeKey:        client.nodeKey.Public().String(),
		OldNodeKey:     "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
		NetworkLockKey: "nlpub:0000000000000000000000000000000000000000000000000000000000000000",
		Auth:           registrationAuth{AuthKey: credential},
		HostInfo:       registrationHost{Hostname: client.hostname},
	})
	if err != nil {
		return fmt.Errorf("encode registration request: %w", err)
	}
	defer clear(payload)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://"+client.tlsServerName+"/machine/register",
		bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("build registration request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := session.connection.RoundTrip(request)
	if err != nil {
		return fmt.Errorf("submit registration request: %w", err)
	}
	body, err := readResponse(response)
	if err != nil {
		return fmt.Errorf("read registration response: %w", err)
	}
	defer clear(body)
	if response.StatusCode != http.StatusOK || !isJSON(response.Header.Get("Content-Type")) {
		return fmt.Errorf("%w: status %d", ErrRegistration, response.StatusCode)
	}
	var result registrationResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode registration response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !result.MachineAuthorized {
		return ErrInvalidClient
	}
	return nil
}
