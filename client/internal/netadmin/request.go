//go:build linux || darwin

package netadmin

import (
	"encoding/json"
	"errors"
	"fmt"
)

type remoteError struct {
	code    string
	message string
}

func (e *remoteError) Error() string {
	return fmt.Sprintf("%s: %s", ErrRemote, e.message)
}

func (e *remoteError) Unwrap() error { return ErrRemote }

func encodeMessage(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding message: %w", ErrProtocol, err)
	}
	if len(payload) == 0 || len(payload) > maxMessageBytes {
		return nil, fmt.Errorf("%w: message size is outside the allowed range", ErrProtocol)
	}

	return payload, nil
}

func newOpenTUNRequest(config TUNConfig) (request, TUNConfig, error) {
	return newTUNRequest(operationOpenTUN, config)
}

func newSetTUNRequest(config TUNConfig) (request, TUNConfig, error) {
	return newTUNRequest(operationSetTUN, config)
}

func newTUNRequest(operation string, config TUNConfig) (request, TUNConfig, error) {
	normalized, err := normalizeTUNConfig(config)
	if err != nil {
		return request{}, TUNConfig{}, err
	}

	return request{
		Version:   protocolVersion,
		Operation: operation,
		Addresses: prefixStrings(normalized.Addresses),
		Routes:    prefixStrings(normalized.Routes),
	}, normalized, nil
}

// errRequestFraming reports a request that is truncated, carries
// descriptors or is not exactly one message.
var errRequestFraming = errors.New("netadmin: invalid request framing")
