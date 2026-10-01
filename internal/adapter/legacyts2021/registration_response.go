package legacyts2021

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrRegistrationResponse reports an unavailable response writer or encoding failure.
var ErrRegistrationResponse = errors.New("legacyts2021: registration response failed")

type authorizedRegistrationResponseWire struct {
	MachineAuthorized bool `json:"MachineAuthorized"`
}

type pendingBrowserRegistrationResponseWire struct {
	MachineAuthorized bool   `json:"MachineAuthorized"`
	AuthURL           string `json:"AuthURL"`
}

// WriteAuthorizedRegistrationResponse writes the successful credential
// registration response expected by the pinned client profile.
func WriteAuthorizedRegistrationResponse(writer io.Writer) error {
	if writer == nil {
		return ErrRegistrationResponse
	}
	if err := json.NewEncoder(writer).Encode(authorizedRegistrationResponseWire{
		MachineAuthorized: true,
	}); err != nil {
		return fmt.Errorf("%w: encode authorized response: %w", ErrRegistrationResponse, err)
	}
	return nil
}

// WritePendingBrowserRegistrationResponse writes the exact server-issued URL
// for a browser authorization that has not completed. The caller must bind the
// URL to the current public control origin and a durable machine-bound intent.
func WritePendingBrowserRegistrationResponse(writer io.Writer, authURL string) error {
	if writer == nil || !validBrowserFollowupURL(authURL) {
		return ErrRegistrationResponse
	}
	if err := json.NewEncoder(writer).Encode(pendingBrowserRegistrationResponseWire{
		MachineAuthorized: false,
		AuthURL:           authURL,
	}); err != nil {
		return fmt.Errorf("%w: encode pending response: %w", ErrRegistrationResponse, err)
	}
	return nil
}
