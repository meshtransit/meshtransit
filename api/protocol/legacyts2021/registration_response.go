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
