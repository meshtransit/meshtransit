package legacyts2021

import (
	"bytes"
	"errors"
	"testing"
)

func TestWriteAuthorizedRegistrationResponse(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := WriteAuthorizedRegistrationResponse(&output); err != nil {
		t.Fatalf("WriteAuthorizedRegistrationResponse() error = %v", err)
	}
	if got := output.String(); got != "{\"MachineAuthorized\":true}\n" {
		t.Fatalf("WriteAuthorizedRegistrationResponse() = %q, want authorized response", got)
	}
}

func TestWriteAuthorizedRegistrationResponseRejectsUnavailableWriter(t *testing.T) {
	t.Parallel()

	if err := WriteAuthorizedRegistrationResponse(nil); !errors.Is(err, ErrRegistrationResponse) {
		t.Fatalf("WriteAuthorizedRegistrationResponse(nil) error = %v, want response failure", err)
	}
	wantErr := errors.New("controlled write failure")
	err := WriteAuthorizedRegistrationResponse(registrationErrorWriter{err: wantErr})
	if !errors.Is(err, ErrRegistrationResponse) || !errors.Is(err, wantErr) {
		t.Fatalf("WriteAuthorizedRegistrationResponse(error) = %v, want wrapped write failure", err)
	}
}

type registrationErrorWriter struct {
	err error
}

func (writer registrationErrorWriter) Write([]byte) (int, error) {
	return 0, writer.err
}
