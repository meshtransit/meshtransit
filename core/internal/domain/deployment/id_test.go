package deployment_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/deployment"
)

const testDeploymentID = "01890f00-0000-7000-8000-000000000001"

func TestID(t *testing.T) {
	t.Parallel()

	id, err := deployment.ParseID(testDeploymentID)
	if err != nil {
		t.Fatalf("ParseID() error = %v", err)
	}
	if !id.IsValid() || id.String() != testDeploymentID {
		t.Fatalf("ParseID() = %q, want %q", id.String(), testDeploymentID)
	}
	if id.Bytes() != [16]byte{
		0x01, 0x89, 0x0f, 0x00, 0x00, 0x00, 0x70, 0x00,
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	} {
		t.Fatal("Bytes() changed the Deployment ID representation")
	}
}

func TestIDRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		parse func() error
	}{
		{
			name: "empty string",
			parse: func() error {
				_, err := deployment.ParseID("")
				return err
			},
		},
		{
			name: "zero bytes",
			parse: func() error {
				_, err := deployment.NewID([16]byte{})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := test.parse(); !errors.Is(err, deployment.ErrInvalidID) {
				t.Fatalf("constructor error = %v, want ErrInvalidID", err)
			}
		})
	}

	if (deployment.ID{}).IsValid() {
		t.Fatal("zero Deployment ID is valid")
	}
}
