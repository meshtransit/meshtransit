package enrollment_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
)

func TestIDParsers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		parse func(string) (string, error)
	}{
		{
			name:  "profile",
			value: "01890f00-0000-7000-8000-000000000401",
			parse: func(value string) (string, error) {
				id, err := enrollment.ParseProfileID(value)
				return id.String(), err
			},
		},
		{
			name:  "credential",
			value: "01890f00-0000-7000-8000-000000000402",
			parse: func(value string) (string, error) {
				id, err := enrollment.ParseCredentialID(value)
				return id.String(), err
			},
		},
		{
			name:  "registration",
			value: "01890f00-0000-7000-8000-000000000403",
			parse: func(value string) (string, error) {
				id, err := enrollment.ParseRegistrationID(value)
				return id.String(), err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := test.parse(test.value)
			if err != nil {
				t.Fatalf("parse() error = %v", err)
			}
			if got != test.value {
				t.Fatalf("parse() = %q, want %q", got, test.value)
			}
			if _, err := test.parse("invalid"); !errors.Is(err, enrollment.ErrInvalidID) {
				t.Fatalf("parse(invalid) error = %v, want ErrInvalidID", err)
			}
		})
	}
}
