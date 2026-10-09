package publicid

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

const testID = "01890f00-0000-7000-8000-000000000001"

func TestNewAt(t *testing.T) {
	t.Parallel()

	timestamp := time.UnixMilli(0x01890f000000).UTC()
	entropy := make([]byte, 10)
	entropy[len(entropy)-1] = 1
	id, err := newAt(timestamp, bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("newAt() error = %v", err)
	}
	if id.String() != testID {
		t.Fatalf("newAt().String() = %q, want %q", id.String(), testID)
	}
	if !id.IsValid() {
		t.Fatal("newAt() returned invalid id")
	}
}

func TestNewAtRejectsInvalidSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		timestamp time.Time
		entropy   *bytes.Reader
		wantErr   error
		wantAny   bool
	}{
		{
			name:      "time before unix epoch",
			timestamp: time.UnixMilli(-1),
			entropy:   bytes.NewReader(make([]byte, 10)),
			wantErr:   ErrTimeOutOfRange,
		},
		{
			name:      "insufficient entropy",
			timestamp: time.UnixMilli(1),
			entropy:   bytes.NewReader(make([]byte, 9)),
			wantAny:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := newAt(test.timestamp, test.entropy)
			if test.wantAny {
				if err == nil {
					t.Fatal("newAt() error = nil, want entropy error")
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("newAt() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid", value: testID},
		{name: "empty", wantErr: true},
		{name: "uppercase", value: strings.ToUpper(testID), wantErr: true},
		{name: "wrong version", value: "01890f00-0000-4000-8000-000000000001", wantErr: true},
		{name: "wrong variant", value: "01890f00-0000-7000-c000-000000000001", wantErr: true},
		{name: "missing separator", value: "01890f000000-7000-8000-000000000001", wantErr: true},
		{name: "invalid hex", value: "01890f00-0000-7000-8000-00000000000g", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			id, err := Parse(test.value)
			if test.wantErr {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Parse() error = %v, want ErrInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if id.String() != test.value {
				t.Fatalf("Parse().String() = %q, want %q", id.String(), test.value)
			}
			if id.Bytes() != [16]byte(id) {
				t.Fatal("Bytes() changed the binary representation")
			}
		})
	}
}

func TestZeroIDIsInvalid(t *testing.T) {
	t.Parallel()

	if (ID{}).IsValid() {
		t.Fatal("zero ID is valid")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(testID)
	f.Add("")
	f.Add("01890f00-0000-4000-8000-000000000001")

	f.Fuzz(func(t *testing.T, value string) {
		id, err := Parse(value)
		if err != nil {
			return
		}
		if !id.IsValid() || id.String() != value {
			t.Fatalf("Parse(%q) returned non-canonical id %q", value, id.String())
		}
	})
}
