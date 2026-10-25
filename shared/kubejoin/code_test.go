package kubejoin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func vectorInputs(t *testing.T) Inputs {
	t.Helper()
	var inputs Inputs
	for index := range inputs.MachineKey {
		inputs.MachineKey[index] = byte(index + 1)
		inputs.NodeKey[index] = byte(index + 33)
	}
	cluster, err := hex.DecodeString("0190f2a1b2c37d4e8f90a1b2c3d4e5f6")
	if err != nil {
		t.Fatal(err)
	}
	copy(inputs.ClusterID[:], cluster)
	inputs.RequestNonce = [32]byte(bytes.Repeat([]byte{0xaa}, 32))
	return inputs
}

// The vector was computed independently, with Python's hashlib and base64.
func TestCodeVector(t *testing.T) {
	t.Parallel()
	code, err := Compute(vectorInputs(t))
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}
	if code.String() != "4KH7I-REC2B" {
		t.Fatalf("Compute() = %q, want 4KH7I-REC2B", code)
	}
}

// Changing any input changes the code.
func TestCodeBindsEveryInput(t *testing.T) {
	t.Parallel()
	base, err := Compute(vectorInputs(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Inputs){
		"machine key": func(inputs *Inputs) { inputs.MachineKey[0] ^= 1 },
		"node key":    func(inputs *Inputs) { inputs.NodeKey[31] ^= 1 },
		"cluster":     func(inputs *Inputs) { inputs.ClusterID[15] ^= 1 },
		"nonce":       func(inputs *Inputs) { inputs.RequestNonce[7] ^= 1 },
	} {
		inputs := vectorInputs(t)
		change(&inputs)
		code, err := Compute(inputs)
		if err != nil || code == base {
			t.Errorf("%s: Compute() = %q, %v; want a different code", name, code, err)
		}
	}
}

func TestComputeRefusesZeroInputs(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*Inputs){
		"machine key": func(inputs *Inputs) { inputs.MachineKey = [32]byte{} },
		"node key":    func(inputs *Inputs) { inputs.NodeKey = [32]byte{} },
		"cluster":     func(inputs *Inputs) { inputs.ClusterID = [16]byte{} },
		"nonce":       func(inputs *Inputs) { inputs.RequestNonce = [32]byte{} },
	} {
		inputs := vectorInputs(t)
		change(&inputs)
		if _, err := Compute(inputs); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Compute() error = %v, want ErrInvalid", name, err)
		}
	}
}

// What a person types is read leniently: case, spaces and the hyphen do not
// matter, but only the base32 alphabet is a code.
func TestParse(t *testing.T) {
	t.Parallel()
	for _, typed := range []string{"4KH7I-REC2B", "4kh7i-rec2b", "4KH7IREC2B", " 4KH7I REC2B ", "4kh7i rec2b"} {
		code, err := Parse(typed)
		if err != nil || code.String() != "4KH7I-REC2B" {
			t.Errorf("Parse(%q) = %q, %v", typed, code, err)
		}
	}
	for _, typed := range []string{"", "4KH7I-REC2", "4KH7I-REC2BB", "4KH7I-REC20", "4KH7I-REC21", "4KH7I_REC2B"} {
		if _, err := Parse(typed); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) error = %v, want ErrInvalid", typed, err)
		}
	}
}

func TestEqual(t *testing.T) {
	t.Parallel()
	code, err := Compute(vectorInputs(t))
	if err != nil {
		t.Fatal(err)
	}
	typed, err := Parse("4kh7irec2b")
	if err != nil {
		t.Fatal(err)
	}
	if !code.Equal(typed) {
		t.Fatal("Equal() = false for the same code")
	}
	other, err := Parse("4KH7I-REC2C")
	if err != nil {
		t.Fatal(err)
	}
	if code.Equal(other) || code.Equal(Code{}) {
		t.Fatal("Equal() = true for a different code")
	}
}

// Bits are the digest's first 50 bits, as the database computes them.
func TestBitsAreTheDigestPrefix(t *testing.T) {
	t.Parallel()
	inputs := vectorInputs(t)
	code, err := Compute(inputs)
	if err != nil {
		t.Fatal(err)
	}
	material := append([]byte(label), 0)
	material = append(material, inputs.MachineKey[:]...)
	material = append(material, inputs.NodeKey[:]...)
	material = append(material, inputs.ClusterID[:]...)
	material = append(material, inputs.RequestNonce[:]...)
	digest := sha256.Sum256(material)
	want := uint64(digest[0])<<42 | uint64(digest[1])<<34 | uint64(digest[2])<<26 | uint64(digest[3])<<18 |
		uint64(digest[4])<<10 | uint64(digest[5])<<2 | uint64(digest[6])>>6
	bits, ok := code.Bits()
	if !ok || bits != want {
		t.Fatalf("Bits() = %#x, %v; want %#x", bits, ok, want)
	}
	if _, ok := (Code{}).Bits(); ok {
		t.Fatal("the zero Code has bits")
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"4KH7I-REC2B", "4kh7i rec2b", "", "-----", "AAAAA-AAAAA"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, typed string) {
		code, err := Parse(typed)
		if err != nil {
			return
		}
		again, err := Parse(code.String())
		if err != nil || !again.Equal(code) {
			t.Fatalf("Parse(%q) = %q does not round-trip", typed, code)
		}
		if _, ok := code.Bits(); !ok {
			t.Fatalf("Parse(%q) has no bits", typed)
		}
	})
}

// A cluster's public ID is a canonical lowercase UUIDv7: anything else is
// refused, so the code binds exactly the bytes Core uses.
func TestParseClusterID(t *testing.T) {
	t.Parallel()
	id, err := ParseClusterID("01890f90-0000-7000-8000-0000000000c1")
	want := [16]byte{0x01, 0x89, 0x0f, 0x90, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xc1}
	if err != nil || id != want {
		t.Fatalf("ParseClusterID() = %x, %v", id, err)
	}
	for _, bad := range []string{
		"", "01890F90-0000-7000-8000-0000000000c1", "01890f90-0000-4000-8000-0000000000c1",
		"01890f90000070008000-0000000000c1", "01890f90-0000-7000-8000-0000000000c1 ", "{01890f90-0000-7000-8000-0000000000c1}",
		"01890f90-0000-7000-8000-0000000000g1",
	} {
		if _, err := ParseClusterID(bad); err == nil {
			t.Errorf("ParseClusterID(%q) accepted", bad)
		}
	}
}
