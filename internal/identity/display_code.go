package identity

import "errors"

// ErrInvalidDisplayCode rejects labels that are not exactly twelve ASCII digits.
var ErrInvalidDisplayCode = errors.New("identity: invalid display code")

// DisplayCode is an immutable human-readable Workspace or Network label.
// It is not an authentication credential or an authorization identity.
type DisplayCode string

// ParseDisplayCode preserves leading zeros and validates the complete label.
func ParseDisplayCode(value string) (DisplayCode, error) {
	if len(value) != 12 {
		return "", ErrInvalidDisplayCode
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return "", ErrInvalidDisplayCode
		}
	}
	return DisplayCode(value), nil
}

// String returns the complete twelve-digit label, including leading zeros.
func (code DisplayCode) String() string { return string(code) }

// IsValid reports whether the value is a complete display label.
func (code DisplayCode) IsValid() bool {
	_, err := ParseDisplayCode(string(code))
	return err == nil
}
