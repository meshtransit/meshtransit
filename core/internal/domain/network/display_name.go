package network

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maximumDisplayNameRunes = 128

// ErrInvalidDisplayName reports an empty, malformed, or unsafe Network display name.
var ErrInvalidDisplayName = errors.New("network: invalid display name")

// DisplayName is a validated, presentation-only Network name. It is never an
// identity or authorization input.
type DisplayName struct {
	value string
}

// ParseDisplayName validates a Network display name without normalizing it.
func ParseDisplayName(value string) (DisplayName, error) {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		utf8.RuneCountInString(value) > maximumDisplayNameRunes {
		return DisplayName{}, ErrInvalidDisplayName
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return DisplayName{}, ErrInvalidDisplayName
		}
	}
	return DisplayName{value: value}, nil
}

// String returns the display text exactly as validated.
func (name DisplayName) String() string { return name.value }

// IsValid reports whether the display name satisfies the Network contract.
func (name DisplayName) IsValid() bool {
	validated, err := ParseDisplayName(name.value)
	return err == nil && validated == name
}
