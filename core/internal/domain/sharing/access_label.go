package sharing

import (
	"errors"
	"strings"
)

const defaultAccessLabel = "device"

// ErrInvalidAccessLabel reports a label that is not one canonical DNS label.
var ErrInvalidAccessLabel = errors.New("sharing: invalid access label")

// AccessLabel is the provider-chosen first label of a share's consumer DNS
// name. It is frozen on the Share Offer; Core appends the provider Workspace
// and Network display codes, so consumers never choose the name. Like the
// name, it is discovery metadata and grants no packet authority.
type AccessLabel struct {
	value string
}

// ParseAccessLabel validates one DNS label and canonicalizes it to lowercase.
// Dots, underscores, non-ASCII characters and all-digit labels are denied.
func ParseAccessLabel(value string) (AccessLabel, error) {
	canonical := strings.ToLower(value)
	if !validAccessNameLabel(canonical) || isNumericAccessName(canonical) {
		return AccessLabel{}, ErrInvalidAccessLabel
	}
	return AccessLabel{value: canonical}, nil
}

// DefaultAccessLabel derives a valid label from a Device hostname: the first
// hostname label, lowercased, with other characters replaced by hyphens and
// trimmed to 63 bytes. An empty result becomes "device"; an all-digit result
// is prefixed with "device-".
func DefaultAccessLabel(hostname string) AccessLabel {
	first, _, _ := strings.Cut(strings.TrimSpace(hostname), ".")
	var builder strings.Builder
	hyphen := false
	for _, character := range strings.ToLower(first) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			builder.WriteRune(character)
			hyphen = false
			continue
		}
		if !hyphen && builder.Len() > 0 {
			builder.WriteByte('-')
			hyphen = true
		}
	}
	label := truncateAccessLabel(strings.Trim(builder.String(), "-"))
	switch {
	case label == "":
		label = defaultAccessLabel
	case isNumericAccessName(label):
		label = truncateAccessLabel(defaultAccessLabel + "-" + label)
	}
	return AccessLabel{value: label}
}

func truncateAccessLabel(label string) string {
	if len(label) <= maximumDNSLabelBytes {
		return label
	}
	return strings.TrimRight(label[:maximumDNSLabelBytes], "-")
}

// String returns the lowercase canonical label.
func (label AccessLabel) String() string { return label.value }

// IsValid reports whether the value satisfies the access-label contract.
func (label AccessLabel) IsValid() bool {
	validated, err := ParseAccessLabel(label.value)
	return err == nil && validated == label
}
