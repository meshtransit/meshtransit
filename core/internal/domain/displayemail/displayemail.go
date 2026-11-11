// Package displayemail holds the one rule for an account email a Device may
// show (S4c §3.1): Core checks it before writing and before sending, and the
// database CHECK in schema 288 is the same rule.
package displayemail

import "strings"

const (
	minimumBytes = 3
	maximumBytes = 254
)

// Valid reports 3-254 printable ASCII characters without '"', '<' or '>',
// with exactly one '@', text on both sides and a dot in the domain. An IDN
// or UTF-8 address is never valid: a Device shows the name alone.
func Valid(email string) bool {
	if len(email) < minimumBytes || len(email) > maximumBytes {
		return false
	}
	for index := range len(email) {
		character := email[index]
		if character < 0x21 || character > 0x7e || character == '"' || character == '<' || character == '>' {
			return false
		}
	}
	local, domain, found := strings.Cut(email, "@")
	return found && local != "" && domain != "" && !strings.Contains(domain, "@") && strings.Contains(domain, ".")
}
