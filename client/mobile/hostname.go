package mobile

import (
	"runtime"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// maxHostnameLabel is the longest DNS label, and so the longest hostname
// a Device registers with.
const maxHostnameLabel = 63

// hostnameFor turns the name the person gave the device ("POCO F4",
// "Điện thoại của Mạnh") into the hostname it registers with: one DNS label
// of lowercase ASCII letters, digits and hyphens ("poco-f4",
// "dien-thoai-cua-manh"), as Core requires. Accents are removed; any other
// character separates words. A name with nothing left gives the platform's
// name. Core may still add a suffix when the Network has the name already.
func hostnameFor(name string) string {
	stripped, _, err := transform.String(stripAccents(), strings.ToLower(name))
	if err != nil {
		stripped = strings.ToLower(name)
	}
	var label strings.Builder
	separate := false
	for _, character := range stripped {
		switch {
		case character == 'đ':
			character = 'd'
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
		default:
			separate = label.Len() > 0
			continue
		}
		if label.Len() >= maxHostnameLabel {
			break
		}
		if separate {
			if label.Len()+2 > maxHostnameLabel {
				break
			}
			label.WriteByte('-')
			separate = false
		}
		label.WriteRune(character)
	}
	if label.Len() == 0 {
		return runtime.GOOS
	}
	return label.String()
}

// stripAccents removes combining marks after decomposing (é → e). A chain
// keeps state while it runs, so each call gets its own.
func stripAccents() transform.Transformer {
	return transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
}
