package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

// tokenObject rejects duplicate names at every JSON nesting level before typed
// decoding. Unknown bounded claims can be ignored, not converted into authority.
// NumericDates are later decoded strictly as whole-second signed integers.
func tokenObject(body []byte, maximumMembers int) (map[string]json.RawMessage, error) {
	if len(body) == 0 || len(body) > 256*1024 || !utf8.Valid(body) || !pairedJSONSurrogates(body) {
		return nil, ErrTokenRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkTokenJSON(decoder, 0); err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); token != nil || !errors.Is(err, io.EOF) {
		return nil, ErrTokenRejected
	}
	values := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &values); err != nil || values == nil || len(values) > maximumMembers {
		return nil, ErrTokenRejected
	}
	return values, nil
}
func walkTokenJSON(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrTokenRejected
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrTokenRejected
	}
	delimiter, isContainer := token.(json.Delim)
	if !isContainer {
		return nil
	}
	if delimiter != '{' && delimiter != '[' {
		return ErrTokenRejected
	}
	seen := make(map[string]struct{})
	count := 0
	for decoder.More() {
		count++
		if count > 128 {
			return ErrTokenRejected
		}
		if delimiter == '{' {
			nameToken, err := decoder.Token()
			name, ok := nameToken.(string)
			if err != nil || !ok || len(name) == 0 || len(name) > 255 {
				return ErrTokenRejected
			}
			if _, exists := seen[name]; exists {
				return ErrTokenRejected
			}
			seen[name] = struct{}{}
		}
		if err := walkTokenJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || delimiter == '{' && closing != json.Delim('}') || delimiter == '[' && closing != json.Delim(']') {
		return ErrTokenRejected
	}
	return nil
}
func tokenRequired[T any](values map[string]json.RawMessage, name string, target *T) bool {
	raw, exists := values[name]
	return exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && json.Unmarshal(raw, target) == nil
}
func tokenOptional[T any](values map[string]json.RawMessage, name string, target *T) bool {
	if _, exists := values[name]; !exists {
		return true
	}
	return tokenRequired(values, name, target)
}

// encoding/json replaces lone UTF-16 surrogate escapes with U+FFFD. Reject that
// lossy decoding before opaque subject/kid equality or duplicate-name checks.
// JSON syntax is still validated by the bounded decoder, not this lexical pass.
func pairedJSONSurrogates(body []byte) bool {
	quoted := false
	for i := 0; i < len(body); i++ {
		if body[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || body[i] != '\\' {
			continue
		}
		i++
		if i >= len(body) {
			return false
		}
		if body[i] != 'u' {
			continue
		}
		if i+4 >= len(body) {
			return false
		}
		value, err := strconv.ParseUint(string(body[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(body[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
