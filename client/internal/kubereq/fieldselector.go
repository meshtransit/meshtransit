/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Modified by The MeshTransit Authors: the parts of
k8s.io/apimachinery@v0.35.3 pkg/fields/selector.go that ParseSelector and
RequiresExactMatch use, returning only the exact match of one field.
*/

package kubereq

import (
	"sort"
	"strings"
)

// exactMatch is ParseSelector(selector).RequiresExactMatch(field): the value
// the first exact term on field (in sorted order) requires; false when the
// selector does not parse or has none.
func exactMatch(selector, field string) (string, bool) {
	terms := splitTerms(selector)
	sort.Strings(terms)
	value, found := "", false
	for _, term := range terms {
		if term == "" {
			continue
		}
		lhs, op, rhs, ok := splitTerm(term)
		if !ok {
			return "", false
		}
		unescaped, ok := unescapeValue(rhs)
		if !ok {
			return "", false
		}
		if op != "!=" && lhs == field && !found {
			value, found = unescaped, true
		}
	}
	return value, found
}

// splitTerms splits a selector at the commas not escaped by "\".
func splitTerms(selector string) []string {
	if selector == "" {
		return nil
	}
	var terms []string
	start, escaped := 0, false
	for index, character := range selector {
		switch {
		case escaped:
			escaped = false
		case character == '\\':
			escaped = true
		case character == ',':
			terms = append(terms, selector[start:index])
			start = index + 1
		}
	}
	return append(terms, selector[start:])
}

// splitTerm splits a term at its first operator: "!=", "==" or "=".
func splitTerm(term string) (lhs, op, rhs string, ok bool) {
	for index := range term {
		for _, operator := range []string{"!=", "==", "="} {
			if strings.HasPrefix(term[index:], operator) {
				return term[:index], operator, term[index+len(operator):], true
			}
		}
	}
	return "", "", "", false
}

// unescapeValue undoes "\\", "\," and "\="; any other escape, or an
// unescaped "," or "=", does not parse.
func unescapeValue(value string) (string, bool) {
	if !strings.ContainsAny(value, `\,=`) {
		return value, true
	}
	var out strings.Builder
	escaped := false
	for _, character := range value {
		if escaped {
			if character != '\\' && character != ',' && character != '=' {
				return "", false
			}
			out.WriteRune(character)
			escaped = false
			continue
		}
		switch character {
		case '\\':
			escaped = true
		case ',', '=':
			return "", false
		default:
			out.WriteRune(character)
		}
	}
	return out.String(), !escaped
}
