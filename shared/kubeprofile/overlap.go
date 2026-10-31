package kubeprofile

import (
	"slices"
	"strings"
)

// Coverage is how much of a rule another set of rules allows: what a
// cluster group's RBAC (its ceiling) leaves of a permission set's row
// (K2h h4, design §33.9 M6). It is shown to people, never a decision.
type Coverage int

const (
	// CoverageNone is a row none of whose requests the ceiling allows.
	CoverageNone Coverage = iota
	// CoveragePartial is a row some of whose requests it allows, perhaps
	// not all.
	CoveragePartial
	// CoverageFull is a row all of whose requests it allows.
	CoverageFull
)

// String names the coverage as the vectors and the Console do.
func (coverage Coverage) String() string {
	switch coverage {
	case CoverageFull:
		return "full"
	case CoveragePartial:
		return "partial"
	default:
		return "none"
	}
}

// maximumCoveragePoints bounds the (verb, group, resource, name) points a
// row is checked at one by one; a larger row is at most partial.
const maximumCoveragePoints = 4096

// RuleCoverage reports how much of row the ceiling allows, as the RBAC
// authorizer would decide each request row allows: none when no ceiling
// rule meets the row, full only when every point of the row is allowed by
// one ceiling rule. A row of resources meets only resource rules, a row of
// paths only path rules. Wildcards in the row are covered only by the same
// wildcard in the ceiling; a ceiling naming resources covers a row naming
// none only in part.
func RuleCoverage(row Rule, ceiling []Rule) Coverage {
	paths := len(row.NonResourceURLs) > 0
	var meeting []Rule
	for _, rule := range ceiling {
		if (len(rule.NonResourceURLs) > 0) != paths {
			continue
		}
		if paths && pathRuleMeets(rule, row) || !paths && resourceRuleMeets(rule, row) {
			meeting = append(meeting, rule)
		}
	}
	if len(meeting) == 0 {
		return CoverageNone
	}
	if paths {
		return pathCoverage(row, meeting)
	}
	return resourceCoverage(row, meeting)
}

func resourceCoverage(row Rule, ceiling []Rule) Coverage {
	// A row naming no object stands for every name; one naming "" for
	// requests without a name only, as RBAC matches it.
	anyName := len(row.ResourceNames) == 0
	names := row.ResourceNames
	if anyName {
		names = []string{""}
	}
	if len(row.Verbs)*len(row.APIGroups)*len(row.Resources)*len(names) > maximumCoveragePoints {
		return CoveragePartial
	}
	for _, verb := range row.Verbs {
		for _, group := range row.APIGroups {
			for _, resource := range row.Resources {
				for _, name := range names {
					if !someCovers(ceiling, func(rule Rule) bool {
						return listCovers(rule.Verbs, verbAll, verb) && listCovers(rule.APIGroups, apiGroupAll, group) &&
							resourceCovers(rule.Resources, resource) && nameCovers(rule.ResourceNames, name, anyName)
					}) {
						return CoveragePartial
					}
				}
			}
		}
	}
	return CoverageFull
}

func pathCoverage(row Rule, ceiling []Rule) Coverage {
	if len(row.Verbs)*len(row.NonResourceURLs) > maximumCoveragePoints {
		return CoveragePartial
	}
	for _, verb := range row.Verbs {
		for _, path := range row.NonResourceURLs {
			if !someCovers(ceiling, func(rule Rule) bool {
				return listCovers(rule.Verbs, verbAll, verb) && pathCovers(rule.NonResourceURLs, path)
			}) {
				return CoveragePartial
			}
		}
	}
	return CoverageFull
}

func someCovers(ceiling []Rule, covers func(Rule) bool) bool {
	for _, rule := range ceiling {
		if covers(rule) {
			return true
		}
	}
	return false
}

// resourceRuleMeets: some request is allowed by both rules. Rows and rules
// are products of their lists, so they meet when every list meets.
func resourceRuleMeets(rule, row Rule) bool {
	return listsMeet(rule.Verbs, row.Verbs, verbAll) && listsMeet(rule.APIGroups, row.APIGroups, apiGroupAll) &&
		resourcesMeet(rule.Resources, row.Resources) && namesMeet(rule.ResourceNames, row.ResourceNames)
}

func pathRuleMeets(rule, row Rule) bool {
	if !listsMeet(rule.Verbs, row.Verbs, verbAll) {
		return false
	}
	for _, path := range row.NonResourceURLs {
		for _, held := range rule.NonResourceURLs {
			if pathsMeet(held, path) {
				return true
			}
		}
	}
	return false
}

// listCovers: the ceiling's list allows every value the row's value
// stands for; the row's wildcard only by the ceiling's.
func listCovers(list []string, all, value string) bool {
	for _, held := range list {
		if held == all || held == value {
			return true
		}
	}
	return false
}

func listsMeet(held, wanted []string, all string) bool {
	for _, value := range wanted {
		for _, have := range held {
			if value == all || have == all || have == value {
				return true
			}
		}
	}
	return false
}

// resourceCovers is RBAC's resourceMatches for a row's resource, which may
// itself be "*" or "*/sub": "*" covers everything, "*/sub" the subresource
// sub of every resource, and otherwise only the same name.
func resourceCovers(held []string, resource string) bool {
	sub := ""
	if index := strings.IndexByte(resource, '/'); index >= 0 {
		sub = resource[index+1:]
	}
	for _, have := range held {
		if have == resourceAll || have == resource || sub != "" && have == "*/"+sub {
			return true
		}
	}
	return false
}

func resourcesMeet(held, wanted []string) bool {
	for _, resource := range wanted {
		if resourceCovers(held, resource) {
			return true
		}
		for _, have := range held {
			if resourceMeets(resource, have) {
				return true
			}
		}
	}
	return false
}

// resourceMeets: a row's wildcard resource meets the ceiling's names it
// stands for ("*" any, "*/sub" any subresource sub).
func resourceMeets(wanted, have string) bool {
	if wanted == resourceAll {
		return true
	}
	if sub, wild := strings.CutPrefix(wanted, "*/"); wild {
		_, haveSub, found := strings.Cut(have, "/")
		return found && haveSub == sub
	}
	return false
}

// nameCovers: a ceiling naming no object allows every name; one naming
// objects allows only those, never a row's "any name".
func nameCovers(held []string, name string, anyName bool) bool {
	if len(held) == 0 {
		return true
	}
	return !anyName && slices.Contains(held, name)
}

func namesMeet(held, wanted []string) bool {
	if len(held) == 0 || len(wanted) == 0 {
		return true
	}
	for _, name := range wanted {
		if slices.Contains(held, name) {
			return true
		}
	}
	return false
}

// pathCovers is RBAC's nonResourceURLMatches for a row's path, which may
// end in "*": a ceiling path ending in "*" covers the paths starting with
// what comes before it.
func pathCovers(held []string, path string) bool {
	for _, have := range held {
		if have == nonResourceAll || have == path {
			return true
		}
		// RBAC trims every trailing star, not one (review h4a H1).
		if strings.HasSuffix(have, "*") && strings.HasPrefix(path, strings.TrimRight(have, "*")) {
			return true
		}
	}
	return false
}

func pathsMeet(have, path string) bool {
	if pathCovers([]string{have}, path) {
		return true
	}
	if !strings.HasSuffix(path, "*") {
		return false
	}
	return strings.HasPrefix(strings.TrimRight(have, "*"), strings.TrimRight(path, "*"))
}
