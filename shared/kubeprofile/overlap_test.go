package kubeprofile

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"
)

type coverageVectors struct {
	Format  string `json:"format"`
	Vectors []struct {
		Name    string `json:"name"`
		Row     Rule   `json:"row"`
		Ceiling []Rule `json:"ceiling"`
		Want    string `json:"want"`
	} `json:"vectors"`
}

func TestRuleCoverageVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/coverage_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors coverageVectors
	if err := json.Unmarshal(raw, &vectors); err != nil || vectors.Format != "meshtransit-kubeprofile-coverage/v1" ||
		len(vectors.Vectors) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for _, vector := range vectors.Vectors {
		if got := RuleCoverage(vector.Row, vector.Ceiling).String(); got != vector.Want {
			t.Errorf("%s: %s, want %s", vector.Name, got, vector.Want)
		}
	}
}

// coverageUniverse is every request built from the values the rules name,
// plus values none names: a row and a ceiling that share a request share
// one of these.
func coverageUniverse(rules []Rule) []Attributes {
	verbs, groups, names, paths := []string{"other-verb"}, []string{"other.group"}, []string{"", "other-name"},
		[]string{"/other"}
	resources := []string{"other", "other/other"}
	for _, rule := range rules {
		verbs = append(verbs, rule.Verbs...)
		groups = append(groups, rule.APIGroups...)
		names = append(names, rule.ResourceNames...)
		for _, resource := range rule.Resources {
			base, sub, _ := strings.Cut(resource, "/")
			resources = append(resources, base, "other/"+sub, base+"/"+sub, base+"/other")
		}
		for _, path := range rule.NonResourceURLs {
			paths = append(paths, path, strings.TrimRight(path, "*"), strings.TrimRight(path, "*")+"x")
		}
	}
	var universe []Attributes
	for _, verb := range unique(verbs) {
		for _, group := range unique(groups) {
			for _, resource := range unique(resources) {
				if strings.Contains(resource, "*") || strings.HasSuffix(resource, "/") {
					continue
				}
				base, sub, _ := strings.Cut(resource, "/")
				for _, name := range unique(names) {
					universe = append(universe, Attributes{
						ResourceRequest: true, Verb: verb, APIGroup: group,
						Resource: base, Subresource: sub, Name: name,
					})
				}
			}
		}
		for _, path := range unique(paths) {
			if !strings.Contains(path, "*") {
				universe = append(universe, Attributes{Verb: verb, Path: path})
			}
		}
	}
	return universe
}

func unique(values []string) []string {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

func randomCoverageRule(random *rand.Rand, paths bool) Rule {
	pick := func(values []string) []string {
		count := 1 + random.IntN(2)
		picked := make([]string, 0, count)
		for range count {
			picked = append(picked, values[random.IntN(len(values))])
		}
		return unique(picked)
	}
	verbs := pick([]string{"get", "list", "delete", "*"})
	if paths {
		return Rule{Verbs: verbs, NonResourceURLs: pick([]string{"/api", "/api/*", "/api*", "/api**", "/apis", "/healthz", "*", "/api/v1"})}
	}
	rule := Rule{
		Verbs: verbs, APIGroups: pick([]string{"", "apps", "*"}),
		Resources: pick([]string{"pods", "pods/log", "deployments", "deployments/scale", "*", "*/scale", "*/log", "a/b/c"}),
	}
	if random.IntN(3) == 0 {
		rule.ResourceNames = pick([]string{"a", "b", "", "c"})
	}
	return rule
}

// RuleCoverage agrees with the RBAC authorizer on every request built from
// the rules' values: none means no request of the row is allowed by the
// ceiling, partial that one is, full that all are.
func TestRuleCoverageAgreesWithRBAC(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(7, 31)) //nolint:gosec // seeded test input, not a secret
	for iteration := range 20000 {
		paths := random.IntN(4) == 0
		row := randomCoverageRule(random, paths)
		ceiling := make([]Rule, random.IntN(4))
		for index := range ceiling {
			ceiling[index] = randomCoverageRule(random, random.IntN(4) == 0)
		}
		coverage := RuleCoverage(row, ceiling)
		shared, missed := 0, 0
		for _, request := range coverageUniverse(append([]Rule{row}, ceiling...)) {
			if !ruleAllows(&row, request) {
				continue
			}
			if slices.ContainsFunc(ceiling, func(rule Rule) bool { return ruleAllows(&rule, request) }) {
				shared++
			} else {
				missed++
			}
		}
		// A row without wildcards stands for the requests the universe
		// holds, so missing none of them is full (review h4a: partial for
		// everything would pass the rest).
		exact := !wildcards(row) && coveragePoints(row) <= maximumCoveragePoints
		switch {
		case coverage == CoverageNone && shared > 0,
			coverage != CoverageNone && shared == 0,
			coverage == CoverageFull && missed > 0,
			exact && shared > 0 && missed == 0 && coverage != CoverageFull:
			t.Fatalf("%d: %s for row %+v and ceiling %+v: %d shared, %d missed", iteration, coverage, row, ceiling,
				shared, missed)
		}
	}
}

func wildcards(rule Rule) bool {
	for _, list := range [][]string{rule.Verbs, rule.APIGroups, rule.Resources, rule.NonResourceURLs} {
		for _, value := range list {
			if strings.Contains(value, "*") {
				return true
			}
		}
	}
	return false
}

func coveragePoints(rule Rule) int {
	if len(rule.NonResourceURLs) > 0 {
		return len(rule.Verbs) * len(rule.NonResourceURLs)
	}
	return len(rule.Verbs) * len(rule.APIGroups) * len(rule.Resources) * max(1, len(rule.ResourceNames))
}

func FuzzRuleCoverage(f *testing.F) {
	f.Add("get,list", ",apps", "pods,*/scale", "a", "get,*", "*", "pods/log,*", "")
	f.Add("get", "", "/apis,/api/v1", "", "get", "", "/api**", "")
	f.Fuzz(func(t *testing.T, verbs, groups, resources, names, ceilingVerbs, ceilingGroups, ceilingResources,
		ceilingNames string,
	) {
		split := func(value string) []string {
			if value == "" {
				return nil
			}
			return strings.Split(value, ",")
		}
		row := Rule{
			Verbs: split(verbs), APIGroups: split(groups), Resources: split(resources),
			ResourceNames: split(names),
		}
		ceiling := []Rule{{
			Verbs: split(ceilingVerbs), APIGroups: split(ceilingGroups),
			Resources: split(ceilingResources), ResourceNames: split(ceilingNames),
		}}
		// A leading "/" makes a side a path rule instead.
		if strings.HasPrefix(resources, "/") {
			row = Rule{Verbs: row.Verbs, NonResourceURLs: row.Resources}
		}
		if strings.HasPrefix(ceilingResources, "/") {
			ceiling[0] = Rule{Verbs: ceiling[0].Verbs, NonResourceURLs: ceiling[0].Resources}
		}
		coverage := RuleCoverage(row, ceiling)
		if coverage < CoverageNone || coverage > CoverageFull {
			t.Fatalf("coverage %d", coverage)
		}
		for _, request := range coverageUniverse([]Rule{row, ceiling[0]}) {
			if !ruleAllows(&row, request) {
				continue
			}
			allowed := ruleAllows(&ceiling[0], request)
			if coverage == CoverageFull && !allowed || coverage == CoverageNone && allowed {
				t.Fatalf("%s, yet %+v is allowed: %v", coverage, request, allowed)
			}
		}
	})
}
