package kubecluster_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/shared/kubeprofile"
)

func validCeilingBody() kubecluster.CeilingBody {
	return kubecluster.CeilingBody{Groups: []kubecluster.CeilingGroup{{
		Group: "edit", ClusterRole: "system:aggregate-to-edit",
		Everywhere: kubecluster.CeilingScope{Measured: true, Rules: []kubeprofile.Rule{
			{Verbs: []string{"get"}, NonResourceURLs: []string{"/api"}},
		}},
		Namespaces: []kubecluster.CeilingScope{
			{Namespace: "default", Measured: true, Incomplete: true, RulesDropped: 3, Rules: []kubeprofile.Rule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
			}},
			{Namespace: "team-a", Rules: []kubeprofile.Rule{}},
		},
	}}}
}

func TestCeilingBodyEncodesOnce(t *testing.T) {
	t.Parallel()
	first, hash, err := validCeilingBody().Encode()
	if err != nil {
		t.Fatal(err)
	}
	again, hashAgain, err := validCeilingBody().Encode()
	if err != nil || !bytes.Equal(first, again) || hash != hashAgain {
		t.Fatal("the same body encodes differently")
	}
	changed := validCeilingBody()
	changed.Truncated = true
	if _, other, _ := changed.Encode(); other == hash {
		t.Fatal("a different body hashes alike")
	}
	if empty, _, err := (kubecluster.CeilingBody{Groups: []kubecluster.CeilingGroup{}}).Encode(); err != nil ||
		string(empty) != `{"groups":[],"truncated":false}` {
		t.Fatalf("an empty body: %s, %v", empty, err)
	}
}

func TestValidCeilingBody(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*kubecluster.CeilingBody){
		"nil groups":            func(b *kubecluster.CeilingBody) { b.Groups = nil },
		"a group twice":         func(b *kubecluster.CeilingBody) { b.Groups = append(b.Groups, b.Groups[0]) },
		"an upper case group":   func(b *kubecluster.CeilingBody) { b.Groups[0].Group = "Edit" },
		"a role with a slash":   func(b *kubecluster.CeilingBody) { b.Groups[0].ClusterRole = "a/b" },
		"a role of ..":          func(b *kubecluster.CeilingBody) { b.Groups[0].ClusterRole = ".." },
		"a named everywhere":    func(b *kubecluster.CeilingBody) { b.Groups[0].Everywhere.Namespace = "x" },
		"nil namespaces":        func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces = nil },
		"nil rules":             func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces[1].Rules = nil },
		"a namespace twice":     func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces[1].Namespace = "default" },
		"an unnamed namespace":  func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces[1].Namespace = "" },
		"unmeasured with rules": func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces[1].Rules = b.Groups[0].Namespaces[0].Rules },
		"unmeasured, dropped":   func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces[1].RulesDropped = 1 },
		"negative dropped":      func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces[0].RulesDropped = -1 },
		"a rule without verbs":  func(b *kubecluster.CeilingBody) { b.Groups[0].Namespaces[0].Rules[0].Verbs = nil },
		"a path rule with groups": func(b *kubecluster.CeilingBody) {
			b.Groups[0].Everywhere.Rules[0].APIGroups = []string{""}
		},
		"a control character": func(b *kubecluster.CeilingBody) {
			b.Groups[0].Namespaces[0].Rules[0].Resources = []string{"pods\n"}
		},
		"a long string": func(b *kubecluster.CeilingBody) {
			b.Groups[0].Namespaces[0].Rules[0].Resources = []string{strings.Repeat("r", 254)}
		},
		"17 namespaces": func(b *kubecluster.CeilingBody) {
			for index := range 15 {
				b.Groups[0].Namespaces = append(b.Groups[0].Namespaces, kubecluster.CeilingScope{
					Namespace: "ns-" + string(rune('a'+index)), Rules: []kubeprofile.Rule{}})
			}
		},
		"577 rules": func(b *kubecluster.CeilingBody) {
			rule := b.Groups[0].Namespaces[0].Rules[0]
			for range 576 {
				b.Groups[0].Namespaces[0].Rules = append(b.Groups[0].Namespaces[0].Rules, rule)
			}
		},
	} {
		body := validCeilingBody()
		change(&body)
		if kubecluster.ValidCeilingBody(body) {
			t.Errorf("%s: valid", name)
		}
		if _, _, err := body.Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if !kubecluster.ValidCeilingBody(validCeilingBody()) {
		t.Fatal("the valid body is refused")
	}
}

func TestEncodedCeiling(t *testing.T) {
	t.Parallel()
	at := time.Unix(1_800_000_000, 0)
	ceiling, err := validCeilingBody().Encoded(at.Add(-time.Minute), at)
	encoded, hash, _ := validCeilingBody().Encode()
	if err != nil || ceiling.IsZero() || !bytes.Equal(ceiling.Bytes(), encoded) || ceiling.Hash() != hash ||
		!ceiling.ReceivedAt().Equal(at) || !ceiling.CheckedAt().Equal(at.Add(-time.Minute)) {
		t.Fatalf("%+v, %v", ceiling, err)
	}
	if _, err := validCeilingBody().Encoded(time.Time{}, time.Time{}); err == nil {
		t.Fatal("a ceiling without a receipt time")
	}
	if _, err := (kubecluster.CeilingBody{}).Encoded(time.Time{}, at); err == nil {
		t.Fatal("an invalid body was encoded")
	}
	if !(kubecluster.EncodedCeiling{}).IsZero() {
		t.Fatal("the zero ceiling is not zero")
	}
}
