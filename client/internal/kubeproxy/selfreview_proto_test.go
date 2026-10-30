package kubeproxy

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"meshtransit.net/shared/kubeprofile"
)

// protoField is one length-delimited field.
func protoField(number protowire.Number, value []byte) []byte {
	out := protowire.AppendTag(nil, number, protowire.BytesType)
	return protowire.AppendBytes(out, value)
}

func protoMessage(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		out = append(out, field...)
	}
	return out
}

// protoReview is a SelfSubjectAccessReview as kubectl sends it in protobuf.
func protoReview(version, kind string, spec []byte, extra ...[]byte) []byte {
	typeMeta := protoMessage(protoField(1, []byte("authorization.k8s.io/"+version)), protoField(2, []byte(kind)))
	review := protoMessage(protoField(1, protoField(1, []byte("ignored-metadata"))), protoField(2, spec))
	envelope := protoMessage(append([][]byte{protoField(1, typeMeta), protoField(2, review)}, extra...)...)
	return append([]byte("k8s\x00"), envelope...)
}

func resourceSpec(fields ...[]byte) []byte { return protoField(1, protoMessage(fields...)) }

func TestDecodeAccessReviewProto(t *testing.T) {
	t.Parallel()
	attributes := resourceSpec(protoField(1, []byte("default")), protoField(2, []byte("delete")),
		protoField(3, []byte("apps")), protoField(5, []byte("deployments")), protoField(7, []byte("web")),
		protoField(15, []byte("unknown")))
	spec, err := decodeAccessReviewProto(protoReview("v1", "SelfSubjectAccessReview", attributes), "v1")
	if err != nil || spec.ResourceAttributes == nil || *spec.ResourceAttributes != (reviewAttributes{
		Namespace: "default", Verb: "delete", Group: "apps", Resource: "deployments", Name: "web",
	}) {
		t.Fatalf("resource review: %+v, %v", spec.ResourceAttributes, err)
	}
	path := protoField(2, protoMessage(protoField(1, []byte("/healthz")), protoField(2, []byte("get"))))
	spec, err = decodeAccessReviewProto(protoReview("v1", "SelfSubjectAccessReview", path), "v1")
	if err != nil || spec.NonResourceAttributes == nil || spec.NonResourceAttributes.Path != "/healthz" {
		t.Fatalf("path review: %+v, %v", spec, err)
	}
	selector := resourceSpec(protoField(2, []byte("list")), protoField(8, []byte{}))
	duplicate := resourceSpec(protoField(1, []byte("default")), protoField(1, []byte("kube-system")))
	for name, body := range map[string][]byte{
		"field selector":  protoReview("v1", "SelfSubjectAccessReview", selector),
		"repeated field":  protoReview("v1", "SelfSubjectAccessReview", duplicate),
		"repeated spec":   protoReview("v1", "SelfSubjectAccessReview", append(attributes, path...)),
		"another kind":    protoReview("v1", "SelfSubjectRulesReview", attributes),
		"another version": protoReview("v1beta1", "SelfSubjectAccessReview", attributes),
		"encoded content": protoReview("v1", "SelfSubjectAccessReview", attributes, protoField(3, []byte("gzip"))),
		"no magic":        protoReview("v1", "SelfSubjectAccessReview", attributes)[4:],
		"truncated":       protoReview("v1", "SelfSubjectAccessReview", attributes)[:20],
		"a varint field":  append([]byte("k8s\x00"), protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 7)...),
		"neither":         protoReview("v1", "SelfSubjectAccessReview", nil),
		"label selector": protoReview("v1", "SelfSubjectAccessReview",
			resourceSpec(protoField(2, []byte("list")), protoField(9, []byte{}))),
		"repeated envelope field": append(protoReview("v1", "SelfSubjectAccessReview", attributes),
			protoField(1, []byte{})...),
		"a varint verb": protoReview("v1", "SelfSubjectAccessReview", protoField(1,
			protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), 1))),
		"a lone end group": protoReview("v1", "SelfSubjectAccessReview", protoField(1,
			protowire.AppendTag(nil, 20, protowire.EndGroupType))),
		"invalid UTF-8": protoReview("v1", "SelfSubjectAccessReview",
			resourceSpec(protoField(2, []byte("get")), protoField(5, []byte{0xff, 'p'}))),
	} {
		if _, err := decodeAccessReviewProto(body, "v1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// kubectl sends its reviews in protobuf: the gateway reads them, answers a
// refusal itself and forwards an allowed one as JSON.
func TestProxyAnswersProtobufAccessReviews(t *testing.T) {
	t.Parallel()
	f := profiledFixture(t, nil, enforcing("edit", scopeDeveloper, time.Now().Add(time.Hour)))
	const path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	deleting := protoReview("v1", "SelfSubjectAccessReview", resourceSpec(protoField(1, []byte("team-a")),
		protoField(2, []byte("delete")), protoField(5, []byte("pods"))))
	_, body := f.post(path, protobufMedia, string(deleting))
	if !strings.Contains(body, `"allowed":false`) || !strings.Contains(body, `profile \"developer\"`) {
		t.Fatalf("a refused protobuf review: %s", body)
	}
	f.nothingForwarded()
	getting := protoReview("v1", "SelfSubjectAccessReview", resourceSpec(protoField(1, []byte("team-a")),
		protoField(2, []byte("get")), protoField(5, []byte("pods"))))
	response, _ := f.post(path, protobufMedia, string(getting))
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		t.Fatalf("an allowed protobuf review: %d", response.StatusCode)
	}
	forwarded := f.forwarded()
	if forwarded.Header.Get("Content-Type") != "application/json" ||
		!strings.Contains(forwarded.Body, `"resourceAttributes":{"namespace":"team-a","verb":"get","resource":"pods"}`) {
		t.Fatalf("forwarded %q %s", forwarded.Header.Get("Content-Type"), forwarded.Body)
	}
}

// A role's rule lists many resources; the narrowed answer keeps each
// resource the profile covers on its own (demo K2e).
func TestNarrowRulesSplitsByResource(t *testing.T) {
	t.Parallel()
	now := time.Now()
	server := &Server{options: Options{CoreNow: func() time.Time { return now }, Discovery: &fakeDiscovery{}}}
	body := `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"team-a"},
"status":{"resourceRules":[{"verbs":["get","delete"],"apiGroups":["","apps"],"resources":["pods","secrets","deployments"]}],
"nonResourceRules":[{"verbs":["get","post"],"nonResourceURLs":["/healthz","/version"]}],"incomplete":false}}`
	narrowed := string(server.narrowRules(t.Context(), []byte(body), true,
		scopedPeer(t, now, enforcing("edit", scopeDeveloper, now.Add(time.Hour))), Group{Name: "edit"}, "team-a"))
	for _, want := range []string{
		`{"verbs":["get"],"apiGroups":[""],"resources":["pods"]}`,
		`{"verbs":["get"],"apiGroups":["apps"],"resources":["deployments"]}`,
	} {
		if !strings.Contains(narrowed, want) {
			t.Errorf("missing %s in %s", want, narrowed)
		}
	}
	if !strings.Contains(narrowed, `"nonResourceRules":[]`) {
		t.Errorf("a path the profile lacks was kept: %s", narrowed)
	}
	if strings.Contains(narrowed, "secrets") || strings.Contains(narrowed, `"delete"`) ||
		strings.Contains(narrowed, `"apps"],"resources":["pods"]`) {
		t.Fatalf("broader than the profile: %s", narrowed)
	}
}

// Names, subresources and paths are each checked on their own cell.
func TestNarrowRulesNamesAndSubresources(t *testing.T) {
	t.Parallel()
	now := time.Now()
	server := &Server{options: Options{CoreNow: func() time.Time { return now }, Discovery: &fakeDiscovery{}}}
	peer := scopedPeer(t, now, enforcing("edit", [32]byte{0xd5}, now.Add(time.Hour)))
	peer.Scopes[[32]byte{0xd5}] = testScope(t, "named", []string{"team-a"}, true, []kubeprofile.Rule{
		{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}, ResourceNames: []string{"web"}},
	}, []kubeprofile.Rule{{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}}})
	body := `{"spec":{"namespace":"team-a"},"status":{"resourceRules":[
{"verbs":["get"],"apiGroups":[""],"resources":["pods","pods/log"]},
{"verbs":["get"],"apiGroups":["apps"],"resources":["deployments"],"resourceNames":["web","db"]},
{"verbs":["get"],"apiGroups":["apps"],"resources":["deployments"],"resourceNames":["web"]}],
"nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/healthz","/version"]}]}}`
	narrowed := string(server.narrowRules(t.Context(), []byte(body), true, peer, Group{Name: "edit"}, "team-a"))
	for _, want := range []string{
		`{"verbs":["get"],"apiGroups":[""],"resources":["pods/log"]}`,
		`{"verbs":["get"],"apiGroups":["apps"],"resources":["deployments"],"resourceNames":["web"]}`,
		`"nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/healthz"]}]`,
	} {
		if !strings.Contains(narrowed, want) {
			t.Errorf("missing %s in %s", want, narrowed)
		}
	}
	if strings.Contains(narrowed, `"resources":["pods"]`) || strings.Contains(narrowed, `"db"`) {
		t.Fatalf("broader than the profile: %s", narrowed)
	}
}

// The API server's rules answer does not echo the namespace: the gateway
// narrows by the one it read in the request, which it forwards encoded
// again; a request it cannot read gets no rules (demo K2e).
func TestProxyRulesReviewNamespaceFromTheRequest(t *testing.T) {
	t.Parallel()
	f := profiledFixture(t, nil, enforcing("edit", scopeDeveloper, time.Now().Add(time.Hour)))
	const path = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
	typeMeta := protoMessage(protoField(1, []byte("authorization.k8s.io/v1")), protoField(2, []byte("SelfSubjectRulesReview")))
	review := protoField(2, protoField(1, []byte("team-a")))
	body := append([]byte("k8s\x00"), protoMessage(protoField(1, typeMeta), protoField(2, review))...)
	_, answer := f.post(path, protobufMedia, string(body))
	forwarded := f.forwarded()
	if forwarded.Header.Get("Content-Type") != "application/json" ||
		!strings.Contains(forwarded.Body, `"spec":{"namespace":"team-a"}`) {
		t.Fatalf("forwarded %q %s", forwarded.Header.Get("Content-Type"), forwarded.Body)
	}
	if forwarded.Header.Get("Accept") != "application/json" || forwarded.Header.Get("Accept-Encoding") == "br" ||
		forwarded.Header.Get("Content-Length") != strconv.Itoa(len(forwarded.Body)) {
		t.Fatalf("forwarded headers %v", forwarded.Header)
	}
	if !strings.Contains(answer, `{"verbs":["get","list"],"apiGroups":[""],"resources":["pods"]}`) {
		t.Fatalf("not narrowed by the request's namespace: %s", answer)
	}
	_, other := f.post(path, "application/json",
		`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"team-c"}}`)
	f.forwarded()
	if strings.Contains(other, `"resources":["pods"]`) {
		t.Fatalf("rules kept in a namespace the profile lacks: %s", other)
	}
	_, unread := f.post(path, "application/json",
		`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","Spec":{"namespace":"team-a"}}`)
	f.nothingForwarded()
	if !strings.Contains(unread, `"resourceRules":[]`) || !strings.Contains(unread, reviewUnevaluable) {
		t.Fatalf("an unreadable request: %s", unread)
	}
}

func TestDecodeRulesReview(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		body, media, want string
		ok                bool
	}{
		"json":           {`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"a"}}`, "application/json", "a", true},
		"json no spec":   {`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview"}`, "application/json", "", true},
		"json case":      {`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"Namespace":"a"}}`, "application/json", "", false},
		"json kind":      {`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{}}`, "application/json", "", false},
		"yaml":           {`kind: x`, "application/yaml", "", false},
		"proto":          {string(rulesProto("v1", "SelfSubjectRulesReview", protoField(2, protoField(1, []byte("a"))))), protobufMedia, "a", true},
		"proto kind":     {string(rulesProto("v1", "SelfSubjectAccessReview", protoField(2, protoField(1, []byte("a"))))), protobufMedia, "", false},
		"proto ver":      {string(rulesProto("v1beta1", "SelfSubjectRulesReview", nil)), protobufMedia, "", false},
		"proto magic":    {string(rulesProto("v1", "SelfSubjectRulesReview", nil)[4:]), protobufMedia, "", false},
		"proto twice":    {string(rulesProto("v1", "SelfSubjectRulesReview", append(protoField(2, nil), protoField(2, nil)...))), protobufMedia, "", false},
		"proto utf8":     {string(rulesProto("v1", "SelfSubjectRulesReview", protoField(2, protoField(1, []byte{0xff})))), protobufMedia, "", false},
		"proto encoding": {string(rulesProto("v1", "SelfSubjectRulesReview", nil, protoField(3, []byte("gzip")))), protobufMedia, "", false},
		"proto varint ns": {string(rulesProto("v1", "SelfSubjectRulesReview", protoField(2,
			protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1)))), protobufMedia, "", false},
	} {
		got, err := decodeRulesReview([]byte(test.body), "v1", test.media)
		if (err == nil) != test.ok || got != test.want {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

// rulesProto is a SelfSubjectRulesReview in protobuf: raw holds review.
func rulesProto(version, kind string, review []byte, extra ...[]byte) []byte {
	typeMeta := protoMessage(protoField(1, []byte("authorization.k8s.io/"+version)), protoField(2, []byte(kind)))
	envelope := protoMessage(append([][]byte{protoField(1, typeMeta), protoField(2, review)}, extra...)...)
	return append([]byte("k8s\x00"), envelope...)
}
