package kubeproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/client/internal/kubereq"
	"meshtransit.net/shared/kubeprofile"
)

const (
	// maximumReviewBody bounds a self review's request; maximumRulesAnswer
	// the API server's rules review the gateway narrows.
	maximumReviewBody  = 64 << 10
	maximumRulesAnswer = 4 << 20
	// maximumRuleChecks bounds the checks one rules review costs; rules past
	// it are left out (the answer says it is incomplete anyway).
	maximumRuleChecks = 4096
	// reviewUnevaluable is a review's reason when the gateway cannot read it.
	reviewUnevaluable = "MeshTransit cannot evaluate this review"
)

// selfAccessReview and selfRulesReview name what a self review asks.
func selfAccessReview(info kubereq.Info) bool {
	return info.APIGroup == "authorization.k8s.io" && info.Resource == "selfsubjectaccessreviews"
}

func selfRulesReview(info kubereq.Info) bool {
	return info.APIGroup == "authorization.k8s.io" && info.Resource == "selfsubjectrulesreviews"
}

// reviewAttributes are a SelfSubjectAccessReview's resource attributes, as
// the gateway encodes them again.
type reviewAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb,omitempty"`
	Group       string `json:"group,omitempty"`
	Version     string `json:"version,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

type reviewPath struct {
	Path string `json:"path,omitempty"`
	Verb string `json:"verb,omitempty"`
}

type reviewSpec struct {
	ResourceAttributes    *reviewAttributes `json:"resourceAttributes,omitempty"`
	NonResourceAttributes *reviewPath       `json:"nonResourceAttributes,omitempty"`
}

// errUnevaluable: a review the gateway cannot read as the API server would.
var errUnevaluable = errors.New("kubeproxy: a review the gateway cannot evaluate")

// mayCreate reads a review's update as kubectl sends one, a PUT, which may
// create the object (S3): the answer is never broader than the request
// (review e4–e6 M1). A server-side apply (patch) may still need create.
func mayCreate(verb string) bool { return verb == "update" }

// strictObject reads a JSON object as Kubernetes does, keys matched by case
// (K2 §9.4): known keys exactly, others ignored, and a key that differs from
// a known one only by case refused, as the two would read apart.
func strictObject(raw json.RawMessage, known ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errUnevaluable
	}
	for key := range object {
		if slices.Contains(known, key) {
			continue
		}
		if slices.ContainsFunc(known, func(name string) bool { return strings.EqualFold(name, key) }) {
			return nil, errUnevaluable
		}
	}
	return object, nil
}

// strictString reads a string field; absent or null is empty.
func strictString(object map[string]json.RawMessage, key string) (string, error) {
	raw, found := object[key]
	if !found || string(raw) == "null" {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errUnevaluable
	}
	return value, nil
}

// present reports a field that is there and not null.
func present(object map[string]json.RawMessage, key string) bool {
	raw, found := object[key]
	return found && string(raw) != "null"
}

// decodeAccessReview reads a SelfSubjectAccessReview's spec: one of its two
// attribute sets, no selectors (the profile does not read them).
func decodeAccessReview(body []byte, version string) (reviewSpec, error) {
	top, err := strictObject(body, "apiVersion", "kind", "metadata", "spec", "status")
	if err != nil {
		return reviewSpec{}, err
	}
	apiVersion, err := strictString(top, "apiVersion")
	if err != nil {
		return reviewSpec{}, err
	}
	kind, err := strictString(top, "kind")
	if err != nil || apiVersion != "authorization.k8s.io/"+version || kind != "SelfSubjectAccessReview" {
		return reviewSpec{}, errUnevaluable
	}
	spec, err := strictObject(top["spec"], "resourceAttributes", "nonResourceAttributes")
	if err != nil {
		return reviewSpec{}, err
	}
	resource, path := present(spec, "resourceAttributes"), present(spec, "nonResourceAttributes")
	if resource == path {
		return reviewSpec{}, errUnevaluable
	}
	if path {
		fields, err := strictObject(spec["nonResourceAttributes"], "path", "verb")
		if err != nil {
			return reviewSpec{}, err
		}
		decoded := reviewPath{}
		if decoded.Path, err = strictString(fields, "path"); err != nil {
			return reviewSpec{}, err
		}
		if decoded.Verb, err = strictString(fields, "verb"); err != nil {
			return reviewSpec{}, err
		}
		return reviewSpec{NonResourceAttributes: &decoded}, nil
	}
	names := []string{"namespace", "verb", "group", "version", "resource", "subresource", "name"}
	fields, err := strictObject(spec["resourceAttributes"], append(names, "fieldSelector", "labelSelector")...)
	if err != nil || present(fields, "fieldSelector") || present(fields, "labelSelector") {
		return reviewSpec{}, errUnevaluable
	}
	values := make([]string, len(names))
	for index, name := range names {
		if values[index], err = strictString(fields, name); err != nil {
			return reviewSpec{}, err
		}
	}
	return reviewSpec{ResourceAttributes: &reviewAttributes{
		Namespace: values[0], Verb: values[1],
		Group: values[2], Version: values[3], Resource: values[4], Subresource: values[5], Name: values[6],
	}}, nil
}

// accessReview decides a SelfSubjectAccessReview of a group held through
// scoped grants (K2 §9.4): a review the profile refuses, or the gateway
// cannot read, is answered here, allowed false; one it allows goes on with
// the spec the gateway read, encoded again, for RBAC to decide. It reports
// whether it answered.
func (server *Server) accessReview(w http.ResponseWriter, r *http.Request, info kubereq.Info, peer Peer,
	group Group, impersonated []kubeprofile.Attributes,
) bool {
	version := info.APIVersion
	media, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumReviewBody+1))
	var spec reviewSpec
	switch {
	case err != nil || len(body) > maximumReviewBody:
		err = errUnevaluable
	case !strings.EqualFold(strings.TrimSpace(media), "application/json"):
		err = errUnevaluable
	default:
		spec, err = decodeAccessReview(body, version)
	}
	if err != nil {
		answerAccessReview(w, version, spec, reviewUnevaluable)
		return true
	}
	check := profileCheck{impersonated: impersonated}
	if attributes := spec.ResourceAttributes; attributes != nil {
		check.request = kubeprofile.Attributes{
			ResourceRequest: true, Verb: attributes.Verb,
			APIGroup: attributes.Group, Resource: attributes.Resource, Subresource: attributes.Subresource,
			Namespace: attributes.Namespace, Name: attributes.Name, MayCreate: mayCreate(attributes.Verb),
		}
		if server.options.Discovery != nil && attributes.Resource != "" {
			waiting, cancel := context.WithTimeout(r.Context(), discoveryWait)
			check.request.Scope = server.options.Discovery.Scope(waiting, attributes.Group, attributes.Resource)
			cancel()
		}
	} else {
		check.request = kubeprofile.Attributes{
			Verb: spec.NonResourceAttributes.Verb,
			Path: spec.NonResourceAttributes.Path,
		}
	}
	decision := decide(peer, group, check, server.options.CoreNow())
	server.decisions.count(decision)
	if !decision.allowed {
		message := reviewUnevaluable
		if len(decision.refusing) > 0 {
			message = profileMessage(peer, group, check, decision.refusing)
		}
		answerAccessReview(w, version, spec, message)
		return true
	}
	encoded, err := json.Marshal(map[string]any{
		"apiVersion": "authorization.k8s.io/" + version, "kind": "SelfSubjectAccessReview",
		"metadata": map[string]any{}, "spec": spec,
	})
	if err != nil {
		answerAccessReview(w, version, spec, reviewUnevaluable)
		return true
	}
	r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(bytes.NewReader(encoded)), int64(len(encoded)), nil
	r.Header.Set("Content-Type", "application/json")
	return false
}

// answerAccessReview answers a review allowed false with reason, as the
// API server would (201 Created).
func answerAccessReview(w http.ResponseWriter, version string, spec reviewSpec, reason string) {
	if version == "" {
		version = "v1"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"apiVersion": "authorization.k8s.io/" + version, "kind": "SelfSubjectAccessReview",
		"metadata": map[string]any{}, "spec": spec,
		"status": map[string]any{"allowed": false, "reason": reason},
	})
}

// rulesStatus is a SelfSubjectRulesReview's status.
type rulesStatus struct {
	ResourceRules    []resourceRule    `json:"resourceRules"`
	NonResourceRules []nonResourceRule `json:"nonResourceRules"`
	Incomplete       bool              `json:"incomplete"`
	EvaluationError  string            `json:"evaluationError,omitempty"`
}

type resourceRule struct {
	Verbs         []string `json:"verbs"`
	APIGroups     []string `json:"apiGroups,omitempty"`
	Resources     []string `json:"resources,omitempty"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

type nonResourceRule struct {
	Verbs           []string `json:"verbs"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

// prepareRulesReview asks the API server for a plain JSON answer the
// gateway can narrow.
func prepareRulesReview(r *http.Request) {
	r.Header.Del("Accept-Encoding")
	r.Header.Set("Accept", "application/json")
}

// rulesNarrower narrows a SelfSubjectRulesReview's answer to what the
// group's grants allow (K2 §9.4): only the verbs a profile covers for every
// group, resource and name the rule lists, nothing with a wildcard; marked
// incomplete, with a note. An answer it cannot read becomes an empty one.
func (server *Server) rulesNarrower(peer Peer, group Group) func(*http.Response) error {
	return func(response *http.Response) error {
		if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maximumRulesAnswer+1))
		_ = response.Body.Close()
		narrowed := server.narrowRules(response.Request.Context(), body, err == nil && len(body) <= maximumRulesAnswer,
			peer, group)
		response.Body = io.NopCloser(bytes.NewReader(narrowed))
		response.ContentLength = int64(len(narrowed))
		response.Header.Set("Content-Length", strconv.Itoa(len(narrowed)))
		response.Header.Set("Content-Type", "application/json")
		response.Header.Del("Content-Encoding")
		return nil
	}
}

func (server *Server) narrowRules(ctx context.Context, body []byte, readable bool, peer Peer, group Group) []byte {
	var top map[string]json.RawMessage
	var status rulesStatus
	namespace := ""
	if readable && json.Unmarshal(body, &top) == nil && top != nil && json.Unmarshal(top["status"], &status) == nil {
		var spec struct {
			Namespace string `json:"namespace"`
		}
		_ = json.Unmarshal(top["spec"], &spec)
		namespace = spec.Namespace
	} else {
		top = map[string]json.RawMessage{
			"apiVersion": json.RawMessage(`"authorization.k8s.io/v1"`),
			"kind":       json.RawMessage(`"SelfSubjectRulesReview"`),
		}
		status = rulesStatus{EvaluationError: reviewUnevaluable}
	}
	// One deadline for every discovery wait of the review (review e4–e6 M2).
	ctx, cancel := context.WithTimeout(ctx, discoveryWait)
	defer cancel()
	narrowing := ruleNarrowing{
		server: server, ctx: ctx, peer: peer, group: group, namespace: namespace,
		now: server.options.CoreNow(), scopes: map[[2]string]kubeprofile.ResourceScope{},
	}
	narrowed := rulesStatus{ResourceRules: []resourceRule{}, NonResourceRules: []nonResourceRule{}, Incomplete: true}
	for _, rule := range status.ResourceRules {
		if verbs := narrowing.resourceVerbs(rule); len(verbs) > 0 {
			rule.Verbs = verbs
			narrowed.ResourceRules = append(narrowed.ResourceRules, rule)
		}
	}
	for _, rule := range status.NonResourceRules {
		if verbs := narrowing.pathVerbs(rule); len(verbs) > 0 {
			rule.Verbs = verbs
			narrowed.NonResourceRules = append(narrowed.NonResourceRules, rule)
		}
	}
	notes := []string{}
	if status.EvaluationError != "" {
		notes = append(notes, status.EvaluationError)
	}
	notes = append(notes, fmt.Sprintf("Narrowed by MeshTransit access %s; some allowed actions may be missing: "+
		"check one action with kubectl auth can-i", narrowing.profileNames()))
	narrowed.EvaluationError = strings.Join(notes, "; ")
	encodedStatus, _ := json.Marshal(narrowed)
	top["status"] = encodedStatus
	encoded, err := json.Marshal(top)
	if err != nil {
		return []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","status":` +
			`{"resourceRules":[],"nonResourceRules":[],"incomplete":true}}`)
	}
	return encoded
}

// ruleNarrowing is one rules review's narrowing: discovery asked once per
// resource, checks bounded.
type ruleNarrowing struct {
	server    *Server
	ctx       context.Context //nolint:containedctx // one response's narrowing
	peer      Peer
	group     Group
	namespace string
	now       time.Time
	scopes    map[[2]string]kubeprofile.ResourceScope
	checks    int
}

func (narrowing *ruleNarrowing) scope(group, resource string) kubeprofile.ResourceScope {
	key := [2]string{group, resource}
	if scope, found := narrowing.scopes[key]; found {
		return scope
	}
	scope := kubeprofile.ScopeUnknown
	// Past the deadline a known resource still answers at once.
	if narrowing.server.options.Discovery != nil {
		scope = narrowing.server.options.Discovery.Scope(narrowing.ctx, group, resource)
	}
	narrowing.scopes[key] = scope
	return scope
}

// allows spends one check of the bound; past it nothing is allowed.
func (narrowing *ruleNarrowing) allows(attributes kubeprofile.Attributes) bool {
	if narrowing.checks >= maximumRuleChecks {
		return false
	}
	narrowing.checks++
	return decide(narrowing.peer, narrowing.group, profileCheck{request: attributes}, narrowing.now).allowed
}

func wildcard(values []string) bool {
	return slices.ContainsFunc(values, func(value string) bool { return strings.Contains(value, "*") })
}

// resourceVerbs are the rule's verbs a grant allows for every group,
// resource and name it lists.
func (narrowing *ruleNarrowing) resourceVerbs(rule resourceRule) []string {
	if wildcard(rule.Verbs) || wildcard(rule.APIGroups) || wildcard(rule.Resources) || len(rule.APIGroups) == 0 ||
		len(rule.Resources) == 0 {
		return nil
	}
	names := rule.ResourceNames
	if len(names) == 0 {
		names = []string{""}
	}
	var kept []string
	for _, verb := range rule.Verbs {
		if narrowing.allEvery(rule, verb, names) {
			kept = append(kept, verb)
		}
	}
	return kept
}

func (narrowing *ruleNarrowing) allEvery(rule resourceRule, verb string, names []string) bool {
	for _, group := range rule.APIGroups {
		for _, combined := range rule.Resources {
			resource, subresource, _ := strings.Cut(combined, "/")
			scope := narrowing.scope(group, resource)
			namespace := ""
			if scope == kubeprofile.ScopeNamespaced {
				namespace = narrowing.namespace
			}
			for _, name := range names {
				if !narrowing.allows(kubeprofile.Attributes{
					ResourceRequest: true, Verb: verb, APIGroup: group,
					Resource: resource, Subresource: subresource, Namespace: namespace, Name: name, Scope: scope,
					MayCreate: mayCreate(verb),
				}) {
					return false
				}
			}
		}
	}
	return true
}

func (narrowing *ruleNarrowing) pathVerbs(rule nonResourceRule) []string {
	if wildcard(rule.Verbs) || wildcard(rule.NonResourceURLs) || len(rule.NonResourceURLs) == 0 {
		return nil
	}
	var kept []string
	for _, verb := range rule.Verbs {
		every := true
		for _, path := range rule.NonResourceURLs {
			if !narrowing.allows(kubeprofile.Attributes{Verb: verb, Path: path}) {
				every = false
				break
			}
		}
		if every {
			kept = append(kept, verb)
		}
	}
	return kept
}

// profileNames names the group's profiles in force, for the note.
func (narrowing *ruleNarrowing) profileNames() string {
	var names []string
	for _, grant := range narrowing.peer.Access.ScopedAt(narrowing.now, narrowing.group.Name) {
		if scope, named := narrowing.peer.Scopes[grant.Scope]; named {
			names = append(names, strconv.Quote(scope.ProfileName))
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) == 1 {
		return "profile " + names[0]
	}
	return "profiles " + strings.Join(names, ", ")
}
