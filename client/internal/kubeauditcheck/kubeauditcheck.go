// Package kubeauditcheck reconciles an API server's audit log with the
// operations Core recorded for a cluster's gateway (K1e design §5): every
// type A request the gateway's ServiceAccounts made must carry, as its
// audit ID, the ID of a record Core holds of that very request. A gateway
// taken over and forwarding without Core shows as a mismatch.
package kubeauditcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"meshtransit.net/client/internal/kubereq"
)

// Format names the records file.
const Format = "meshtransit-kube-operations/v1"

const (
	// maxLine bounds an audit line read whole; a longer one (a large object
	// logged at RequestResponse level) is streamed for the request's fields
	// (re-review M5).
	maxLine     = 64 << 20
	maxRecords  = 256 << 20
	readBuffer  = 1 << 20
	clockWindow = 5 * time.Minute
)

// ErrRecords reports a records file that cannot be used.
var ErrRecords = errors.New("kubeauditcheck: invalid records file")

// ErrNoEvents reports a log with no audit event in it: the wrong file or
// format (an EventList batch, a wrapped export, a compressed file).
var ErrNoEvents = errors.New("kubeauditcheck: no audit.k8s.io/v1 events in the log")

// Records is Core's export for one cluster and a time range.
type Records struct {
	Format           string   `json:"format"`
	ClusterID        string   `json:"cluster_id"`
	GatewayNamespace string   `json:"gateway_namespace"`
	PrivilegedGroups []string `json:"privileged_groups"`
	// SecretResources are resources read like secrets, as the chart's
	// secretResources lists them ("resource.group", "resource" for the
	// core group) or "group/resource".
	SecretResources []string `json:"secret_resources"`
	// From..To is the range checked, by the API server's clock.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// RecordsFrom..RecordsTo is the range of Core's clock the records
	// cover: wider than From..To by the clock window, so a request the
	// API server logged in range has its record here (re-review H1).
	RecordsFrom time.Time `json:"records_from"`
	RecordsTo   time.Time `json:"records_to"`
	Records     []Record  `json:"records"`
}

// Record is one operation Core recorded.
type Record struct {
	AuditID      string    `json:"audit_id"`
	ReceivedAt   time.Time `json:"received_at"`
	Class        string    `json:"class"`
	Groups       []string  `json:"groups"`
	Verb         string    `json:"verb"`
	APIGroup     string    `json:"api_group"`
	Resource     string    `json:"resource"`
	Subresource  string    `json:"subresource"`
	Namespace    string    `json:"namespace"`
	Name         string    `json:"name"`
	Impersonated string    `json:"impersonated"`
	// Status is the outcome the gateway reported: 502 when it never
	// reached the API server, 0 when none was recorded.
	Status int `json:"status"`
}

// ReadRecords reads and checks a records file, and returns the gateway's
// classification options from it. A record Core classed privileged or a
// secret read that the file's lists do not explain means a list is
// incomplete, and the check would take such requests for reads (review e4
// H5, re-review M4).
func ReadRecords(reader io.Reader) (Records, kubereq.Options, error) {
	var records Records
	limited := &io.LimitedReader{R: reader, N: maxRecords}
	if err := json.NewDecoder(limited).Decode(&records); err != nil {
		if limited.N == 0 {
			return Records{}, kubereq.Options{}, fmt.Errorf("%w: over %d MiB; export a shorter range", ErrRecords,
				maxRecords>>20)
		}
		return Records{}, kubereq.Options{}, fmt.Errorf("%w: %w", ErrRecords, err)
	}
	if err := records.validRange(); err != nil {
		return Records{}, kubereq.Options{}, err
	}
	options := kubereq.Options{}
	for _, entry := range records.SecretResources {
		resource, err := secretResource(entry)
		if err != nil {
			return Records{}, kubereq.Options{}, err
		}
		options.SecretResources = append(options.SecretResources, resource)
	}
	for _, record := range records.Records {
		if err := records.explains(record, options); err != nil {
			return Records{}, kubereq.Options{}, err
		}
	}
	return records, options, nil
}

func (records Records) validRange() error {
	switch {
	case records.Format != Format:
		return fmt.Errorf("%w: format %q, want %q", ErrRecords, records.Format, Format)
	case records.GatewayNamespace == "":
		return fmt.Errorf("%w: no gateway_namespace", ErrRecords)
	case records.From.IsZero() || !records.To.After(records.From):
		return fmt.Errorf("%w: from and to do not make a range", ErrRecords)
	case records.RecordsFrom.IsZero() || records.RecordsFrom.After(records.From.Add(-clockWindow)) ||
		records.RecordsTo.Before(records.To.Add(clockWindow)):
		return fmt.Errorf("%w: records_from..records_to must cover from..to and %s on each side", ErrRecords,
			clockWindow)
	}
	return nil
}

// explains checks that the file's lists account for record's class.
func (records Records) explains(record Record, options kubereq.Options) error {
	if record.ReceivedAt.Before(records.RecordsFrom) || !record.ReceivedAt.Before(records.RecordsTo) {
		return fmt.Errorf("%w: record %s lies outside records_from..records_to", ErrRecords, record.AuditID)
	}
	switch record.Class {
	case string(kubereq.ClassPrivileged):
		for _, group := range record.Groups {
			if slices.Contains(records.PrivilegedGroups, group) {
				return nil
			}
		}
		return fmt.Errorf("%w: Core classed %s privileged, but privileged_groups lists none of %v", ErrRecords,
			record.AuditID, record.Groups)
	case string(kubereq.ClassSecretRead):
		resource := kubereq.GroupResource{Group: record.APIGroup, Resource: record.Resource}
		if resource != (kubereq.GroupResource{Resource: "secrets"}) && !slices.Contains(options.SecretResources, resource) {
			return fmt.Errorf("%w: Core classed %s a secret read of %s, but secret_resources does not list it",
				ErrRecords, record.AuditID, resource)
		}
	}
	return nil
}

func secretResource(entry string) (kubereq.GroupResource, error) {
	entry = strings.TrimSpace(entry)
	if group, resource, ok := strings.Cut(entry, "/"); ok && resource != "" && !strings.Contains(resource, "/") {
		return kubereq.GroupResource{Group: group, Resource: resource}, nil
	}
	resource, group, _ := strings.Cut(entry, ".")
	if resource == "" || strings.ContainsAny(entry, " /") {
		return kubereq.GroupResource{}, fmt.Errorf("%w: secret resource %q", ErrRecords, entry)
	}
	return kubereq.GroupResource{Group: group, Resource: resource}, nil
}

// Event is what the check reads of an audit.k8s.io/v1 Event.
type Event struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	Verb       string `json:"verb"`
	URI        string `json:"requestURI"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	ObjectRef *ObjectRef `json:"objectRef"`
	Received  time.Time  `json:"requestReceivedTimestamp"`
}

// ObjectRef is the object an event names.
type ObjectRef struct {
	APIGroup    string `json:"apiGroup"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
}

func (event Event) impersonated() string {
	if event.ImpersonatedUser == nil {
		return ""
	}
	return event.ImpersonatedUser.Username
}

func (event Event) valid() bool {
	return event.Kind == "Event" && event.APIVersion == "audit.k8s.io/v1" && event.AuditID != "" &&
		!event.Received.IsZero()
}

// gatewayAuditID reports an audit ID the gateway could have sent: it
// sends Core's UUIDv7 only.
func gatewayAuditID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for index, char := range id {
		switch {
		case index == 8 || index == 13 || index == 18 || index == 23:
			if char != '-' {
				return false
			}
		case !strings.ContainsRune("0123456789abcdefABCDEF", char):
			return false
		}
	}
	return true
}

// Finding is one request the records do not account for.
type Finding struct {
	AuditID  string    `json:"audit_id"`
	Received time.Time `json:"received_at"`
	User     string    `json:"user"`
	Verb     string    `json:"verb"`
	URI      string    `json:"request_uri"`
	Reason   string    `json:"reason"`
}

func newFinding(event Event, reason string) *Finding {
	return &Finding{AuditID: event.AuditID, Received: event.Received, User: event.User.Username,
		Verb: event.Verb, URI: event.URI, Reason: reason}
}

// Result is a check's outcome.
type Result struct {
	// Events counts the audit events read; Checked the requests of the
	// gateway's ServiceAccounts in from..to that had to be recorded.
	Events     int       `json:"events"`
	Checked    int       `json:"checked"`
	Matched    int       `json:"matched"`
	Mismatches []Finding `json:"mismatches"`
	// OutOfRange counts such requests logged outside from..to: not
	// checked here, and not a fault (re-review H1).
	OutOfRange int `json:"out_of_range"`
	// Unseen counts records, away from the range's edges, whose audit ID
	// the log does not hold: a replica's log or an audit policy rule is
	// missing, and what that path served goes unchecked (re-review M2).
	Unseen      int    `json:"unseen_records"`
	FirstUnseen string `json:"first_unseen_record,omitempty"`
	// NotForwarded counts unseen records the gateway reported it could
	// not send (status 502): not a gap in the log (re-review 3 M1).
	NotForwarded int `json:"not_forwarded_records"`
	// Unreadable counts lines that are not audit events; FirstUnreadable
	// is the first's line number.
	Unreadable      int `json:"unreadable_lines"`
	FirstUnreadable int `json:"first_unreadable_line,omitempty"`
}

// Incomplete reports a log the check cannot vouch for: lines it could
// not read, or records it did not find.
func (result Result) Incomplete() bool { return result.Unreadable > 0 || result.Unseen > 0 }

// request is what the check keeps of one audit ID, bounded whatever its
// class (re-review M6): a digest of what all its events must share, the
// stages seen, the first type A event, and why its events disagree.
type request struct {
	digest   [sha256.Size]byte
	stages   uint8
	typeA    *Event
	conflict *Finding
}

type checker struct {
	records  Records
	options  kubereq.Options
	prefix   string
	result   Result
	requests map[string]*request
	order    []string
}

// Check reads an audit log (JSON lines) and reconciles it with records.
func Check(log io.Reader, records Records, options kubereq.Options) (Result, error) {
	return check(log, records, options, maxLine)
}

func check(log io.Reader, records Records, options kubereq.Options, limit int) (Result, error) {
	byID := make(map[string]Record, len(records.Records))
	for _, record := range records.Records {
		id := strings.ToLower(record.AuditID)
		if _, taken := byID[id]; taken {
			return Result{}, fmt.Errorf("%w: audit_id %s twice", ErrRecords, record.AuditID)
		}
		byID[id] = record
	}
	state := &checker{records: records, options: options, requests: map[string]*request{},
		prefix: "system:serviceaccount:" + records.GatewayNamespace + ":mt-",
		result: Result{Mismatches: []Finding{}}}
	if err := state.read(log, limit); err != nil {
		return state.result, err
	}
	if state.result.Events == 0 {
		return state.result, ErrNoEvents
	}
	for _, id := range state.order {
		state.settle(state.requests[id], byID[id], id, byID)
	}
	state.unseen()
	return state.result, nil
}

// take counts one line's event.
func (state *checker) take(event Event, readable bool, number int) {
	if !readable || !event.valid() {
		state.result.Unreadable++
		if state.result.FirstUnreadable == 0 {
			state.result.FirstUnreadable = number
		}
		return
	}
	state.result.Events++
	if strings.HasPrefix(event.User.Username, state.prefix) {
		state.observe(event)
	}
}

// observe adds event to its request. Every event of the gateway's
// ServiceAccounts counts, whatever its class: a write must not hide
// under a read's audit ID (review e4 C1).
func (state *checker) observe(event Event) {
	id := strings.ToLower(event.AuditID)
	foreign := !gatewayAuditID(id)
	if foreign {
		// Not through the gateway's proxy, whatever its class; keyed by a
		// digest so a long ID costs no more than a UUID.
		sum := sha256.Sum256([]byte(id))
		id = "x" + hex.EncodeToString(sum[:])
		event.AuditID = truncate(event.AuditID, 64)
	}
	current, seen := state.requests[id]
	digest := eventDigest(event)
	if !seen {
		current = &request{digest: digest}
		state.requests[id] = current
		state.order = append(state.order, id)
	}
	bit := stageBit(event.Stage)
	if current.conflict == nil {
		switch {
		case foreign:
			current.conflict = newFinding(event, "the audit ID is not a UUID the gateway sends")
		case current.stages&bit != 0:
			current.conflict = newFinding(event, "two events of stage "+event.Stage+" share the audit ID")
		case digest != current.digest:
			current.conflict = newFinding(event, "events of the audit ID differ in verb, URI, user, impersonation, "+
				"object or time")
		}
	}
	current.stages |= bit
	group := strings.TrimPrefix(event.User.Username, state.prefix)
	if current.typeA == nil && typeA(event, group, state.options, state.records.PrivilegedGroups) {
		kept := event
		current.typeA = &kept
	}
}

func stageBit(stage string) uint8 {
	switch stage {
	case "RequestReceived":
		return 1
	case "ResponseStarted":
		return 2
	case "ResponseComplete":
		return 4
	case "Panic":
		return 8
	default:
		return 16
	}
}

// settle decides one request.
func (state *checker) settle(current *request, record Record, id string, byID map[string]Record) {
	result := &state.result
	// Two requests under one ID are a mismatch whatever their class or
	// time (review e4 C1).
	if current.conflict != nil {
		result.Checked++
		result.Mismatches = append(result.Mismatches, *current.conflict)
		return
	}
	if current.typeA == nil {
		return
	}
	event := *current.typeA
	if event.Received.Before(state.records.From) || !event.Received.Before(state.records.To) {
		result.OutOfRange++
		return
	}
	result.Checked++
	_, recorded := byID[id]
	group := strings.TrimPrefix(event.User.Username, state.prefix)
	if reason := mismatch(record, recorded, event, group); reason != "" {
		result.Mismatches = append(result.Mismatches, *newFinding(event, reason))
		return
	}
	result.Matched++
}

// unseen counts the records the log should hold and does not. Records
// near the range's edges are left out: Core's clock and the API server's
// differ, and the log may end there.
func (state *checker) unseen() {
	from, to := state.records.From.Add(clockWindow), state.records.To.Add(-clockWindow)
	for _, record := range state.records.Records {
		if record.ReceivedAt.Before(from) || !record.ReceivedAt.Before(to) {
			continue
		}
		if _, seen := state.requests[strings.ToLower(record.AuditID)]; seen {
			continue
		}
		if record.Status == http.StatusBadGateway {
			state.result.NotForwarded++
			continue
		}
		state.result.Unseen++
		if state.result.FirstUnseen == "" {
			state.result.FirstUnseen = record.AuditID
		}
	}
}

// eventDigest is what every event of one request shares. A create's name
// and namespace come from its body only past RequestReceived, so they are
// left out of a create's digest; its URI still names the namespace.
func eventDigest(event Event) [sha256.Size]byte {
	parts := []string{event.Verb, event.URI, event.User.Username, event.impersonated(),
		event.Received.UTC().Format(time.RFC3339Nano)}
	if ref := event.ObjectRef; ref != nil {
		parts = append(parts, ref.APIGroup, ref.Resource, ref.Subresource)
		if event.Verb != "create" {
			parts = append(parts, ref.Namespace, ref.Name)
		}
	}
	return sha256.Sum256([]byte(strings.Join(parts, "\x00")))
}

// mismatch is why record does not account for event, or "".
func mismatch(record Record, recorded bool, event Event, group string) string {
	if !recorded {
		return "Core holds no record of this audit ID"
	}
	if record.Verb != event.Verb {
		return "Core recorded verb " + record.Verb
	}
	if record.Resource != "" && event.ObjectRef == nil {
		return "Core recorded an object; the request names none"
	}
	if ref := event.ObjectRef; ref != nil {
		// The gateway records a create's name from its URL: none for a
		// POST to a collection, while the log names the created object
		// (review e4 H2).
		name, namespace := ref.Name, ref.Namespace
		if record.Verb == "create" && record.Name == "" {
			name = ""
		}
		if record.Verb == "create" && record.Namespace == "" {
			namespace = ""
		}
		if record.APIGroup != ref.APIGroup || record.Resource != ref.Resource || record.Subresource != ref.Subresource ||
			record.Namespace != namespace || record.Name != name {
			return "Core recorded another object"
		}
	}
	if record.Impersonated != event.impersonated() {
		return "Core recorded another impersonation"
	}
	if !slices.Contains(record.Groups, group) {
		return "Core recorded other groups"
	}
	if gap := event.Received.Sub(record.ReceivedAt); gap > clockWindow || gap < -clockWindow {
		return "Core recorded it at another time"
	}
	return ""
}

func truncate(text string, size int) string {
	if len(text) <= size {
		return text
	}
	return strings.ToValidUTF8(text[:size], "") + "…"
}

// typeA classifies event as the gateway classifies requests, from what the
// audit log holds: the verb's method, the request URI, impersonation. An
// upgrade other than to exec, attach or port-forward looks like a read
// here (no headers in the log): a known blind spot (runbook).
func typeA(event Event, group string, options kubereq.Options, privileged []string) bool {
	options.Privileged = slices.Contains(privileged, group)
	options.Impersonating = event.ImpersonatedUser != nil
	parsed, err := url.ParseRequestURI(event.URI)
	if err != nil {
		return true // the gateway records what it cannot parse
	}
	header := http.Header{}
	if options.Impersonating {
		header.Set("Impersonate-User", event.ImpersonatedUser.Username)
	}
	class, _ := kubereq.Classify(kubereq.Request{Method: method(event.Verb), URL: parsed, Header: header}, options)
	return class.TypeA()
}

func method(verb string) string {
	switch verb {
	case "get", "list", "watch":
		return http.MethodGet
	case "head":
		return http.MethodHead
	case "create":
		return http.MethodPost
	case "update":
		return http.MethodPut
	case "patch":
		return http.MethodPatch
	case "delete", "deletecollection":
		return http.MethodDelete
	default:
		return http.MethodPost // an unknown verb is never taken for a read
	}
}
