package kubeauditcheck

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/kubereq"
)

var base = time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)

const (
	edit      = "system:serviceaccount:mt-kube:mt-edit"
	pods      = "/api/v1/namespaces/team-a/pods/p"
	recordCM  = "01a1b2c3-0000-7000-8000-000000000001"
	recordPod = "01a1b2c3-0000-7000-8000-000000000002"
)

func records(extra ...Record) Records {
	return Records{Format: Format, GatewayNamespace: "mt-kube", PrivilegedGroups: []string{"sre"},
		From: base.Add(-time.Hour), To: base.Add(time.Hour),
		RecordsFrom: base.Add(-time.Hour - clockWindow), RecordsTo: base.Add(time.Hour + clockWindow),
		Records: append([]Record{
			// A create to a collection: the gateway records no name.
			{AuditID: recordCM, ReceivedAt: base, Class: "write", Groups: []string{"edit"},
				Verb: "create", Resource: "configmaps", Namespace: "team-a"},
			{AuditID: recordPod, ReceivedAt: base, Class: "write", Groups: []string{"edit"},
				Verb: "delete", Resource: "pods", Namespace: "team-a", Name: "p"},
		}, extra...)}
}

type event struct {
	id, stage, verb, uri, user, group, resource, namespace, name, impersonated string
	at                                                                         time.Time
}

// deletePod is the request recordPod records, at stage.
func deletePod(stage string) event {
	return event{id: recordPod, stage: stage, verb: "delete", uri: pods, user: edit, resource: "pods",
		namespace: "team-a", name: "p"}
}

func (e event) line() string {
	impersonated := ""
	if e.impersonated != "" {
		impersonated = `,"impersonatedUser":{"username":"` + e.impersonated + `"}`
	}
	at := e.at
	if at.IsZero() {
		at = base
	}
	return `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"` + e.id + `","stage":"` +
		e.stage + `","requestURI":"` + e.uri + `","verb":"` + e.verb + `","user":{"username":"` + e.user + `"}` +
		impersonated + `,"objectRef":{"resource":"` + e.resource + `","namespace":"` + e.namespace + `","name":"` +
		e.name + `","apiGroup":"` + e.group + `"},"requestReceivedTimestamp":"` + at.Format(time.RFC3339Nano) + `"}`
}

func join(events ...event) string {
	lines := make([]string, len(events))
	for index, e := range events {
		lines[index] = e.line()
	}
	return strings.Join(lines, "\n")
}

func run(t *testing.T, recorded Records, events ...event) Result {
	t.Helper()
	options := kubereq.Options{SecretResources: []kubereq.GroupResource{{Group: "bitnami.com", Resource: "sealedsecrets"}}}
	result, err := Check(strings.NewReader(join(events...)), recorded, options)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func reasons(result Result) map[string]string {
	out := map[string]string{}
	for _, finding := range result.Mismatches {
		out[finding.AuditID] = finding.Reason
	}
	return out
}

func TestCheck(t *testing.T) {
	t.Parallel()
	collection := "/api/v1/namespaces/team-a/configmaps"
	result := run(t, records(),
		// A create in two stages: only the second names the object, the
		// record names none (review e4 H2).
		event{id: recordCM, stage: "RequestReceived", verb: "create", uri: collection, user: edit,
			resource: "configmaps", namespace: "team-a"},
		event{id: recordCM, stage: "ResponseComplete", verb: "create", uri: collection, user: edit,
			resource: "configmaps", namespace: "team-a", name: "cm"},
		// A read: not checked.
		event{id: "aaaaaaaa-0000-4000-8000-000000000003", stage: "ResponseComplete", verb: "get", uri: pods,
			user: edit, resource: "pods", namespace: "team-a", name: "p"},
		// A write Core never saw.
		event{id: "bbbbbbbb-0000-4000-8000-000000000004", stage: "ResponseComplete", verb: "delete",
			uri: "/api/v1/namespaces/team-a/secrets/s", user: edit, resource: "secrets", namespace: "team-a", name: "s"},
		// A recorded ID reused for another object.
		event{id: recordPod, stage: "ResponseComplete", verb: "delete", uri: "/api/v1/namespaces/team-a/pods/other",
			user: edit, resource: "pods", namespace: "team-a", name: "other"},
		// A read by a privileged group is type A.
		event{id: "cccccccc-0000-4000-8000-000000000005", stage: "ResponseComplete", verb: "get", uri: pods,
			user: "system:serviceaccount:mt-kube:mt-sre", resource: "pods", namespace: "team-a", name: "p"},
		// A read of a resource read like a secret is type A.
		event{id: "cdcdcdcd-0000-4000-8000-00000000000c", stage: "ResponseComplete", verb: "get",
			uri: "/apis/bitnami.com/v1alpha1/namespaces/team-a/sealedsecrets/s", user: edit, group: "bitnami.com",
			resource: "sealedsecrets", namespace: "team-a", name: "s"},
		// Another namespace's mt-* account is not the gateway's.
		event{id: "dddddddd-0000-4000-8000-000000000006", stage: "ResponseComplete", verb: "delete",
			uri: "/api/v1/namespaces/x/pods/p", user: "system:serviceaccount:other:mt-edit", resource: "pods",
			namespace: "x", name: "p"},
		// Outside the range: counted, not checked.
		event{id: "eeeeeeee-0000-4000-8000-000000000007", stage: "ResponseComplete", verb: "create", uri: collection,
			user: edit, resource: "configmaps", namespace: "team-a", at: base.Add(2 * time.Hour)},
	)
	if result.Checked != 5 || result.Matched != 1 || len(result.Mismatches) != 4 || result.OutOfRange != 1 ||
		result.Unseen != 0 || result.Incomplete() {
		t.Fatalf("result %+v", result)
	}
	found := reasons(result)
	if !strings.Contains(found["bbbbbbbb-0000-4000-8000-000000000004"], "no record") ||
		!strings.Contains(found[recordPod], "another object") ||
		!strings.Contains(found["cccccccc-0000-4000-8000-000000000005"], "no record") ||
		!strings.Contains(found["cdcdcdcd-0000-4000-8000-00000000000c"], "no record") {
		t.Fatalf("reasons %v", found)
	}
}

// A second request under one audit ID is a mismatch: a write behind a
// read (review e4 C1), a replay, impersonation added later, another time.
func TestCheckSharedAuditID(t *testing.T) {
	t.Parallel()
	read := deletePod("ResponseComplete")
	read.verb = "get"
	impersonating := deletePod("ResponseComplete")
	impersonating.impersonated = "admin"
	later := deletePod("ResponseComplete")
	later.at = base.Add(time.Second)
	for name, events := range map[string][]event{
		"write behind a read": {read, {id: recordPod, stage: "ResponseStarted", verb: "delete",
			uri: "/api/v1/namespaces/a/secrets/s", user: edit, resource: "secrets", namespace: "a", name: "s"}},
		"replay":                {deletePod("ResponseComplete"), deletePod("ResponseComplete")},
		"impersonation added":   {deletePod("RequestReceived"), impersonating},
		"another received time": {deletePod("RequestReceived"), later},
	} {
		if result := run(t, records(), events...); len(result.Mismatches) != 1 || result.Matched != 0 {
			t.Errorf("%s: %+v", name, result)
		}
	}
	if result := run(t, records(), deletePod("RequestReceived"), deletePod("ResponseComplete")); result.Matched != 1 ||
		len(result.Mismatches) != 0 {
		t.Fatalf("one request in two stages: %+v", result)
	}
}

func TestCheckRecordDiffers(t *testing.T) {
	t.Parallel()
	impersonating := deletePod("ResponseComplete")
	impersonating.impersonated = "admin"
	late := deletePod("ResponseComplete")
	late.at = base.Add(clockWindow + time.Second)
	otherGroup := deletePod("ResponseComplete")
	otherGroup.user = "system:serviceaccount:mt-kube:mt-view"
	for name, test := range map[string]struct {
		event  event
		reason string
	}{
		"impersonation": {impersonating, "impersonation"},
		"time":          {late, "another time"},
		"group":         {otherGroup, "other groups"},
	} {
		result := run(t, records(), test.event)
		if len(result.Mismatches) != 1 || !strings.Contains(result.Mismatches[0].Reason, test.reason) {
			t.Errorf("%s: %+v", name, result)
		}
	}
}

// A HEAD is a read; a verb the checker does not know is taken for a write.
func TestCheckVerbs(t *testing.T) {
	t.Parallel()
	result := run(t, records(),
		event{id: "abababab-0000-4000-8000-000000000009", stage: "ResponseComplete", verb: "head", uri: pods,
			user: edit, resource: "pods", namespace: "team-a", name: "p"},
		event{id: "abababab-0000-4000-8000-00000000000a", stage: "ResponseComplete", verb: "frobnicate", uri: pods,
			user: edit, resource: "pods", namespace: "team-a", name: "p"},
	)
	if result.Checked != 1 || len(result.Mismatches) != 1 ||
		result.Mismatches[0].AuditID != "abababab-0000-4000-8000-00000000000a" {
		t.Fatalf("result %+v", result)
	}
}

// An unrecorded write near the range's edge is a mismatch: the records
// reach past the range, so its record would be there (re-review H1).
func TestCheckEdge(t *testing.T) {
	t.Parallel()
	near := deletePod("ResponseComplete")
	near.id, near.at = "acacacac-0000-4000-8000-00000000000b", base.Add(time.Hour-time.Minute)
	// Recorded by Core's clock just past the range, logged just inside.
	skewed := records(Record{AuditID: "acacacac-0000-4000-8000-00000000000d", ReceivedAt: base.Add(time.Hour + time.Minute),
		Class: "write", Groups: []string{"edit"}, Verb: "delete", Resource: "pods", Namespace: "team-a", Name: "p"})
	inside := deletePod("ResponseComplete")
	inside.id, inside.at = "acacacac-0000-4000-8000-00000000000d", base.Add(time.Hour-time.Minute)
	result := run(t, skewed, near, inside)
	if len(result.Mismatches) != 1 || result.Mismatches[0].AuditID != near.id || result.Matched != 1 {
		t.Fatalf("result %+v", result)
	}
}

// Records the log does not hold mean a missing log or policy rule; near
// the edges they are left out (re-review M2).
func TestCheckUnseen(t *testing.T) {
	t.Parallel()
	edge := Record{AuditID: "adadadad-0000-7000-8000-00000000000e", ReceivedAt: base.Add(-time.Hour + time.Minute),
		Class: "write", Groups: []string{"edit"}, Verb: "delete", Resource: "pods"}
	result := run(t, records(edge), deletePod("ResponseComplete"))
	if result.Unseen != 1 || result.FirstUnseen != recordCM || !result.Incomplete() || len(result.Mismatches) != 0 {
		t.Fatalf("result %+v", result)
	}
	// A log of none of the gateway's requests is incomplete, not clean.
	other := deletePod("ResponseComplete")
	other.user = "system:serviceaccount:kube-system:replicaset-controller"
	if result := run(t, records(), other); result.Unseen != 2 || !result.Incomplete() {
		t.Fatalf("another cluster's log: %+v", result)
	}
}

func TestCheckLongLines(t *testing.T) {
	t.Parallel()
	pad := `,"responseObject":{"items":[` + strings.Repeat(`{"data":"`+strings.Repeat("x", 100)+`"},`, 40) + `{}]}`
	// The request's fields come before and after the large object.
	long := strings.Replace(deletePod("ResponseComplete").line(), `,"requestReceivedTimestamp"`,
		pad+`,"requestReceivedTimestamp"`, 1)
	write := event{id: "afafafaf-0000-4000-8000-00000000000f", stage: "ResponseComplete", verb: "deletecollection",
		uri: "/api/v1/namespaces/team-a/pods", user: edit, resource: "pods", namespace: "team-a"}
	unrecorded := strings.Replace(write.line(), `,"requestReceivedTimestamp"`, pad+`,"requestReceivedTimestamp"`, 1)
	for name, log := range map[string]string{
		"middle":               long + "\n" + unrecorded + "\n" + `{"log":"wrapped"}`,
		"last, no newline":     `{"log":"wrapped"}` + "\n" + long + "\n" + unrecorded,
		"last, with newline":   `{"log":"wrapped"}` + "\n" + long + "\n" + unrecorded + "\n",
		"broken long, then ok": `{"kind":"Event",` + strings.Repeat(`"x":1,`, 1000) + "\n" + long + "\n" + unrecorded,
	} {
		result, err := check(strings.NewReader(log), records(), kubereq.Options{}, 256)
		if err != nil || result.Events != 2 || result.Matched != 1 || len(result.Mismatches) != 1 ||
			result.Mismatches[0].AuditID != write.id || result.Unreadable != 1 {
			t.Errorf("%s: %+v, %v", name, result, err)
		}
	}
	if _, err := Check(strings.NewReader(`{"log":"wrapped"}`), records(), kubereq.Options{}); !errors.Is(err, ErrNoEvents) {
		t.Fatalf("a log of no events: %v", err)
	}
}

func TestReadRecords(t *testing.T) {
	t.Parallel()
	head := `{"format":"` + Format + `","gateway_namespace":"n","from":"2026-10-30T00:00:00Z","to":"2026-10-30T01:00:00Z",` +
		`"records_from":"2026-10-29T23:55:00+00:00","records_to":"2026-10-30T01:05:00Z"`
	for name, input := range map[string]string{
		"wrong format":        strings.Replace(head, Format, "x", 1) + "}",
		"no namespace":        strings.Replace(head, `"gateway_namespace":"n",`, "", 1) + "}",
		"no range":            `{"format":"` + Format + `","gateway_namespace":"n"}`,
		"narrow export":       strings.Replace(head, "2026-10-29T23:55:00+00:00", "2026-10-29T23:56:00Z", 1) + "}",
		"bad secret resource": head + `,"secret_resources":["a b"]}`,
		"privileged not listed": head + `,"records":[{"audit_id":"x","received_at":"2026-10-30T00:10:00Z",` +
			`"class":"privileged","groups":["sre"]}]}`,
		"secret resource not listed": head + `,"records":[{"audit_id":"x","received_at":"2026-10-30T00:10:00Z",` +
			`"class":"secret_read","api_group":"bitnami.com","resource":"sealedsecrets"}]}`,
		"record outside the export": head + `,"records":[{"audit_id":"x","received_at":"2026-10-30T02:00:00Z"}]}`,
	} {
		if _, _, err := ReadRecords(strings.NewReader(input)); !errors.Is(err, ErrRecords) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, options, err := ReadRecords(strings.NewReader(head + `,"secret_resources":["sealedsecrets.bitnami.com",` +
		`"secrets","external-secrets.io/externalsecrets"],"records":[{"audit_id":"x","received_at":` +
		`"2026-10-30T00:10:00Z","class":"secret_read","api_group":"bitnami.com","resource":"sealedsecrets"},` +
		`{"audit_id":"y","received_at":"2026-10-30T00:10:00Z","class":"secret_read","resource":"secrets"}]}`))
	if err != nil || len(options.SecretResources) != 3 ||
		options.SecretResources[0] != (kubereq.GroupResource{Group: "bitnami.com", Resource: "sealedsecrets"}) ||
		options.SecretResources[2] != (kubereq.GroupResource{Group: "external-secrets.io", Resource: "externalsecrets"}) {
		t.Fatalf("secret resources %+v, %v", options.SecretResources, err)
	}
	twice := records(Record{AuditID: strings.ToUpper(recordPod)})
	if _, err := Check(strings.NewReader(""), twice, kubereq.Options{}); !errors.Is(err, ErrRecords) {
		t.Fatalf("an audit ID twice: %v", err)
	}
}

func TestReadRecordsOversized(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("reads 256 MiB")
	}
	endless := io.MultiReader(strings.NewReader(`{"format":"`+Format+`","pad":"`), xs{})
	if _, _, err := ReadRecords(endless); err == nil || !strings.Contains(err.Error(), "shorter range") {
		t.Fatalf("an oversized file: %v", err)
	}
}

// xs reads an endless run of x.
type xs struct{}

func (xs) Read(p []byte) (int, error) {
	for index := range p {
		p[index] = 'x'
	}
	return len(p), nil
}

// padTo pads line with a field to size bytes.
func padTo(t *testing.T, line string, size int) string {
	t.Helper()
	const field = `,"pad":""}`
	short := size - len(line) - len(field) + 1
	if short < 0 {
		t.Fatalf("line of %d bytes over %d", len(line), size)
	}
	return strings.TrimSuffix(line, "}") + `,"pad":"` + strings.Repeat("x", short) + `"}`
}

func TestCheckLineAtTheLimit(t *testing.T) {
	t.Parallel()
	write := event{id: "afafafaf-0000-4000-8000-000000000010", stage: "ResponseComplete", verb: "delete", uri: pods,
		user: edit, resource: "pods", namespace: "team-a", name: "p"}
	for _, size := range []int{511, 512, 513} {
		for _, newline := range []string{"", "\n"} {
			log := padTo(t, write.line(), size) + newline
			result, err := check(strings.NewReader(log), records(), kubereq.Options{}, 512)
			if err != nil || result.Events != 1 || len(result.Mismatches) != 1 || result.Unreadable != 0 {
				t.Errorf("%d bytes, newline %q: %+v, %v", size, newline, result, err)
			}
		}
	}
	// Two values on one long line are unreadable, as on a short one.
	double := padTo(t, write.line(), 600) + deletePod("ResponseComplete").line()
	result, err := check(strings.NewReader(double+"\n"+deletePod("ResponseComplete").line()), records(),
		kubereq.Options{}, 512)
	if err != nil || result.Unreadable != 1 || result.Matched != 1 || len(result.Mismatches) != 0 {
		t.Fatalf("two values: %+v, %v", result, err)
	}
}

func TestCheckForeignAndIncompleteEvents(t *testing.T) {
	t.Parallel()
	foreign := deletePod("ResponseComplete")
	foreign.id, foreign.verb = "req-"+strings.Repeat("9", 200), "get" // a read, still not the gateway's
	untimed := strings.Replace(deletePod("ResponseComplete").line(), `,"requestReceivedTimestamp":"`+
		base.Format(time.RFC3339Nano)+`"`, "", 1)
	result, err := Check(strings.NewReader(foreign.line()+"\n"+untimed+"\n"+deletePod("ResponseComplete").line()),
		records(Record{AuditID: "aeaeaeae-0000-7000-8000-000000000011", ReceivedAt: base, Class: "write",
			Groups: []string{"edit"}, Verb: "delete", Resource: "pods", Status: 502}), kubereq.Options{})
	if err != nil || len(result.Mismatches) != 1 || len(result.Mismatches[0].AuditID) > 70 ||
		!strings.Contains(result.Mismatches[0].Reason, "not a UUID") || result.Unreadable != 1 ||
		result.NotForwarded != 1 || result.Unseen != 1 || result.FirstUnseen != recordCM {
		t.Fatalf("result %+v, %v", result, err)
	}
}
