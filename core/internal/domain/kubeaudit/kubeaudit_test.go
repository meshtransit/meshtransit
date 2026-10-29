package kubeaudit

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// intentID is an ID in the UUIDv7 layout at at.
func intentID(at time.Time, last byte) [16]byte {
	var id [16]byte
	var millis [8]byte
	binary.BigEndian.PutUint64(millis[:], uint64(at.UnixMilli()))
	copy(id[:6], millis[2:])
	id[6], id[8], id[15] = 0x70, 0x80, last
	return id
}

func validIntent(t *testing.T, now time.Time) Intent {
	t.Helper()
	peer, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return Intent{ID: intentID(now, 1), Peer: peer, Groups: []string{"edit"}, Class: ClassWrite, Verb: "delete",
		APIGroup: "apps", Resource: "deployments", Namespace: "default", Name: "web", TokenID: []byte{1, 2},
		ObservedAt: now}
}

// An intent is taken only with every field in form (design §3.3): the
// same bounds as schema 245, no NUL or control characters, an ID of now.
func TestIntentValid(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC)
	if !validIntent(t, now).Valid(now) {
		t.Fatal("a valid intent refused")
	}
	for name, change := range map[string]func(*Intent){
		"class":            func(intent *Intent) { intent.Class = "read" },
		"no verb":          func(intent *Intent) { intent.Verb = "" },
		"NUL":              func(intent *Intent) { intent.Name = "web\x00" },
		"control":          func(intent *Intent) { intent.Namespace = "a\nb" },
		"C1 control":       func(intent *Intent) { intent.Resource = "a\u0085" },
		"bad UTF-8":        func(intent *Intent) { intent.Name = "\xff" },
		"long name":        func(intent *Intent) { intent.Name = strings.Repeat("a", 254) },
		"long group":       func(intent *Intent) { intent.Groups = []string{strings.Repeat("g", 64)} },
		"empty group":      func(intent *Intent) { intent.Groups = []string{""} },
		"17 groups":        func(intent *Intent) { intent.Groups = make([]string, 17) },
		"long token":       func(intent *Intent) { intent.TokenID = make([]byte, 33) },
		"no peer":          func(intent *Intent) { intent.Peer = publicid.ID{} },
		"not v7":           func(intent *Intent) { intent.ID[6] = 0x40 },
		"old ID":           func(intent *Intent) { intent.ID = intentID(now.Add(-6*time.Minute), 1) },
		"future ID":        func(intent *Intent) { intent.ID = intentID(now.Add(6*time.Minute), 1) },
		"no observed time": func(intent *Intent) { intent.ObservedAt = time.Time{} },
		"past year 9999": func(intent *Intent) {
			intent.ObservedAt = time.UnixMilli(latestObserved + 1).In(time.FixedZone("west", -3600))
		},
		"bidi override":  func(intent *Intent) { intent.Name = "web\u202egnp" },
		"line separator": func(intent *Intent) { intent.Verb = "get\u2028" },
	} {
		intent := validIntent(t, now)
		change(&intent)
		if intent.Valid(now) {
			t.Errorf("%s: taken", name)
		}
	}
}

// The digest changes with any field, and with how groups split.
func TestIntentDigest(t *testing.T) {
	t.Parallel()
	now := time.Now()
	intent := validIntent(t, now)
	same := intent
	same.Groups = []string{"edit"}
	if intent.Digest() != same.Digest() {
		t.Fatal("the same intent digested differently")
	}
	for name, change := range map[string]func(*Intent){
		"verb":   func(intent *Intent) { intent.Verb = "patch" },
		"groups": func(intent *Intent) { intent.Groups = []string{"ed", "it"} },
		"name":   func(intent *Intent) { intent.Name = "api" },
		"time":   func(intent *Intent) { intent.ObservedAt = now.Add(time.Millisecond) },
	} {
		other := intent
		change(&other)
		if other.Digest() == intent.Digest() {
			t.Errorf("%s: same digest", name)
		}
	}
}
