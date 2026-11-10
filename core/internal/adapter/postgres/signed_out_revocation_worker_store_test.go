package postgres

import (
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/publicid"
)

func TestDecodeSignedOutRevocationProof(t *testing.T) {
	t.Parallel()
	change, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	device, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"changed":true,"failed":1,"change_id":"` + change.String() + `","device_id":"` + device.String() +
		`","aggregate_version":4,"action":"device.revoked","stream_id":7,"sequence":9,"previous_hash":"` +
		strings.Repeat("ab", 32) + `","network_revision":12,"audit_payload":"{}","outbox_payload":"{}"}`
	if proof, err := decodeSignedOutRevocationProof(valid, change); err != nil || !proof.Changed || proof.Failed != 1 {
		t.Fatalf("valid proof = %+v, %v", proof, err)
	}
	if proof, err := decodeSignedOutRevocationProof(`{"changed":false,"failed":2}`, change); err != nil ||
		proof.Changed || proof.Failed != 2 {
		t.Fatalf("nothing due = %+v, %v", proof, err)
	}
	for name, encoded := range map[string]string{
		"another change":   strings.Replace(valid, change.String(), device.String(), 1),
		"another action":   strings.Replace(valid, "device.revoked", "device.logged_out", 1),
		"unknown field":    strings.Replace(valid, `"failed":1`, `"failed":1,"extra":1`, 1),
		"short hash":       strings.Replace(valid, strings.Repeat("ab", 32), "ab", 1),
		"no revision":      strings.Replace(valid, `"network_revision":12`, `"network_revision":0`, 1),
		"unchanged extras": `{"changed":false,"failed":0,"action":"device.revoked"}`,
		"two documents":    valid + `{}`,
	} {
		if _, err := decodeSignedOutRevocationProof(encoded, change); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
